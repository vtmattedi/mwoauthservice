package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
)

const (
	maxProviderStateLength = 1024
	maxProviderCodeLength  = 16384
	maxProviderErrorLength = 256
)

type CallbackService struct {
	store       CallbackStore
	cipher      PKCEDecrypter
	google      GoogleCodeExchanger
	deliverer   ResultDeliverer
	credentials CredentialSource
}

// CallbackOption configures a CallbackService.
type CallbackOption func(*CallbackService)

// WithCredentials lets callbacks complete authorizations that were pinned to a
// per-project Google client.
func WithCredentials(source CredentialSource) CallbackOption {
	return func(s *CallbackService) { s.credentials = source }
}

type GoogleCallbackInput struct {
	State         string
	Code          string
	ProviderError string
}

type CallbackOutcome struct {
	ProjectID     int64
	TransactionID string
	ReturnURL     string
	Status        string
}

func NewCallbackService(
	store CallbackStore,
	cipher PKCEDecrypter,
	google GoogleCodeExchanger,
	deliverer ResultDeliverer,
	options ...CallbackOption,
) (*CallbackService, error) {
	if store == nil {
		return nil, fmt.Errorf("OAuth callback store is required")
	}
	if cipher == nil {
		return nil, fmt.Errorf("PKCE decrypter is required")
	}
	if google == nil {
		return nil, fmt.Errorf("Google code exchanger is required")
	}
	if deliverer == nil {
		return nil, fmt.Errorf("OAuth result deliverer is required")
	}

	service := &CallbackService{
		store:     store,
		cipher:    cipher,
		google:    google,
		deliverer: deliverer,
	}
	for _, option := range options {
		option(service)
	}

	return service, nil
}

// clientForTransaction returns the Google client pinned to the transaction.
// It never substitutes another client: a pinned credential that is disabled,
// deleted or undecryptable fails the authorization permanently with
// ErrCredentialUnavailable. Any other error (for example a store failure)
// is returned as is, and the caller treats it as transient.
func (s *CallbackService) clientForTransaction(
	ctx context.Context,
	transaction domain.OAuthTransaction,
) (GoogleClient, error) {
	if transaction.GoogleCredentialID == "" || s.credentials == nil {
		return GoogleClient{}, fmt.Errorf(
			"%w: the authorization is not bound to a Google client",
			ErrCredentialUnavailable,
		)
	}

	resolved, err := s.credentials.Resolve(
		ctx,
		transaction.ProjectID,
		transaction.GoogleCredentialID,
		googlecred.PurposeExchange,
	)
	if err != nil {
		if isPermanentCredentialError(err) {
			return GoogleClient{}, fmt.Errorf(
				"%w: %v",
				ErrCredentialUnavailable,
				err,
			)
		}
		return GoogleClient{}, err
	}

	return GoogleClient{
		ClientID:     resolved.ClientID,
		ClientSecret: resolved.ClientSecret,
	}, nil
}
func (s *CallbackService) HandleGoogle(
	ctx context.Context,
	input GoogleCallbackInput,
) (CallbackOutcome, error) {
	input.State = strings.TrimSpace(input.State)
	input.Code = strings.TrimSpace(input.Code)
	input.ProviderError = strings.TrimSpace(
		input.ProviderError,
	)

	if input.State == "" ||
		len(input.State) > maxProviderStateLength {
		return CallbackOutcome{}, ErrInvalidCallback
	}

	if len(input.Code) > maxProviderCodeLength ||
		len(input.ProviderError) > maxProviderErrorLength {
		return CallbackOutcome{}, ErrInvalidCallback
	}

	if input.Code != "" && input.ProviderError != "" {
		return CallbackOutcome{}, ErrInvalidCallback
	}

	transaction, err := s.store.ConsumeOAuthTransactionByStateHash(
		ctx,
		hashOpaqueValue(input.State),
		time.Now().UTC().Unix(),
	)

	outcome := CallbackOutcome{
		ProjectID:     transaction.ProjectID,
		TransactionID: transaction.ID,
		ReturnURL:     transaction.ReturnURL,
	}

	if err != nil {
		switch {
		case errors.Is(err, ErrTransactionExpired):
			outcome.Status = "expired"
			return outcome, ErrTransactionExpired

		case errors.Is(err, ErrTransactionConsumed):
			return CallbackOutcome{}, ErrTransactionConsumed

		case errors.Is(err, ErrTransactionNotFound):
			return CallbackOutcome{}, ErrTransactionNotFound

		default:
			return CallbackOutcome{}, fmt.Errorf(
				"consume OAuth transaction: %w",
				err,
			)
		}
	}

	if input.ProviderError != "" {
		if input.ProviderError == "access_denied" {
			if err := s.transition(
				ctx,
				transaction.ID,
				"denied",
			); err != nil {
				return outcome, err
			}

			outcome.Status = "denied"
			return outcome, ErrProviderDenied
		}

		if err := s.transition(
			ctx,
			transaction.ID,
			"provider_failed",
		); err != nil {
			return outcome, err
		}

		outcome.Status = "provider_failed"
		return outcome, ErrProviderExchangeFailed
	}

	if input.Code == "" {
		if err := s.transition(
			ctx,
			transaction.ID,
			"invalid",
		); err != nil {
			return outcome, err
		}

		outcome.Status = "invalid"
		return outcome, ErrInvalidCallback
	}

	// Resolve the pinned Google client before touching the PKCE verifier.
	googleClient, err := s.clientForTransaction(ctx, transaction)
	if err != nil {
		if errors.Is(err, ErrCredentialUnavailable) {
			_ = s.transition(ctx, transaction.ID, "provider_failed")
			outcome.Status = "provider_failed"
			return outcome, err
		}

		// A transient failure must not cost the user their one-time state:
		// put the authorization back so reloading the callback can succeed.
		if resetErr := s.store.TransitionOAuthTransactionStatus(
			ctx, transaction.ID, "processing", "pending",
		); resetErr != nil {
			slog.ErrorContext(
				ctx,
				"could not return OAuth transaction to pending",
				"transaction_id", transaction.ID,
				"error", resetErr,
			)
		}
		outcome.Status = "pending"
		return outcome, fmt.Errorf("%w: %v", ErrTemporaryFailure, err)
	}

	verifierBytes, err := s.cipher.Decrypt(
		transaction.PKCEVerifierCiphertext,
		transaction.PKCEVerifierNonce,
	)
	if err != nil {
		_ = s.transition(
			ctx,
			transaction.ID,
			"provider_failed",
		)
		outcome.Status = "provider_failed"

		return outcome, fmt.Errorf(
			"%w: decrypt PKCE verifier",
			ErrProviderExchangeFailed,
		)
	}

	verifier := string(verifierBytes)
	clearBytes(verifierBytes)

	tokens, err := s.google.ExchangeCode(
		ctx,
		googleClient,
		input.Code,
		verifier,
	)
	verifier = ""
	googleClient = GoogleClient{}

	if err != nil {
		_ = s.transition(
			ctx,
			transaction.ID,
			"provider_failed",
		)
		outcome.Status = "provider_failed"

		return outcome, fmt.Errorf(
			"%w: %v",
			ErrProviderExchangeFailed,
			err,
		)
	}
	defer clearTokenSet(&tokens)

	// Google accepted the client and the code: this credential has now really
	// authorized. Informational, so a failure here does not fail the flow.
	if transaction.GoogleCredentialID != "" && s.credentials != nil {
		if markErr := s.credentials.RecordAuthorized(
			ctx,
			transaction.ProjectID,
			transaction.GoogleCredentialID,
		); markErr != nil {
			slog.WarnContext(
				ctx,
				"could not record Google credential authorization",
				"project_id", transaction.ProjectID,
				"credential_ref", transaction.GoogleCredentialID,
				"error", markErr,
			)
		}
	}

	if err := s.deliverer.Deliver(
		ctx,
		transaction,
		tokens,
	); err != nil {
		if transitionErr := s.transition(
			ctx,
			transaction.ID,
			"delivery_failed",
		); transitionErr != nil {
			return outcome, transitionErr
		}

		outcome.Status = "delivery_failed"
		return outcome, fmt.Errorf(
			"%w: %v",
			ErrDeliveryFailed,
			err,
		)
	}

	if err := s.transition(
		ctx,
		transaction.ID,
		"completed",
	); err != nil {
		return outcome, err
	}

	outcome.Status = "completed"
	return outcome, nil
}

func (s *CallbackService) transition(
	ctx context.Context,
	transactionID string,
	toStatus string,
) error {
	if err := s.store.TransitionOAuthTransactionStatus(
		ctx,
		transactionID,
		"processing",
		toStatus,
	); err != nil {
		return fmt.Errorf(
			"transition OAuth transaction to %s: %w",
			toStatus,
			err,
		)
	}

	return nil
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
