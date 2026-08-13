package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	maxProviderStateLength = 1024
	maxProviderCodeLength  = 16384
	maxProviderErrorLength = 256
)

type CallbackService struct {
	store     CallbackStore
	cipher    PKCEDecrypter
	google    GoogleCodeExchanger
	deliverer ResultDeliverer
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

	return &CallbackService{
		store:     store,
		cipher:    cipher,
		google:    google,
		deliverer: deliverer,
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
		input.Code,
		verifier,
	)
	verifier = ""

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
