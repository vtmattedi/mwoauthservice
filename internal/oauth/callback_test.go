package oauth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
	"github.com/vtmattedi/mw-oauth-service/internal/transactioncrypto"
)

// realCredentials gives the project a real, encrypted Google client and
// returns the service together with the credential's reference.
func realCredentials(
	t *testing.T,
	store *sqlite.Store,
	projectID int64,
) (*googlecred.Service, string) {
	t.Helper()

	keys, err := secretbox.NewGoogleCredentialKeyring(
		"1:"+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32)),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	service := googlecred.NewService(store, keys)
	configured, err := service.Configure(
		context.Background(),
		projectID,
		"test-client.apps.googleusercontent.com",
		"GOCSPX-test-secret-value",
	)
	if err != nil {
		t.Fatal(err)
	}

	return service, configured.Credential.ID
}

type fakeGoogleExchanger struct {
	tokens oauth.TokenSet
	err    error
}

func (f fakeGoogleExchanger) ExchangeCode(
	ctx context.Context,
	client oauth.GoogleClient,
	code string,
	verifier string,
) (oauth.TokenSet, error) {
	if code != "provider-code" {
		return oauth.TokenSet{}, fmt.Errorf(
			"unexpected provider code %q",
			code,
		)
	}
	if verifier != "test-verifier" {
		return oauth.TokenSet{}, fmt.Errorf(
			"unexpected verifier %q",
			verifier,
		)
	}

	return f.tokens, f.err
}

type captureDeliverer struct {
	delivered bool
}

func (d *captureDeliverer) Deliver(
	ctx context.Context,
	transaction domain.OAuthTransaction,
	tokens oauth.TokenSet,
) error {
	if transaction.ID != "oauth_txn_callback" {
		return fmt.Errorf(
			"unexpected transaction %q",
			transaction.ID,
		)
	}
	if tokens.AccessToken != "access" {
		return fmt.Errorf("unexpected access token")
	}

	d.delivered = true
	return nil
}

func TestGoogleCallbackCompletesWithSuccessfulDeliverer(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	projectRow, err := store.CreateProject(
		context.Background(),
		project.CreateRecord{
			Name:                     "Callback Service Test",
			Enabled:                  true,
			CallbackSecretCiphertext: "cipher",
			CallbackSecretNonce:      "nonce",
			CallbackSecretKeyVersion: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	creds, credentialRef := realCredentials(t, store, projectRow.ID)

	key := bytes.Repeat([]byte{0x64}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	cipher, err := transactioncrypto.New(encoded)
	if err != nil {
		t.Fatal(err)
	}

	verifierCiphertext, verifierNonce, err := cipher.Encrypt(
		[]byte("test-verifier"),
	)
	if err != nil {
		t.Fatal(err)
	}

	state := "raw-state"
	stateSum := sha256.Sum256([]byte(state))
	stateHash := fmt.Sprintf("%x", stateSum[:])

	now := time.Now().UTC().Unix()

	transaction := domain.OAuthTransaction{
		GoogleCredentialID:     credentialRef,
		ID:                     "oauth_txn_callback",
		ProjectID:              projectRow.ID,
		Provider:               "google",
		StateHash:              stateHash,
		PKCEVerifierCiphertext: verifierCiphertext,
		PKCEVerifierNonce:      verifierNonce,
		ClientReference:        "ref",
		CallbackURL:            "https://app.example.com/callback",
		ReturnURL:              "https://app.example.com/return",
		RequestedScopesJSON:    `["scope"]`,
		Status:                 "pending",
		ExpiresAtUnix:          now + 600,
		CreatedAtUnix:          now,
	}

	if err := store.CreateOAuthTransaction(
		context.Background(),
		transaction,
		domain.OAuthLimits{
			PerMinute:  10,
			PerHour:    100,
			MaxPending: 50,
		},
		now,
	); err != nil {
		t.Fatal(err)
	}

	deliverer := &captureDeliverer{}

	callbackService, err := oauth.NewCallbackService(
		store,
		cipher,
		fakeGoogleExchanger{
			tokens: oauth.TokenSet{
				AccessToken:  "access",
				RefreshToken: "refresh",
				TokenType:    "Bearer",
				ExpiresIn:    3599,
				Scopes:       []string{"scope"},
			},
		},
		deliverer,
		oauth.WithCredentials(creds),
	)
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := callbackService.HandleGoogle(
		context.Background(),
		oauth.GoogleCallbackInput{
			State: state,
			Code:  "provider-code",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if outcome.Status != "completed" {
		t.Fatalf(
			"outcome status = %q; want completed",
			outcome.Status,
		)
	}
	if !deliverer.delivered {
		t.Fatal("deliverer was not called")
	}

	var status string
	if err := store.DB().QueryRow(
		`SELECT status
         FROM oauth_transactions
         WHERE id = ?`,
		transaction.ID,
	).Scan(&status); err != nil {
		t.Fatal(err)
	}

	if status != "completed" {
		t.Fatalf(
			"stored status = %q; want completed",
			status,
		)
	}
}

func TestUnavailableDelivererMarksDeliveryFailed(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	projectRow, err := store.CreateProject(
		context.Background(),
		project.CreateRecord{
			Name:                     "Delivery Failure Test",
			Enabled:                  true,
			CallbackSecretCiphertext: "cipher",
			CallbackSecretNonce:      "nonce",
			CallbackSecretKeyVersion: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	creds, credentialRef := realCredentials(t, store, projectRow.ID)

	key := bytes.Repeat([]byte{0x65}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	cipher, err := transactioncrypto.New(encoded)
	if err != nil {
		t.Fatal(err)
	}

	verifierCiphertext, verifierNonce, err := cipher.Encrypt(
		[]byte("test-verifier"),
	)
	if err != nil {
		t.Fatal(err)
	}

	state := "raw-state-failure"
	stateSum := sha256.Sum256([]byte(state))
	stateHash := fmt.Sprintf("%x", stateSum[:])

	now := time.Now().UTC().Unix()

	transaction := domain.OAuthTransaction{
		GoogleCredentialID:     credentialRef,
		ID:                     "oauth_txn_delivery_failure",
		ProjectID:              projectRow.ID,
		Provider:               "google",
		StateHash:              stateHash,
		PKCEVerifierCiphertext: verifierCiphertext,
		PKCEVerifierNonce:      verifierNonce,
		ClientReference:        "ref",
		CallbackURL:            "https://app.example.com/callback",
		ReturnURL:              "https://app.example.com/return",
		RequestedScopesJSON:    `["scope"]`,
		Status:                 "pending",
		ExpiresAtUnix:          now + 600,
		CreatedAtUnix:          now,
	}

	if err := store.CreateOAuthTransaction(
		context.Background(),
		transaction,
		domain.OAuthLimits{
			PerMinute:  10,
			PerHour:    100,
			MaxPending: 50,
		},
		now,
	); err != nil {
		t.Fatal(err)
	}

	callbackService, err := oauth.NewCallbackService(
		store,
		cipher,
		fakeGoogleExchanger{
			tokens: oauth.TokenSet{
				AccessToken: "access",
			},
		},
		oauth.UnavailableDeliverer{},
		oauth.WithCredentials(creds),
	)
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := callbackService.HandleGoogle(
		context.Background(),
		oauth.GoogleCallbackInput{
			State: state,
			Code:  "provider-code",
		},
	)
	if err == nil {
		t.Fatal("expected delivery failure")
	}
	if outcome.Status != "delivery_failed" {
		t.Fatalf(
			"outcome status = %q; want delivery_failed",
			outcome.Status,
		)
	}

	var status string
	if err := store.DB().QueryRow(
		`SELECT status
         FROM oauth_transactions
         WHERE id = ?`,
		transaction.ID,
	).Scan(&status); err != nil {
		t.Fatal(err)
	}

	if status != "delivery_failed" {
		t.Fatalf(
			"stored status = %q; want delivery_failed",
			status,
		)
	}
}
