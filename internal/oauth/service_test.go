package oauth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
	"github.com/vtmattedi/mw-oauth-service/internal/transactioncrypto"
)

func TestAuthorizeGoogleCreatesProtectedTransaction(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	projectRow, err := store.CreateProject(
		context.Background(),
		project.CreateRecord{
			Name:                     "OAuth Test",
			Enabled:                  true,
			TokenHash:                project.HashAPIKey("mw_live_test"),
			CallbackSecretCiphertext: "cipher",
			CallbackSecretNonce:      "nonce",
			CallbackSecretKeyVersion: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	err = store.ReplaceGoogleOAuthConfig(
		context.Background(),
		projectRow.ID,
		domain.GoogleOAuthConfig{
			Enabled: true,
			AllowedScopes: []string{
				"https://www.googleapis.com/auth/calendar",
			},
			AllowedCallbackURLs: []string{
				"https://app.example.com/api/oauth/google/result",
			},
			AllowedReturnURLs: []string{
				"https://app.example.com/settings/integrations",
			},
			Limits: domain.OAuthLimits{
				PerMinute:  10,
				PerHour:    100,
				MaxPending: 50,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	projectService := project.NewService(store, nil)

	key := bytes.Repeat([]byte{0x55}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)
	transactionCipher, err := transactioncrypto.New(encoded)
	if err != nil {
		t.Fatal(err)
	}

	service, err := oauth.NewService(
		store,
		projectService,
		transactionCipher,
		oauth.Options{
			GoogleClientID:    "google-client-id",
			GoogleRedirectURI: "https://oauth.example.com/oauth/google/callback",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	authenticated, err := service.AuthenticateProject(
		context.Background(),
		"mw_live_test",
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.AuthorizeGoogle(
		context.Background(),
		authenticated,
		oauth.GoogleAuthorizationRequest{
			Scopes: []string{
				"https://www.googleapis.com/auth/calendar",
			},
			CallbackURL:     "https://app.example.com/api/oauth/google/result",
			ReturnURL:       "https://app.example.com/settings/integrations",
			ClientReference: "oauth_pending_123",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(
		result.TransactionID,
		"oauth_txn_",
	) {
		t.Fatalf(
			"transaction id = %q",
			result.TransactionID,
		)
	}

	parsed, err := url.Parse(result.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}

	state := parsed.Query().Get("state")
	challenge := parsed.Query().Get("code_challenge")

	if state == "" {
		t.Fatal("authorization URL is missing state")
	}
	if challenge == "" {
		t.Fatal("authorization URL is missing PKCE challenge")
	}
	if parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("expected S256 PKCE")
	}

	var stateHash string
	var verifierCiphertext string
	var verifierNonce string
	var status string

	err = store.DB().QueryRow(
		`SELECT
            state_hash,
            pkce_verifier_ciphertext,
            pkce_verifier_nonce,
            status
         FROM oauth_transactions
         WHERE id = ?`,
		result.TransactionID,
	).Scan(
		&stateHash,
		&verifierCiphertext,
		&verifierNonce,
		&status,
	)
	if err != nil {
		t.Fatal(err)
	}

	stateSum := sha256.Sum256([]byte(state))
	expectedStateHash := strings.ToLower(
		fmt.Sprintf("%x", stateSum[:]),
	)

	if stateHash != expectedStateHash {
		t.Fatal("stored state hash does not match returned state")
	}
	if stateHash == state {
		t.Fatal("raw state was stored")
	}

	verifier, err := transactionCipher.Decrypt(
		verifierCiphertext,
		verifierNonce,
	)
	if err != nil {
		t.Fatal(err)
	}

	verifierSum := sha256.Sum256(verifier)
	expectedChallenge := base64.RawURLEncoding.EncodeToString(
		verifierSum[:],
	)

	if challenge != expectedChallenge {
		t.Fatal("stored PKCE verifier does not match URL challenge")
	}
	if status != "pending" {
		t.Fatalf("transaction status = %q; want pending", status)
	}
}

func TestAuthorizeGoogleEnforcesPerMinuteRateLimit(t *testing.T) {
	store, service, authenticated := newRateLimitTestService(t)

	request := oauth.GoogleAuthorizationRequest{
		Scopes:          []string{"scope"},
		CallbackURL:     "https://app.example.com/callback",
		ReturnURL:       "https://app.example.com/return",
		ClientReference: "ref-1",
	}

	if _, err := service.AuthorizeGoogle(
		context.Background(),
		authenticated,
		request,
	); err != nil {
		t.Fatal(err)
	}

	request.ClientReference = "ref-2"

	_, err := service.AuthorizeGoogle(
		context.Background(),
		authenticated,
		request,
	)
	if err == nil {
		t.Fatal("expected rate limit")
	}

	var rateLimit *oauth.RateLimitError
	if !errors.As(err, &rateLimit) {
		t.Fatalf("expected RateLimitError; got %T: %v", err, err)
	}
	if rateLimit.Reason != "per_minute" {
		t.Fatalf(
			"rate limit reason = %q; want per_minute",
			rateLimit.Reason,
		)
	}

	_ = store
}

func newRateLimitTestService(
	t *testing.T,
) (
	*sqlite.Store,
	*oauth.Service,
	domain.Project,
) {
	t.Helper()

	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	projectRow, err := store.CreateProject(
		context.Background(),
		project.CreateRecord{
			Name:                     "Rate Limit Test",
			Enabled:                  true,
			TokenHash:                project.HashAPIKey("mw_live_rate"),
			CallbackSecretCiphertext: "cipher",
			CallbackSecretNonce:      "nonce",
			CallbackSecretKeyVersion: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	err = store.ReplaceGoogleOAuthConfig(
		context.Background(),
		projectRow.ID,
		domain.GoogleOAuthConfig{
			Enabled:       true,
			AllowedScopes: []string{"scope"},
			AllowedCallbackURLs: []string{
				"https://app.example.com/callback",
			},
			AllowedReturnURLs: []string{
				"https://app.example.com/return",
			},
			Limits: domain.OAuthLimits{
				PerMinute:  1,
				PerHour:    100,
				MaxPending: 50,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	projectService := project.NewService(store, nil)

	key := bytes.Repeat([]byte{0x77}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	transactionCipher, err := transactioncrypto.New(encoded)
	if err != nil {
		t.Fatal(err)
	}

	service, err := oauth.NewService(
		store,
		projectService,
		transactionCipher,
		oauth.Options{
			GoogleClientID:    "client-id",
			GoogleRedirectURI: "https://oauth.example.com/oauth/google/callback",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	authenticated, err := service.AuthenticateProject(
		context.Background(),
		"mw_live_rate",
	)
	if err != nil {
		t.Fatal(err)
	}

	return store, service, authenticated
}
