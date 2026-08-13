package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
	"github.com/vtmattedi/mw-oauth-service/internal/transactioncrypto"
)

type callbackTestGoogle struct{}

func (callbackTestGoogle) ExchangeCode(
	ctx context.Context,
	code string,
	verifier string,
) (oauth.TokenSet, error) {
	return oauth.TokenSet{
		AccessToken: "access",
	}, nil
}

func TestGoogleCallbackDenialRedirectsTrustedReturnURL(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	projectRow, err := store.CreateProject(
		context.Background(),
		project.CreateRecord{
			Name:                     "Callback API Test",
			Enabled:                  true,
			TokenHash:                "callback-api-hash",
			CallbackSecretCiphertext: "cipher",
			CallbackSecretNonce:      "nonce",
			CallbackSecretKeyVersion: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	key := bytes.Repeat([]byte{0x66}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)
	cipher, err := transactioncrypto.New(encoded)
	if err != nil {
		t.Fatal(err)
	}

	encryptedVerifier, nonce, err := cipher.Encrypt(
		[]byte("verifier"),
	)
	if err != nil {
		t.Fatal(err)
	}

	state := "callback-api-state"
	stateSum := sha256.Sum256([]byte(state))
	stateHash := fmt.Sprintf("%x", stateSum[:])

	now := time.Now().UTC().Unix()
	returnURL := "https://app.example.com/settings/integrations"

	transaction := domain.OAuthTransaction{
		ID:                     "oauth_txn_callback_api",
		ProjectID:              projectRow.ID,
		Provider:               "google",
		StateHash:              stateHash,
		PKCEVerifierCiphertext: encryptedVerifier,
		PKCEVerifierNonce:      nonce,
		ClientReference:        "ref",
		CallbackURL:            "https://app.example.com/callback",
		ReturnURL:              returnURL,
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
		callbackTestGoogle{},
		oauth.UnavailableDeliverer{},
	)
	if err != nil {
		t.Fatal(err)
	}

	handler := RequestID(
		GoogleOAuthCallback(
			callbackService,
			audit.NewService(store),
		),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/oauth/google/callback?state="+
			url.QueryEscape(state)+
			"&error=access_denied",
		nil,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusSeeOther,
		)
	}

	location := response.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Scheme+"://"+parsed.Host+parsed.Path != returnURL {
		t.Fatalf(
			"redirect base = %q; want %q",
			parsed.Scheme+"://"+parsed.Host+parsed.Path,
			returnURL,
		)
	}

	if parsed.Query().Get("mw_oauth_status") != "denied" {
		t.Fatalf(
			"redirect status = %q",
			parsed.Query().Get("mw_oauth_status"),
		)
	}
	if parsed.Query().Get("code") != "" {
		t.Fatal("provider code leaked into redirect")
	}
	if parsed.Query().Get("state") != "" {
		t.Fatal("provider state leaked into redirect")
	}
}
