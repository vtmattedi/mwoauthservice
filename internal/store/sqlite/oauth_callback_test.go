package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
)

func TestConsumeOAuthTransactionIsSingleUse(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	projectRow, err := store.CreateProject(
		context.Background(),
		testProjectRecord("Callback Test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Unix()

	transaction := domain.OAuthTransaction{
		ID:                     "oauth_txn_test",
		ProjectID:              projectRow.ID,
		Provider:               "google",
		StateHash:              "state-hash",
		PKCEVerifierCiphertext: "ciphertext",
		PKCEVerifierNonce:      "nonce",
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

	consumed, err := store.ConsumeOAuthTransactionByStateHash(
		context.Background(),
		"state-hash",
		now,
	)
	if err != nil {
		t.Fatal(err)
	}

	if consumed.Status != "processing" {
		t.Fatalf(
			"status = %q; want processing",
			consumed.Status,
		)
	}
	if consumed.ConsumedAtUnix == nil {
		t.Fatal("expected consumed_at_unix")
	}

	_, err = store.ConsumeOAuthTransactionByStateHash(
		context.Background(),
		"state-hash",
		now,
	)
	if !errors.Is(err, oauth.ErrTransactionConsumed) {
		t.Fatalf(
			"second consume error = %v; want consumed",
			err,
		)
	}
}

func TestConsumeOAuthTransactionExpiresAtomically(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	projectRow, err := store.CreateProject(
		context.Background(),
		testProjectRecord("Expired Callback Test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Unix()

	transaction := domain.OAuthTransaction{
		ID:                     "oauth_txn_expired",
		ProjectID:              projectRow.ID,
		Provider:               "google",
		StateHash:              "expired-state-hash",
		PKCEVerifierCiphertext: "ciphertext",
		PKCEVerifierNonce:      "nonce",
		ClientReference:        "ref",
		CallbackURL:            "https://app.example.com/callback",
		ReturnURL:              "https://app.example.com/return",
		RequestedScopesJSON:    `["scope"]`,
		Status:                 "pending",
		ExpiresAtUnix:          now - 1,
		CreatedAtUnix:          now - 601,
	}

	if err := store.CreateOAuthTransaction(
		context.Background(),
		transaction,
		domain.OAuthLimits{
			PerMinute:  10,
			PerHour:    100,
			MaxPending: 50,
		},
		now-601,
	); err != nil {
		t.Fatal(err)
	}

	consumed, err := store.ConsumeOAuthTransactionByStateHash(
		context.Background(),
		"expired-state-hash",
		now,
	)
	if !errors.Is(err, oauth.ErrTransactionExpired) {
		t.Fatalf(
			"consume error = %v; want expired",
			err,
		)
	}
	if consumed.Status != "expired" {
		t.Fatalf(
			"status = %q; want expired",
			consumed.Status,
		)
	}
}
