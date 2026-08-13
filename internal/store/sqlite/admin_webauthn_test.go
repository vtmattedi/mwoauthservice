package sqlite

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/adminwebauthn"
)

func TestWebAuthnUserHandleStableAndCeremonySingleUse(
	t *testing.T,
) {
	store, err := Open(
		filepath.Join(t.TempDir(), "oauth.db"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	user, err := store.CreateAdminUser(
		t.Context(),
		"webauthn@example.com",
		"unused-password-hash",
	)
	if err != nil {
		t.Fatal(err)
	}

	firstHandle := bytes.Repeat([]byte{0x11}, 64)
	first, err := store.EnsureWebAuthnUser(
		t.Context(),
		user.ID,
		"example.com",
		firstHandle,
	)
	if err != nil {
		t.Fatal(err)
	}

	second, err := store.EnsureWebAuthnUser(
		t.Context(),
		user.ID,
		"example.com",
		bytes.Repeat([]byte{0x22}, 64),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first.UserHandle, second.UserHandle) {
		t.Fatal("WebAuthn user handle changed")
	}

	now := time.Now().UTC().Unix()
	err = store.CreateWebAuthnCeremony(
		t.Context(),
		adminwebauthn.CeremonyRecord{
			TokenHash:         "hash-one",
			AdminUserID:       &user.ID,
			RPID:              "example.com",
			Purpose:           "registration",
			SessionCiphertext: "ciphertext",
			SessionNonce:      "nonce",
			SessionKeyVersion: 1,
			ExpiresAtUnix:     now + 60,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.ConsumeWebAuthnCeremony(
		t.Context(),
		"hash-one",
		now,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := store.ConsumeWebAuthnCeremony(
		t.Context(),
		"hash-one",
		now,
	); !errors.Is(err, adminwebauthn.ErrCeremonyUsed) {
		t.Fatalf("second consume err = %v", err)
	}

	err = store.CreateWebAuthnCeremony(
		t.Context(),
		adminwebauthn.CeremonyRecord{
			TokenHash:         "hash-expired",
			AdminUserID:       &user.ID,
			RPID:              "example.com",
			Purpose:           "registration",
			SessionCiphertext: "ciphertext",
			SessionNonce:      "nonce",
			SessionKeyVersion: 1,
			ExpiresAtUnix:     now - 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.ConsumeWebAuthnCeremony(
		t.Context(),
		"hash-expired",
		now,
	); !errors.Is(err, adminwebauthn.ErrCeremonyExpired) {
		t.Fatalf("expired consume err = %v", err)
	}
}
