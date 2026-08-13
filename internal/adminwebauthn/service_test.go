package adminwebauthn_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/adminwebauthn"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

func TestBeginRegistrationAndDiscoverableLoginPolicy(
	t *testing.T,
) {
	store, err := sqlite.Open(
		filepath.Join(t.TempDir(), "oauth.db"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	user, err := store.CreateAdminUser(
		t.Context(),
		"admin@example.com",
		"unused-password-hash",
	)
	if err != nil {
		t.Fatal(err)
	}

	key := base64.RawURLEncoding.EncodeToString(
		bytes.Repeat([]byte{0x55}, 32),
	)

	service, err := adminwebauthn.NewService(
		store,
		adminwebauthn.Options{
			RPID:                       "example.com",
			RPName:                     "MW OAuth Test",
			Origins:                    []string{"https://admin.example.com"},
			CredentialKeys:             "1:" + key,
			CredentialActiveKeyVersion: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	creation, registrationToken, err :=
		service.BeginRegistration(
			t.Context(),
			user,
			"Windows Hello",
		)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(registrationToken, "wac_") {
		t.Fatalf(
			"registration token = %q",
			registrationToken,
		)
	}

	creationJSON, err := json.Marshal(creation)
	if err != nil {
		t.Fatal(err)
	}
	creationText := string(creationJSON)

	for _, expected := range []string{
		`"residentKey":"required"`,
		`"userVerification":"required"`,
		`"attestation":"none"`,
	} {
		if !strings.Contains(creationText, expected) {
			t.Fatalf(
				"registration options missing %s: %s",
				expected,
				creationText,
			)
		}
	}

	var storedHash string
	var storedCiphertext string
	err = store.DB().QueryRowContext(
		t.Context(),
		`SELECT token_hash, session_ciphertext
         FROM admin_webauthn_ceremonies
         WHERE purpose = 'registration'
         LIMIT 1`,
	).Scan(&storedHash, &storedCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if storedHash == registrationToken {
		t.Fatal("raw ceremony token was stored")
	}
	if strings.Contains(storedCiphertext, registrationToken) {
		t.Fatal("ceremony ciphertext contains raw token")
	}

	assertion, loginToken, err := service.BeginLogin(
		t.Context(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loginToken, "wac_") {
		t.Fatalf("login token = %q", loginToken)
	}

	assertionJSON, err := json.Marshal(assertion)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(
		string(assertionJSON),
		`"userVerification":"required"`,
	) {
		t.Fatalf(
			"login options do not require user verification: %s",
			assertionJSON,
		)
	}
}
