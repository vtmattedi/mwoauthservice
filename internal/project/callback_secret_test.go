package project_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

func TestCallbackSigningSecretDecryptsOnlyOnDemand(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	key := bytes.Repeat([]byte{0x33}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	keyring, err := secretbox.NewKeyring(
		"1:"+encoded,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	service := project.NewService(store, keyring)

	credentials, err := service.Create(
		context.Background(),
		"Callback Secret Read Test",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := service.CallbackSigningSecret(
		context.Background(),
		credentials.Project.ID,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()

	if string(plaintext) != credentials.CallbackSecret {
		t.Fatal("decrypted callback secret does not match")
	}

	var ciphertext string
	if err := store.DB().QueryRow(
		`SELECT callback_secret_ciphertext
         FROM projects
         WHERE id = ?`,
		credentials.Project.ID,
	).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}

	if ciphertext == credentials.CallbackSecret {
		t.Fatal("raw callback secret was persisted")
	}
}
