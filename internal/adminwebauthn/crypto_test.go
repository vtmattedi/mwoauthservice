package adminwebauthn

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestKeyringEncryptDecryptUsesAAD(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(
		bytes.Repeat([]byte{0x41}, 32),
	)

	keyring, err := NewKeyring("1:"+key, 1)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, nonce, version, err := keyring.Encrypt(
		[]byte("credential"),
		[]byte("aad-one"),
	)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := keyring.Decrypt(
		ciphertext,
		nonce,
		version,
		[]byte("aad-one"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "credential" {
		t.Fatalf("plaintext = %q", plaintext)
	}

	if _, err := keyring.Decrypt(
		ciphertext,
		nonce,
		version,
		[]byte("aad-two"),
	); err == nil {
		t.Fatal("expected wrong AAD to fail")
	}
}
