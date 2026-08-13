package transactioncrypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	cipher, err := New(encoded)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, nonce, err := cipher.Encrypt(
		[]byte("pkce-verifier-example"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if ciphertext == "pkce-verifier-example" {
		t.Fatal("verifier was not encrypted")
	}

	plaintext, err := cipher.Decrypt(ciphertext, nonce)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != "pkce-verifier-example" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}
