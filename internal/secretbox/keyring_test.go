package secretbox

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestKeyringEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	ring, err := NewKeyring("1:"+encoded, 1)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, nonce, version, err := ring.Encrypt(
		[]byte("mw_whsec_example"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if ciphertext == "mw_whsec_example" {
		t.Fatal("secret was not encrypted")
	}
	if version != 1 {
		t.Fatalf("version = %d; want 1", version)
	}

	plaintext, err := ring.Decrypt(
		ciphertext,
		nonce,
		version,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != "mw_whsec_example" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestKeyringRequiresActiveVersion(t *testing.T) {
	key := bytes.Repeat([]byte{0x21}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	if _, err := NewKeyring("1:"+encoded, 2); err == nil {
		t.Fatal("expected missing active version to fail")
	}
}
