package transactioncrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

var pkceVerifierAAD = []byte(
	"mw-oauth-service:pkce-verifier:v1",
)

type Cipher struct {
	key []byte
}

func New(raw string) (*Cipher, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("TOKEN_ENCRYPTION_KEY is required")
	}

	key, err := decodeKey(raw)
	if err != nil {
		return nil, fmt.Errorf(
			"decode TOKEN_ENCRYPTION_KEY: %w",
			err,
		)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf(
			"TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes",
		)
	}

	return &Cipher{key: key}, nil
}

func (c *Cipher) Encrypt(
	plaintext []byte,
) (
	ciphertext string,
	nonce string,
	err error,
) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", "", fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("create AES-GCM: %w", err)
	}

	nonceBytes := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", fmt.Errorf(
			"generate transaction nonce: %w",
			err,
		)
	}

	sealed := gcm.Seal(
		nil,
		nonceBytes,
		plaintext,
		pkceVerifierAAD,
	)

	return base64.RawURLEncoding.EncodeToString(sealed),
		base64.RawURLEncoding.EncodeToString(nonceBytes),
		nil
}

func (c *Cipher) Decrypt(
	ciphertext string,
	nonce string,
) ([]byte, error) {
	ciphertextBytes, err := base64.RawURLEncoding.DecodeString(
		ciphertext,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"decode transaction ciphertext: %w",
			err,
		)
	}

	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return nil, fmt.Errorf(
			"decode transaction nonce: %w",
			err,
		)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}

	if len(nonceBytes) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid transaction nonce length")
	}

	plaintext, err := gcm.Open(
		nil,
		nonceBytes,
		ciphertextBytes,
		pkceVerifierAAD,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"decrypt PKCE verifier: %w",
			err,
		)
	}

	return plaintext, nil
}

func decodeKey(raw string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(raw)
	if err == nil {
		return key, nil
	}

	key, stdErr := base64.StdEncoding.DecodeString(raw)
	if stdErr == nil {
		return key, nil
	}

	return nil, err
}
