package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

var callbackSecretAAD = []byte(
	"mw-oauth-service:callback-secret:v1",
)

type Keyring struct {
	keys          map[int][]byte
	activeVersion int
}

func NewKeyring(raw string, activeVersion int) (*Keyring, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("CALLBACK_SECRET_KEYS is required")
	}
	if activeVersion <= 0 {
		return nil, fmt.Errorf(
			"CALLBACK_SECRET_ACTIVE_KEY_VERSION must be positive",
		)
	}

	keys := make(map[int][]byte)

	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		versionText, encodedKey, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf(
				"invalid CALLBACK_SECRET_KEYS entry %q",
				entry,
			)
		}

		version, err := strconv.Atoi(strings.TrimSpace(versionText))
		if err != nil || version <= 0 {
			return nil, fmt.Errorf(
				"invalid callback secret key version %q",
				versionText,
			)
		}

		key, err := decodeKey(strings.TrimSpace(encodedKey))
		if err != nil {
			return nil, fmt.Errorf(
				"decode callback secret key version %d: %w",
				version,
				err,
			)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf(
				"callback secret key version %d must decode to 32 bytes",
				version,
			)
		}

		if _, exists := keys[version]; exists {
			return nil, fmt.Errorf(
				"duplicate callback secret key version %d",
				version,
			)
		}

		keys[version] = key
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no callback secret keys configured")
	}

	if _, exists := keys[activeVersion]; !exists {
		return nil, fmt.Errorf(
			"active callback secret key version %d is not configured",
			activeVersion,
		)
	}

	return &Keyring{
		keys:          keys,
		activeVersion: activeVersion,
	}, nil
}

func (k *Keyring) Encrypt(
	plaintext []byte,
) (
	ciphertext string,
	nonce string,
	keyVersion int,
	err error,
) {
	key := k.keys[k.activeVersion]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", 0, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", 0, fmt.Errorf("create AES-GCM: %w", err)
	}

	nonceBytes := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", 0, fmt.Errorf("generate encryption nonce: %w", err)
	}

	sealed := gcm.Seal(
		nil,
		nonceBytes,
		plaintext,
		callbackSecretAAD,
	)

	return base64.RawURLEncoding.EncodeToString(sealed),
		base64.RawURLEncoding.EncodeToString(nonceBytes),
		k.activeVersion,
		nil
}

func (k *Keyring) Decrypt(
	ciphertext string,
	nonce string,
	keyVersion int,
) ([]byte, error) {
	key, exists := k.keys[keyVersion]
	if !exists {
		return nil, fmt.Errorf(
			"callback secret key version %d is not configured",
			keyVersion,
		)
	}

	ciphertextBytes, err := base64.RawURLEncoding.DecodeString(
		ciphertext,
	)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}

	if len(nonceBytes) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid encryption nonce length")
	}

	plaintext, err := gcm.Open(
		nil,
		nonceBytes,
		ciphertextBytes,
		callbackSecretAAD,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt callback secret: %w", err)
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
