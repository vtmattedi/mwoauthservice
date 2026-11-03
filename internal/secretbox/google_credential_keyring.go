package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

const (
	googleCredentialKeysEnv    = "GOOGLE_CLIENT_SECRET_KEYS"
	googleCredentialAADPrefix  = "mw-oauth-service:google-client-secret:v1"
	googleCredentialProvider   = "google"
	googleCredentialKeyLength  = 32
	maxGoogleCredentialPayload = 4096
)

// GoogleCredentialContext identifies the row a Google client secret belongs to.
// It is bound into the AEAD associated data, so ciphertext copied to another
// credential or project fails authentication.
type GoogleCredentialContext struct {
	CredentialID string
	ProjectID    int64
}

func (c GoogleCredentialContext) aad() ([]byte, error) {
	if strings.TrimSpace(c.CredentialID) == "" {
		return nil, fmt.Errorf("google credential id is required")
	}
	if strings.ContainsRune(c.CredentialID, '|') {
		return nil, fmt.Errorf("google credential id contains reserved character")
	}
	if c.ProjectID <= 0 {
		return nil, fmt.Errorf("google credential project id is required")
	}

	return []byte(fmt.Sprintf(
		"%s|%s|%d|%s",
		googleCredentialAADPrefix,
		c.CredentialID,
		c.ProjectID,
		googleCredentialProvider,
	)), nil
}

// GoogleCredentialKeyring encrypts per-project Google OAuth client secrets.
// It is intentionally separate from the callback-secret Keyring: different
// environment variable, different key material and different AAD purpose.
type GoogleCredentialKeyring struct {
	keys          map[int][]byte
	activeVersion int
}

func NewGoogleCredentialKeyring(
	raw string,
	activeVersion int,
) (*GoogleCredentialKeyring, error) {
	keys, err := parseVersionedKeys(googleCredentialKeysEnv, raw)
	if err != nil {
		return nil, err
	}
	if activeVersion <= 0 {
		return nil, fmt.Errorf(
			"GOOGLE_CLIENT_SECRET_ACTIVE_KEY_VERSION must be positive",
		)
	}
	if _, ok := keys[activeVersion]; !ok {
		return nil, fmt.Errorf(
			"active Google client secret key version %d is not configured",
			activeVersion,
		)
	}

	return &GoogleCredentialKeyring{
		keys:          keys,
		activeVersion: activeVersion,
	}, nil
}

// ActiveVersion returns the key version used for new encryptions.
func (k *GoogleCredentialKeyring) ActiveVersion() int {
	return k.activeVersion
}

// HasVersion reports whether a key version can still be decrypted.
func (k *GoogleCredentialKeyring) HasVersion(version int) bool {
	_, ok := k.keys[version]
	return ok
}

func (k *GoogleCredentialKeyring) Encrypt(
	ctx GoogleCredentialContext,
	plaintext []byte,
) (ciphertext string, nonce string, keyVersion int, err error) {
	if len(plaintext) == 0 || len(plaintext) > maxGoogleCredentialPayload {
		return "", "", 0, fmt.Errorf("google client secret has invalid length")
	}

	aad, err := ctx.aad()
	if err != nil {
		return "", "", 0, err
	}

	gcm, err := newGCM(k.keys[k.activeVersion])
	if err != nil {
		return "", "", 0, err
	}

	nonceBytes := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", 0, fmt.Errorf("generate encryption nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonceBytes, plaintext, aad)

	return base64.RawURLEncoding.EncodeToString(sealed),
		base64.RawURLEncoding.EncodeToString(nonceBytes),
		k.activeVersion,
		nil
}

func (k *GoogleCredentialKeyring) Decrypt(
	ctx GoogleCredentialContext,
	ciphertext string,
	nonce string,
	keyVersion int,
) ([]byte, error) {
	key, ok := k.keys[keyVersion]
	if !ok {
		return nil, fmt.Errorf(
			"google client secret key version %d is not configured",
			keyVersion,
		)
	}

	aad, err := ctx.aad()
	if err != nil {
		return nil, err
	}

	ciphertextBytes, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonceBytes) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid encryption nonce length")
	}

	plaintext, err := gcm.Open(nil, nonceBytes, ciphertextBytes, aad)
	if err != nil {
		// Do not wrap the AEAD error: it adds nothing safe to expose.
		return nil, fmt.Errorf("decrypt google client secret failed")
	}

	return plaintext, nil
}

// EnsureIndependentGoogleCredentialKeys fails when the Google client secret
// keyring shares any key material with another keyring, so one leaked key
// cannot decrypt both purposes.
func EnsureIndependentGoogleCredentialKeys(
	googleRaw string,
	otherName string,
	otherRaw string,
) error {
	googleKeys, err := parseVersionedKeys(googleCredentialKeysEnv, googleRaw)
	if err != nil {
		return err
	}
	if strings.TrimSpace(otherRaw) == "" {
		return nil
	}
	otherKeys, err := parseVersionedKeys(otherName, otherRaw)
	if err != nil {
		// Some keys (TOKEN_ENCRYPTION_KEY) are a single unversioned value.
		// Anything else that does not parse is validated where it is used.
		single, decodeErr := decodeKey(strings.TrimSpace(otherRaw))
		if decodeErr != nil || len(single) != googleCredentialKeyLength {
			return nil
		}
		otherKeys = map[int][]byte{0: single}
	}

	for _, g := range googleKeys {
		for _, o := range otherKeys {
			if subtle.ConstantTimeCompare(g, o) == 1 {
				return fmt.Errorf(
					"%s must not reuse key material from %s",
					googleCredentialKeysEnv,
					otherName,
				)
			}
		}
	}

	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return gcm, nil
}

func parseVersionedKeys(name string, raw string) (map[int][]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%s is required", name)
	}

	keys := make(map[int][]byte)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		versionText, encodedKey, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("invalid %s entry (expected version:key)", name)
		}

		version, err := strconv.Atoi(strings.TrimSpace(versionText))
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("invalid %s key version %q", name, versionText)
		}

		key, err := decodeKey(strings.TrimSpace(encodedKey))
		if err != nil {
			return nil, fmt.Errorf("decode %s key version %d: %w", name, version, err)
		}
		if len(key) != googleCredentialKeyLength {
			return nil, fmt.Errorf(
				"%s key version %d must decode to %d bytes",
				name, version, googleCredentialKeyLength,
			)
		}
		if _, exists := keys[version]; exists {
			return nil, fmt.Errorf("duplicate %s key version %d", name, version)
		}
		keys[version] = key
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys configured in %s", name)
	}
	return keys, nil
}
