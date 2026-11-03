package secretbox

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func testKey(b byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func newTestGoogleRing(t *testing.T, raw string, active int) *GoogleCredentialKeyring {
	t.Helper()
	ring, err := NewGoogleCredentialKeyring(raw, active)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

var testCtx = GoogleCredentialContext{CredentialID: "gcred_abc", ProjectID: 7}

func TestGoogleCredentialRoundTrip(t *testing.T) {
	ring := newTestGoogleRing(t, "1:"+testKey(1), 1)

	ct, nonce, version, err := ring.Encrypt(testCtx, []byte("GOCSPX-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ct, "GOCSPX") || version != 1 {
		t.Fatalf("unexpected ciphertext/version: %q %d", ct, version)
	}

	got, err := ring.Decrypt(testCtx, ct, nonce, version)
	if err != nil || string(got) != "GOCSPX-secret" {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
}

func TestGoogleCredentialNonceIsRandom(t *testing.T) {
	ring := newTestGoogleRing(t, "1:"+testKey(1), 1)
	_, n1, _, _ := ring.Encrypt(testCtx, []byte("s"))
	_, n2, _, _ := ring.Encrypt(testCtx, []byte("s"))
	if n1 == n2 {
		t.Fatal("nonce reused")
	}
}

func TestGoogleCredentialRejectsWrongContext(t *testing.T) {
	ring := newTestGoogleRing(t, "1:"+testKey(1), 1)
	ct, nonce, version, _ := ring.Encrypt(testCtx, []byte("secret"))

	for name, ctx := range map[string]GoogleCredentialContext{
		"other project":    {CredentialID: "gcred_abc", ProjectID: 8},
		"other credential": {CredentialID: "gcred_xyz", ProjectID: 7},
	} {
		if _, err := ring.Decrypt(ctx, ct, nonce, version); err == nil {
			t.Fatalf("%s: expected decrypt failure", name)
		}
	}
}

func TestGoogleCredentialRejectsTampering(t *testing.T) {
	ring := newTestGoogleRing(t, "1:"+testKey(1), 1)
	ct, nonce, version, _ := ring.Encrypt(testCtx, []byte("secret"))

	raw, _ := base64.RawURLEncoding.DecodeString(ct)
	raw[0] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	if _, err := ring.Decrypt(testCtx, tampered, nonce, version); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}
}

func TestGoogleCredentialKeyRotation(t *testing.T) {
	old := newTestGoogleRing(t, "1:"+testKey(1), 1)
	ct, nonce, version, _ := old.Encrypt(testCtx, []byte("secret"))

	rotated := newTestGoogleRing(t, "1:"+testKey(1)+",2:"+testKey(2), 2)
	if rotated.ActiveVersion() != 2 || !rotated.HasVersion(1) {
		t.Fatal("rotated ring should keep version 1 and activate 2")
	}

	got, err := rotated.Decrypt(testCtx, ct, nonce, version)
	if err != nil || string(got) != "secret" {
		t.Fatalf("old-version decrypt = %q, %v", got, err)
	}

	_, _, newVersion, _ := rotated.Encrypt(testCtx, []byte("secret"))
	if newVersion != 2 {
		t.Fatalf("new encryption used version %d; want 2", newVersion)
	}
}

func TestGoogleCredentialMissingKeyVersion(t *testing.T) {
	old := newTestGoogleRing(t, "1:"+testKey(1), 1)
	ct, nonce, version, _ := old.Encrypt(testCtx, []byte("secret"))

	onlyNew := newTestGoogleRing(t, "2:"+testKey(2), 2)
	if _, err := onlyNew.Decrypt(testCtx, ct, nonce, version); err == nil {
		t.Fatal("expected missing key version to fail")
	}
}

func TestGoogleCredentialConfigValidation(t *testing.T) {
	cases := map[string]struct {
		raw    string
		active int
	}{
		"empty":          {"", 1},
		"bad entry":      {"nokey", 1},
		"bad version":    {"x:" + testKey(1), 1},
		"short key":      {"1:" + base64.RawURLEncoding.EncodeToString([]byte("short")), 1},
		"duplicate":      {"1:" + testKey(1) + ",1:" + testKey(2), 1},
		"missing active": {"1:" + testKey(1), 2},
		"non-positive":   {"1:" + testKey(1), 0},
	}
	for name, tc := range cases {
		if _, err := NewGoogleCredentialKeyring(tc.raw, tc.active); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestGoogleCredentialRejectsBadInputs(t *testing.T) {
	ring := newTestGoogleRing(t, "1:"+testKey(1), 1)

	if _, _, _, err := ring.Encrypt(testCtx, nil); err == nil {
		t.Fatal("empty secret should fail")
	}
	if _, _, _, err := ring.Encrypt(GoogleCredentialContext{ProjectID: 1}, []byte("s")); err == nil {
		t.Fatal("missing credential id should fail")
	}
	if _, _, _, err := ring.Encrypt(GoogleCredentialContext{CredentialID: "a|b", ProjectID: 1}, []byte("s")); err == nil {
		t.Fatal("separator in credential id should fail")
	}
	if _, _, _, err := ring.Encrypt(GoogleCredentialContext{CredentialID: "a"}, []byte("s")); err == nil {
		t.Fatal("missing project id should fail")
	}
}

func TestGoogleCredentialErrorsDoNotLeakKeyOrSecret(t *testing.T) {
	ring := newTestGoogleRing(t, "1:"+testKey(1), 1)
	ct, nonce, version, _ := ring.Encrypt(testCtx, []byte("TOPSECRET"))

	_, err := ring.Decrypt(GoogleCredentialContext{CredentialID: "other", ProjectID: 7}, ct, nonce, version)
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") || strings.Contains(err.Error(), testKey(1)) {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestGoogleCredentialKeysAreIndependentFromCallbackKeys(t *testing.T) {
	shared := "1:" + testKey(9)
	if err := EnsureIndependentGoogleCredentialKeys(shared, "CALLBACK_SECRET_KEYS", shared); err == nil {
		t.Fatal("shared key material should be rejected")
	}
	if err := EnsureIndependentGoogleCredentialKeys(
		"1:"+testKey(1), "CALLBACK_SECRET_KEYS", "1:"+testKey(2),
	); err != nil {
		t.Fatalf("distinct keys rejected: %v", err)
	}
	if err := EnsureIndependentGoogleCredentialKeys(
		"1:"+testKey(5), "TOKEN_ENCRYPTION_KEY", testKey(5),
	); err == nil {
		t.Fatal("shared unversioned key should be rejected")
	}
	if err := EnsureIndependentGoogleCredentialKeys("1:"+testKey(1), "CALLBACK_SECRET_KEYS", ""); err != nil {
		t.Fatalf("empty other keyring should pass: %v", err)
	}
}
