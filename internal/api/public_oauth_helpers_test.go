package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
	"github.com/vtmattedi/mw-oauth-service/internal/transactioncrypto"
)

func jsonDecode(raw []byte, target any) error { return json.Unmarshal(raw, target) }

// testGoogleCredentials gives a project a real, encrypted Google client and
// returns the service with the credential's reference.
func testGoogleCredentials(
	t *testing.T,
	store *sqlite.Store,
	projectID int64,
) (*googlecred.Service, string) {
	t.Helper()

	keys, err := secretbox.NewGoogleCredentialKeyring(
		"1:"+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x78}, 32)), 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	service := googlecred.NewService(store, keys)
	configured, err := service.Configure(
		context.Background(), projectID,
		"helper-client.apps.googleusercontent.com", "GOCSPX-helper-secret-value",
	)
	if err != nil {
		t.Fatal(err)
	}
	return service, configured.Credential.ID
}

// projectRecord builds a minimal project row for tests.
func projectRecord(name string) project.CreateRecord {
	return project.CreateRecord{
		Name: name, Enabled: true, CallbackSecretCiphertext: "c", CallbackSecretNonce: "n", CallbackSecretKeyVersion: 1,
	}
}

func mustCipher(t *testing.T) *transactioncrypto.Cipher {
	t.Helper()
	cipher, err := transactioncrypto.New(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

// googlecredWithoutKeys reads the fixture's database with no keyring.
func googlecredWithoutKeys(f authzFixture) *googlecred.Service {
	return googlecred.NewService(f.store, nil)
}

// serve sends one authorization request through handler.
func serve(t *testing.T, handler http.Handler, bearer string) *httptest.ResponseRecorder {
	t.Helper()

	body := `{"scopes":["` + testScope + `"],"callback_url":"` + testCallbackURL +
		`","return_url":"` + testReturnURL + `","client_reference":"ref-serve"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/google/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}
