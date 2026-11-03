package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
)

func TestAuthorizeUsesProjectGoogleClient(t *testing.T) {
	f := newAuthzFixture(t, true)

	res := f.authorize(t, f.token(t))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}

	var body struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if err := jsonDecode(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("client_id"); got != "project-client.apps.googleusercontent.com" {
		t.Fatalf("client_id = %q; want the project's client", got)
	}
	if strings.Contains(res.Body.String(), "GOCSPX-project-secret") {
		t.Fatal("response leaks the Google client secret")
	}

	var pinned string
	if err := f.store.DB().QueryRow(`SELECT google_credential_id FROM oauth_transactions`).Scan(&pinned); err != nil || pinned != f.credRef {
		t.Fatalf("pinned = %q, %v; want %q", pinned, err, f.credRef)
	}
}

func TestAuthorizeReportsMissingGoogleClient(t *testing.T) {
	f := newAuthzFixture(t, true)

	// The only credential is disabled: there is no fallback, only an explicit error.
	if _, err := f.creds.Disable(context.Background(), f.project, f.credRef); err != nil {
		t.Fatal(err)
	}

	res := f.authorize(t, f.token(t))
	if res.Code != http.StatusConflict || errorCode(t, res) != "google_client_missing" {
		t.Fatalf("%d %s", res.Code, res.Body.String())
	}
	f.lastEvent(t, "oauth.request.rejected.google_client_missing")
}

func TestAuthorizeReportsUnavailableGoogleClient(t *testing.T) {
	f := newAuthzFixture(t, true)

	// Same database, but the service now has no Google client keyring.
	service, err := oauth.NewService(f.store, f.projects, mustCipher(t), oauth.Options{
		GoogleRedirectURI: "https://oauth.example.com/oauth/google/callback",
		Credentials:       googlecredWithoutKeys(f),
	})
	if err != nil {
		t.Fatal(err)
	}

	handler := NewRouter(Dependencies{Audit: f.audit, OAuth: service, AppAuth: f.appAuth})
	res := serve(t, handler, f.token(t))
	if res.Code != http.StatusServiceUnavailable || errorCode(t, res) != "google_client_unavailable" {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "GOCSPX") {
		t.Fatal("error body leaks secret material")
	}
	f.lastEvent(t, "oauth.request.failed.google_client_unavailable")

	var transactions int
	_ = f.store.DB().QueryRow(`SELECT COUNT(*) FROM oauth_transactions`).Scan(&transactions)
	if transactions != 0 {
		t.Fatalf("created %d transactions", transactions)
	}
}
