package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

// The only credential the authorize endpoint accepts is a short-lived MW
// access token. Everything else, including the old project API keys, is an
// invalid token.
func TestPublicGoogleAuthorizeRejectsEverythingButAnAccessToken(t *testing.T) {
	f := newAuthzFixture(t, true)

	cases := map[string]string{
		"no credentials":      "",
		"old-style project":   "mw_live_old-style-project-key",
		"client secret":       f.client.ClientSecret,
		"google access token": "ya29.not-an-mw-token",
		"garbage":             "garbage",
	}

	for name, bearer := range cases {
		res := f.authorize(t, bearer)
		if res.Code != http.StatusUnauthorized || errorCode(t, res) != "invalid_token" {
			t.Fatalf("%s: status = %d body=%s", name, res.Code, res.Body.String())
		}
		if !strings.Contains(res.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("%s: WWW-Authenticate = %q", name, res.Header().Get("WWW-Authenticate"))
		}
	}

	// Each rejection is audited, without the credential.
	page, err := f.audit.List(t.Context(), domain.AuditFilters{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	rejected := 0
	for _, event := range page.Items {
		if event.EventType == "oauth.request.rejected.invalid_token" {
			rejected++
		}
	}
	if rejected != len(cases) {
		t.Fatalf("audited rejections = %d; want %d", rejected, len(cases))
	}

	var transactions int
	_ = f.store.DB().QueryRow(`SELECT COUNT(*) FROM oauth_transactions`).Scan(&transactions)
	if transactions != 0 {
		t.Fatalf("rejected requests created %d transactions", transactions)
	}
}

func TestProjectReportsWhetherItHasApplicationCredentials(t *testing.T) {
	f := newAuthzFixture(t, true)
	ctx := t.Context()

	withClient, err := f.projects.Get(ctx, f.project)
	if err != nil || !withClient.AppCredentialsConfigured {
		t.Fatalf("project with a client: %+v, %v", withClient, err)
	}

	bare, err := f.store.CreateProject(ctx, projectRecord("no-client"))
	if err != nil {
		t.Fatal(err)
	}
	if bare.AppCredentialsConfigured {
		t.Fatal("a new project has no application credentials yet")
	}

	list, err := f.projects.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string]bool{}
	for _, p := range list {
		flags[p.Name] = p.AppCredentialsConfigured
	}
	if !flags["app"] || flags["no-client"] {
		t.Fatalf("list flags = %v", flags)
	}
}

func TestAuthorizeEndpointIsNotRegisteredWithoutAppAuth(t *testing.T) {
	f := newAuthzFixture(t, false)

	res := f.authorize(t, "mw_at_anything")
	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d", res.Code)
	}
}
