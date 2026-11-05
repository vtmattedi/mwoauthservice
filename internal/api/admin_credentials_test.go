package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/federation"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

type credAdminFixture struct {
	scopes    *[]string
	handler   http.Handler
	audit     *audit.Service
	projects  *project.Service
	projectID int64
	store     *sqlite.Store
}

func newCredAdminFixture(t *testing.T) credAdminFixture {
	t.Helper()

	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	keys, err := secretbox.NewGoogleCredentialKeyring(
		"1:"+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32)), 1,
	)
	if err != nil {
		t.Fatal(err)
	}

	projects := project.NewService(store, nil)
	created, err := store.CreateProject(context.Background(), projectRecord("demo"))
	if err != nil {
		t.Fatal(err)
	}

	scopes := []string{}
	// The stub reads the slice at call time, so tests change the granted
	// scopes between requests.
	authenticator, err := federation.NewAuthenticator(
		federation.ModeFederated, "mw-oauth", scopedStub{scopes: &scopes},
	)
	if err != nil {
		t.Fatal(err)
	}

	auditService := audit.NewService(store)
	handler := NewRouter(Dependencies{
		Build:             buildinfo.Current(),
		Admin:             admin.NewService(store, admin.Options{}),
		Projects:          projects,
		Audit:             auditService,
		AppAuth:           appauth.NewService(store, 0),
		GoogleCredentials: googlecred.NewService(store, keys),
		Federation:        authenticator,
	})

	return credAdminFixture{
		scopes: &scopes, handler: handler, audit: auditService,
		projects: projects, projectID: created.ID, store: store,
	}
}

type scopedStub struct{ scopes *[]string }

func (s scopedStub) Introspect(context.Context, string) (federation.Token, error) {
	return federation.Token{
		Active: true, Subject: "usr_admin", Audience: []string{"mw-oauth"},
		Scopes: append([]string(nil), *s.scopes...), AMR: []string{"webauthn"},
	}, nil
}

func (f credAdminFixture) call(
	t *testing.T, method string, path string, body string, scopes ...string,
) *httptest.ResponseRecorder {
	t.Helper()
	*f.scopes = scopes

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "/admin/api/projects/"+path, reader)
	req.Header.Set("Authorization", "Bearer opaque")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res := httptest.NewRecorder()
	f.handler.ServeHTTP(res, req)
	return res
}

func (f credAdminFixture) pid(suffix string) string {
	return itoa(f.projectID) + suffix
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func decode[T any](t *testing.T, res *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %q: %v", res.Body.String(), err)
	}
	return out
}

func codeOf(t *testing.T, res *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[adminCodedError](t, res).Code
}

func TestMWClientLifecycleThroughAdminAPI(t *testing.T) {
	f := newCredAdminFixture(t)
	read, rotate := federation.ScopeCredentialsRead, federation.ScopeCredentialsRotate

	if res := f.call(t, "GET", f.pid("/client"), "", read); res.Code != 404 ||
		codeOf(t, res) != "client_not_found" {
		t.Fatalf("no client yet: %d %s", res.Code, res.Body)
	}

	// First call creates the client and returns its first secret once.
	res := f.call(t, "POST", f.pid("/client/credentials"), "", rotate)
	if res.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", res.Code, res.Body)
	}
	created := decode[adminClientSecretResponse](t, res)
	if !strings.HasPrefix(created.ClientSecret, appauth.SecretPrefix) ||
		!strings.HasPrefix(created.Client.ClientID, appauth.ClientIDPrefix) {
		t.Fatalf("created = %+v", created)
	}
	if created.Client.DisplayName != "demo" {
		t.Fatalf("display name defaults to the project name, got %q", created.Client.DisplayName)
	}

	// Reads never contain the secret or its hash.
	res = f.call(t, "GET", f.pid("/client"), "", read)
	if res.Code != 200 || strings.Contains(res.Body.String(), created.ClientSecret) ||
		strings.Contains(res.Body.String(), "hash") {
		t.Fatalf("read: %d %s", res.Code, res.Body)
	}

	// Second call is a rotation: an overlapping secret; a third is refused.
	res = f.call(t, "POST", f.pid("/client/credentials"), "", rotate)
	if res.Code != http.StatusCreated {
		t.Fatalf("rotate: %d %s", res.Code, res.Body)
	}
	rotated := decode[adminClientSecretResponse](t, res)
	if rotated.ClientSecret == created.ClientSecret || rotated.Secret == nil {
		t.Fatalf("rotated = %+v", rotated)
	}
	if len(rotated.Client.Secrets) != 2 {
		t.Fatalf("secrets = %+v", rotated.Client.Secrets)
	}
	if res := f.call(t, "POST", f.pid("/client/credentials"), "", rotate); res.Code != 409 ||
		codeOf(t, res) != "too_many_active_secrets" {
		t.Fatalf("third secret: %d %s", res.Code, res.Body)
	}

	// Revoke the first secret, then its tokens are gone too.
	revoke := f.call(t, "DELETE", f.pid("/client/credentials/"+itoa(rotated.Client.Secrets[0].ID)), "", rotate)
	if revoke.Code != 200 {
		t.Fatalf("revoke: %d %s", revoke.Code, revoke.Body)
	}
	if res := f.call(t, "DELETE", f.pid("/client/credentials/abc"), "", rotate); res.Code != 400 {
		t.Fatalf("bad id: %d", res.Code)
	}
	if res := f.call(t, "DELETE", f.pid("/client/credentials/9999"), "", rotate); res.Code != 404 {
		t.Fatalf("unknown secret: %d %s", res.Code, res.Body)
	}

	res = f.call(t, "POST", f.pid("/client/tokens/revoke"), "", rotate)
	if res.Code != 200 || decode[map[string]int64](t, res)["revoked"] != 0 {
		t.Fatalf("revoke tokens: %d %s", res.Code, res.Body)
	}

	// Audit trail has no secret.
	page, err := f.audit.List(context.Background(), domain.AuditFilters{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, event := range page.Items {
		seen[event.EventType] = true
		raw, _ := json.Marshal(event)
		if strings.Contains(string(raw), created.ClientSecret) ||
			strings.Contains(string(raw), rotated.ClientSecret) {
			t.Fatalf("secret in audit: %s", raw)
		}
	}
	for _, want := range []string{
		"oauth.client.created", "oauth.client.credential_rotated",
		"oauth.client.revoked", "oauth.client.tokens_revoked",
	} {
		if !seen[want] {
			t.Errorf("missing audit event %s (have %v)", want, seen)
		}
	}
}

func TestGoogleClientLifecycleThroughAdminAPI(t *testing.T) {
	f := newCredAdminFixture(t)
	read := federation.ScopeProviderCredentialsRead
	manage := federation.ScopeProviderCredentialsManage
	const secret = "GOCSPX-super-secret-value"

	res := f.call(t, "GET", f.pid("/oauth/google/client"), "", read)
	if res.Code != 200 || !strings.Contains(res.Body.String(), `"credentials":[]`) {
		t.Fatalf("empty list: %d %s", res.Code, res.Body)
	}

	put := func(clientID string) *httptest.ResponseRecorder {
		return f.call(t, "PUT", f.pid("/oauth/google/client"),
			`{"client_id":"`+clientID+`","client_secret":"`+secret+`"}`, manage)
	}

	res = put("first.apps.googleusercontent.com")
	if res.Code != 200 || strings.Contains(res.Body.String(), secret) {
		t.Fatalf("put: %d %s", res.Code, res.Body)
	}
	first := decode[googlecred.ConfigureResult](t, res)
	if first.Credential.State != domain.GoogleCredentialActive || first.Retired != nil {
		t.Fatalf("first = %+v", first)
	}

	// Replacing retires the previous credential.
	res = put("second.apps.googleusercontent.com")
	second := decode[googlecred.ConfigureResult](t, res)
	if second.Retired == nil || second.Retired.ID != first.Credential.ID {
		t.Fatalf("second = %+v", second)
	}

	res = f.call(t, "GET", f.pid("/oauth/google/client"), "", read)
	list := decode[adminGoogleClientListResponse](t, res)
	if len(list.Credentials) != 2 || list.ActiveRef != second.Credential.ID ||
		strings.Contains(res.Body.String(), secret) {
		t.Fatalf("list = %s", res.Body)
	}

	// Disable needs confirmation; the first answer shows the impact.
	disablePath := f.pid("/oauth/google/client/" + first.Credential.ID + "/disable")
	res = f.call(t, "POST", disablePath, "", manage)
	if res.Code != 409 || codeOf(t, res) != "confirmation_required" ||
		!strings.Contains(res.Body.String(), `"impact"`) {
		t.Fatalf("unconfirmed: %d %s", res.Code, res.Body)
	}
	res = f.call(t, "GET", f.pid("/oauth/google/client/"+first.Credential.ID+"/impact"), "", read)
	if res.Code != 200 {
		t.Fatalf("impact: %d %s", res.Code, res.Body)
	}

	res = f.call(t, "POST", disablePath, `{"confirm":true}`, manage)
	if res.Code != 200 || decode[domain.GoogleCredential](t, res).State != domain.GoogleCredentialDisabled {
		t.Fatalf("disable: %d %s", res.Code, res.Body)
	}
	// Disabled is final.
	if res := f.call(t, "POST", disablePath, `{"confirm":true}`, manage); res.Code != 409 ||
		codeOf(t, res) != "configuration_conflict" {
		t.Fatalf("second disable: %d %s", res.Code, res.Body)
	}
	retirePath := f.pid("/oauth/google/client/" + second.Credential.ID + "/retire")
	if res := f.call(t, "POST", retirePath, `{"confirm":true}`, manage); res.Code != 200 {
		t.Fatalf("retire: %d %s", res.Code, res.Body)
	}

	// Unknown reference, bad input and validation errors never echo the secret.
	if res := f.call(t, "POST", f.pid("/oauth/google/client/gcred_nope/disable"),
		`{"confirm":true}`, manage); res.Code != 404 || codeOf(t, res) != "credential_not_found" {
		t.Fatalf("unknown ref: %d %s", res.Code, res.Body)
	}
	res = put("not-a-google-client-id")
	if res.Code != 400 || strings.Contains(res.Body.String(), secret) {
		t.Fatalf("invalid: %d %s", res.Code, res.Body)
	}
	if res := f.call(t, "PUT", f.pid("/oauth/google/client"),
		`{"client_id":"x.apps.googleusercontent.com","client_secret":"`+secret+`","extra":1}`,
		manage); res.Code != 400 || strings.Contains(res.Body.String(), secret) {
		t.Fatalf("unknown field: %d %s", res.Code, res.Body)
	}

	page, _ := f.audit.List(context.Background(), domain.AuditFilters{Limit: 100})
	for _, event := range page.Items {
		if raw, _ := json.Marshal(event); strings.Contains(string(raw), secret) {
			t.Fatalf("secret in audit: %s", raw)
		}
	}
}

// Policy editors must not be able to manage Google secrets or MW client
// credentials, and vice versa.
func TestCredentialRoutesRequireTheirOwnScopes(t *testing.T) {
	f := newCredAdminFixture(t)

	type route struct{ method, path, body string }
	routes := map[string][]route{
		federation.ScopeCredentialsRead: {{"GET", "/client", ""}},
		federation.ScopeCredentialsRotate: {
			{"POST", "/client/credentials", ""},
			{"DELETE", "/client/credentials/1", ""},
			{"POST", "/client/tokens/revoke", ""},
		},
		federation.ScopeProviderCredentialsRead: {
			{"GET", "/oauth/google/client", ""},
			{"GET", "/oauth/google/client/gcred_x/impact", ""},
		},
		federation.ScopeProviderCredentialsManage: {
			{"PUT", "/oauth/google/client", `{"client_id":"a.apps.googleusercontent.com","client_secret":"GOCSPX-secret-1"}`},
			{"POST", "/oauth/google/client/gcred_x/retire", `{"confirm":true}`},
			{"POST", "/oauth/google/client/gcred_x/disable", `{"confirm":true}`},
		},
	}

	every := []string{
		federation.ScopeCredentialsRead, federation.ScopeCredentialsRotate,
		federation.ScopeProviderCredentialsRead, federation.ScopeProviderCredentialsManage,
		federation.ScopePolicyRead, federation.ScopePolicyWrite,
		federation.ScopeProjectsRead, federation.ScopeProjectsWrite,
	}

	for need, list := range routes {
		for _, rt := range list {
			var others []string
			for _, s := range every {
				if s != need {
					others = append(others, s)
				}
			}
			res := f.call(t, rt.method, f.pid(rt.path), rt.body, others...)
			if res.Code != http.StatusForbidden {
				t.Errorf("%s %s without %s: status %d", rt.method, rt.path, need, res.Code)
			}
		}
	}

	// The summary needs only projects.read.
	if res := f.call(t, "GET", "summary", "", federation.ScopePolicyWrite); res.Code != http.StatusForbidden {
		t.Errorf("summary without projects.read: %d", res.Code)
	}
}

func TestUnknownProjectIsNotFoundOnCredentialRoutes(t *testing.T) {
	f := newCredAdminFixture(t)

	res := f.call(t, "GET", "9999/client", "", federation.ScopeCredentialsRead)
	if res.Code != http.StatusNotFound {
		t.Fatalf("status %d %s", res.Code, res.Body)
	}
	res = f.call(t, "GET", "9999/oauth/google/client", "", federation.ScopeProviderCredentialsRead)
	if res.Code != http.StatusNotFound {
		t.Fatalf("status %d %s", res.Code, res.Body)
	}
	res = f.call(t, "POST", "0/client/credentials", "", federation.ScopeCredentialsRotate)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", res.Code, res.Body)
	}
}

func TestCredentialsOfOneProjectAreInvisibleFromAnother(t *testing.T) {
	f := newCredAdminFixture(t)
	other, err := f.store.CreateProject(context.Background(), projectRecord("other"))
	if err != nil {
		t.Fatal(err)
	}
	manage := federation.ScopeProviderCredentialsManage

	res := f.call(t, "PUT", f.pid("/oauth/google/client"),
		`{"client_id":"a.apps.googleusercontent.com","client_secret":"GOCSPX-secret-1"}`, manage)
	ref := decode[googlecred.ConfigureResult](t, res).Credential.ID

	res = f.call(t, "POST", itoa(other.ID)+"/oauth/google/client/"+ref+"/disable",
		`{"confirm":true}`, manage)
	if res.Code != http.StatusNotFound {
		t.Fatalf("cross-project disable: %d %s", res.Code, res.Body)
	}
}

func TestProjectSummaryReportsSetupStateInOneCall(t *testing.T) {
	f := newCredAdminFixture(t)
	manage := federation.ScopeProviderCredentialsManage

	f.call(t, "POST", f.pid("/client/credentials"), "", federation.ScopeCredentialsRotate)
	f.call(t, "PUT", f.pid("/oauth/google/client"),
		`{"client_id":"a.apps.googleusercontent.com","client_secret":"GOCSPX-secret-1"}`, manage)
	if _, err := f.store.CreateProject(context.Background(), projectRecord("bare")); err != nil {
		t.Fatal(err)
	}

	res := f.call(t, "GET", "summary", "", federation.ScopeProjectsRead)
	if res.Code != 200 {
		t.Fatalf("summary: %d %s", res.Code, res.Body)
	}
	byName := map[string]adminProjectSummary{}
	for _, p := range decode[adminProjectSummaryResponse](t, res).Projects {
		byName[p.Name] = p
	}
	if p := byName["demo"]; !p.AppCredentialsConfigured || p.GoogleClient != "active" || p.StatusError {
		t.Fatalf("demo = %+v", p)
	}
	if p := byName["bare"]; p.AppCredentialsConfigured || p.GoogleClient != "none" || p.StatusError {
		t.Fatalf("bare = %+v", p)
	}
}
