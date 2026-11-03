package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
	"github.com/vtmattedi/mw-oauth-service/internal/transactioncrypto"
)

const (
	testCallbackURL = "https://app.example.com/api/oauth/google/result"
	testReturnURL   = "https://app.example.com/settings/integrations"
	testScope       = "https://www.googleapis.com/auth/calendar"
)

type authzClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *authzClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *authzClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type authzFixture struct {
	handler  http.Handler
	store    *sqlite.Store
	appAuth  *appauth.Service
	audit    *audit.Service
	clock    *authzClock
	project  int64
	legacy   string
	client   appauth.CreatedClient
	projects *project.Service
}

func newAuthzFixture(t *testing.T, wireAppAuth bool) authzFixture {
	t.Helper()

	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	legacyKey := "mw_live_legacy-test-key"
	p, err := store.CreateProject(context.Background(), project.CreateRecord{
		Name: "app", Enabled: true, TokenHash: project.HashAPIKey(legacyKey),
		CallbackSecretCiphertext: "c", CallbackSecretNonce: "n", CallbackSecretKeyVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.ReplaceGoogleOAuthConfig(context.Background(), p.ID, domain.GoogleOAuthConfig{
		Enabled:             true,
		AllowedScopes:       []string{testScope},
		AllowedCallbackURLs: []string{testCallbackURL},
		AllowedReturnURLs:   []string{testReturnURL},
		Limits:              domain.OAuthLimits{PerMinute: 100, PerHour: 1000, MaxPending: 100},
	}); err != nil {
		t.Fatal(err)
	}

	projects := project.NewService(store, nil)
	cipher, err := transactioncrypto.New(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	oauthService, err := oauth.NewService(store, projects, cipher, oauth.Options{
		GoogleClientID:    "client-id",
		GoogleRedirectURI: "https://oauth.example.com/oauth/google/callback",
	})
	if err != nil {
		t.Fatal(err)
	}

	clk := &authzClock{t: time.Now()}
	appAuthService := appauth.NewService(store, 0).WithClock(clk.Now)
	client, err := appAuthService.CreateClient(context.Background(), p.ID, "worker", nil)
	if err != nil {
		t.Fatal(err)
	}

	auditService := audit.NewService(store)
	deps := Dependencies{
		Build: buildinfo.Current(),
		Audit: auditService,
		OAuth: oauthService,
	}
	if wireAppAuth {
		deps.AppAuth = appAuthService
	}

	return authzFixture{
		handler: NewRouter(deps), store: store, appAuth: appAuthService,
		audit: auditService, clock: clk, project: p.ID, legacy: legacyKey,
		client: client, projects: projects,
	}
}

func (f authzFixture) token(t *testing.T, scopes ...string) string {
	t.Helper()
	tok, err := f.appAuth.IssueToken(context.Background(), f.client.Client.ClientID, f.client.ClientSecret, scopes)
	if err != nil {
		t.Fatal(err)
	}
	return tok.AccessToken
}

func (f authzFixture) authorize(t *testing.T, bearer string) *httptest.ResponseRecorder {
	t.Helper()

	body := `{"scopes":["` + testScope + `"],"callback_url":"` + testCallbackURL +
		`","return_url":"` + testReturnURL + `","client_reference":"ref-` +
		strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "") + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/google/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	res := httptest.NewRecorder()
	f.handler.ServeHTTP(res, req)
	return res
}

func errorCode(t *testing.T, res *httptest.ResponseRecorder) string {
	t.Helper()
	var body publicOAuthErrorResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", res.Body.String(), err)
	}
	return body.Error.Code
}

func (f authzFixture) lastEvent(t *testing.T, eventType string) domain.AuditEvent {
	t.Helper()
	page, err := f.audit.List(context.Background(), domain.AuditFilters{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range page.Items {
		if e.EventType == eventType {
			return e
		}
	}
	t.Fatalf("no %s audit event in %d events", eventType, len(page.Items))
	return domain.AuditEvent{}
}

func TestAuthorizeAcceptsScopedAppToken(t *testing.T) {
	f := newAuthzFixture(t, true)

	res := f.authorize(t, f.token(t, appauth.ScopeGoogleAuthorize))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil || result["authorization_url"] == "" {
		t.Fatalf("unexpected body: %s", res.Body.String())
	}

	// The transaction belongs to the token's project.
	var owner int64
	if err := f.store.DB().QueryRow(`SELECT project_id FROM oauth_transactions LIMIT 1`).Scan(&owner); err != nil || owner != f.project {
		t.Fatalf("transaction project = %d, %v", owner, err)
	}

	event := f.lastEvent(t, "oauth.request.accepted")
	if event.Metadata["auth_method"] != "app_token" || event.Metadata["mw_client_id"] != f.client.Client.ClientID {
		t.Fatalf("audit metadata = %v", event.Metadata)
	}
	raw, _ := json.Marshal(event)
	if strings.Contains(string(raw), "mw_at_") {
		t.Fatal("audit leaks the access token")
	}
}

func TestAuthorizeRequiresGoogleAuthorizeScope(t *testing.T) {
	f := newAuthzFixture(t, true)

	res := f.authorize(t, f.token(t, appauth.ScopeGoogleRefresh))
	if res.Code != http.StatusForbidden || errorCode(t, res) != "insufficient_scope" {
		t.Fatalf("refresh-only token: %d %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("WWW-Authenticate = %q", res.Header().Get("WWW-Authenticate"))
	}
	if event := f.lastEvent(t, "oauth.request.rejected.insufficient_scope"); event.ProjectID == nil || *event.ProjectID != f.project {
		t.Fatalf("event = %+v", event)
	}

	var transactions int
	_ = f.store.DB().QueryRow(`SELECT COUNT(*) FROM oauth_transactions`).Scan(&transactions)
	if transactions != 0 {
		t.Fatalf("rejected request created %d transactions", transactions)
	}
}

func TestAuthorizeRejectsInvalidExpiredAndRevokedTokens(t *testing.T) {
	f := newAuthzFixture(t, true)

	check := func(name, bearer string) {
		t.Helper()
		res := f.authorize(t, bearer)
		if res.Code != http.StatusUnauthorized || errorCode(t, res) != "invalid_token" {
			t.Fatalf("%s: %d %s", name, res.Code, res.Body.String())
		}
		if !strings.Contains(res.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("%s: WWW-Authenticate = %q", name, res.Header().Get("WWW-Authenticate"))
		}
	}

	check("unknown", "mw_at_unknown-token")
	check("client secret as token", "mw_at_"+f.client.ClientSecret)

	expiring := f.token(t)
	if res := f.authorize(t, expiring); res.Code != http.StatusOK {
		t.Fatalf("fresh token: %d %s", res.Code, res.Body.String())
	}
	f.clock.Advance(901 * time.Second)
	check("expired", expiring)

	revoked := f.token(t)
	if _, err := f.appAuth.RevokeTokens(context.Background(), f.project, nil); err != nil {
		t.Fatal(err)
	}
	check("revoked", revoked)
}

func TestAuthorizeRevalidatesClientProjectAndScopeEveryRequest(t *testing.T) {
	f := newAuthzFixture(t, true)
	ctx := context.Background()
	tok := f.token(t)

	if res := f.authorize(t, tok); res.Code != http.StatusOK {
		t.Fatalf("baseline: %d", res.Code)
	}

	// Narrowing the client's grant applies to the existing token.
	if _, err := f.appAuth.UpdateClient(ctx, f.project, nil, nil, []string{appauth.ScopeGoogleRefresh}); err != nil {
		t.Fatal(err)
	}
	if res := f.authorize(t, tok); res.Code != http.StatusForbidden || errorCode(t, res) != "insufficient_scope" {
		t.Fatalf("narrowed client: %d %s", res.Code, res.Body.String())
	}
	if _, err := f.appAuth.UpdateClient(ctx, f.project, nil, nil, []string{appauth.ScopeGoogleAuthorize, appauth.ScopeGoogleRefresh}); err != nil {
		t.Fatal(err)
	}

	off := false
	if _, err := f.appAuth.UpdateClient(ctx, f.project, nil, &off, nil); err != nil {
		t.Fatal(err)
	}
	if res := f.authorize(t, tok); res.Code != http.StatusForbidden || errorCode(t, res) != "client_disabled" {
		t.Fatalf("disabled client: %d %s", res.Code, res.Body.String())
	}
	on := true
	if _, err := f.appAuth.UpdateClient(ctx, f.project, nil, &on, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := f.store.DB().Exec(`UPDATE projects SET enabled = 0 WHERE id = ?`, f.project); err != nil {
		t.Fatal(err)
	}
	if res := f.authorize(t, tok); res.Code != http.StatusForbidden || errorCode(t, res) != "project_disabled" {
		t.Fatalf("disabled project: %d %s", res.Code, res.Body.String())
	}
}

func TestAuthorizeKeepsLegacyAPIKeyWorking(t *testing.T) {
	f := newAuthzFixture(t, true)

	res := f.authorize(t, f.legacy)
	if res.Code != http.StatusOK {
		t.Fatalf("legacy key: %d %s", res.Code, res.Body.String())
	}
	event := f.lastEvent(t, "oauth.request.accepted")
	if event.Metadata["auth_method"] != "legacy_api_key" {
		t.Fatalf("audit metadata = %v", event.Metadata)
	}

	// Wrong legacy keys still get the original error.
	res = f.authorize(t, "mw_live_wrong")
	if res.Code != http.StatusUnauthorized || errorCode(t, res) != "invalid_api_key" {
		t.Fatalf("wrong legacy key: %d %s", res.Code, res.Body.String())
	}
	if res = f.authorize(t, ""); res.Code != http.StatusUnauthorized || errorCode(t, res) != "invalid_api_key" {
		t.Fatalf("no credentials: %d %s", res.Code, res.Body.String())
	}
}

func TestLegacyAPIKeyCanBeDisabledPerProjectWithoutAffectingAppTokens(t *testing.T) {
	f := newAuthzFixture(t, true)
	ctx := context.Background()

	updated, err := f.projects.SetLegacyEnabled(ctx, f.project, false)
	if err != nil || updated.LegacyEnabled {
		t.Fatalf("disable legacy: %+v, %v", updated, err)
	}

	res := f.authorize(t, f.legacy)
	if res.Code != http.StatusForbidden || errorCode(t, res) != "legacy_auth_disabled" {
		t.Fatalf("legacy after disable: %d %s", res.Code, res.Body.String())
	}
	f.lastEvent(t, "oauth.request.rejected.legacy_disabled")

	if res := f.authorize(t, f.token(t)); res.Code != http.StatusOK {
		t.Fatalf("app token after legacy disable: %d %s", res.Code, res.Body.String())
	}

	if _, err := f.projects.SetLegacyEnabled(ctx, f.project, true); err != nil {
		t.Fatal(err)
	}
	if res := f.authorize(t, f.legacy); res.Code != http.StatusOK {
		t.Fatalf("legacy after re-enable: %d", res.Code)
	}

	if _, err := f.projects.SetLegacyEnabled(ctx, 9999, false); err == nil {
		t.Fatal("unknown project should fail")
	}
}

func TestAppTokensAreNotAcceptedWithoutAppAuthWiring(t *testing.T) {
	f := newAuthzFixture(t, false)
	tok := f.token(t)

	res := f.authorize(t, tok)
	if res.Code != http.StatusUnauthorized || errorCode(t, res) != "invalid_api_key" {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestLegacyAPIKeyIsNeverTreatedAsAppToken(t *testing.T) {
	f := newAuthzFixture(t, true)

	// A mw_live_ value must go through legacy lookup only, so it cannot be
	// confused with a token even if someone stores a token hash as an API key.
	res := f.authorize(t, "mw_live_"+strings.TrimPrefix(f.token(t), "mw_at_"))
	if res.Code != http.StatusUnauthorized || errorCode(t, res) != "invalid_api_key" {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestProjectIntegrationModeFollowsCredentialsAndLegacyFlag(t *testing.T) {
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	projects := project.NewService(store, nil)
	p, err := store.CreateProject(ctx, project.CreateRecord{
		Name: "p", Enabled: true, TokenHash: "h", CallbackSecretCiphertext: "c",
		CallbackSecretNonce: "n", CallbackSecretKeyVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	mode := func() string {
		t.Helper()
		got, err := projects.Get(ctx, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.IntegrationMode
	}

	// Existing and new projects start in legacy mode: nothing breaks on upgrade.
	if got := mode(); got != domain.IntegrationLegacy {
		t.Fatalf("initial mode = %q", got)
	}

	svc := appauth.NewService(store, 0)
	if _, err := svc.CreateClient(ctx, p.ID, "w", nil); err != nil {
		t.Fatal(err)
	}
	if got := mode(); got != domain.IntegrationMigrating {
		t.Fatalf("with client = %q", got)
	}

	if _, err := projects.SetLegacyEnabled(ctx, p.ID, false); err != nil {
		t.Fatal(err)
	}
	if got := mode(); got != domain.IntegrationAppCredentials {
		t.Fatalf("legacy off = %q", got)
	}

	if _, err := store.DB().Exec(`DELETE FROM mw_application_clients WHERE project_id = ?`, p.ID); err != nil {
		t.Fatal(err)
	}
	if got := mode(); got != domain.IntegrationUnconfigured {
		t.Fatalf("no client, legacy off = %q", got)
	}

	list, err := projects.List(ctx)
	if err != nil || len(list) != 1 || list[0].IntegrationMode != domain.IntegrationUnconfigured {
		t.Fatalf("list = %+v, %v", list, err)
	}
}
