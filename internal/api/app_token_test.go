package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

type tokenFixture struct {
	handler http.Handler
	svc     *appauth.Service
	audit   *audit.Service
	store   *sqlite.Store
	project int64
	client  appauth.CreatedClient
}

func newTokenFixture(t *testing.T, limits TokenLimits) tokenFixture {
	t.Helper()

	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	p, err := store.CreateProject(context.Background(), project.CreateRecord{
		Name: "app", Enabled: true, TokenHash: "h", CallbackSecretCiphertext: "c",
		CallbackSecretNonce: "n", CallbackSecretKeyVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := appauth.NewService(store, 0)
	client, err := svc.CreateClient(context.Background(), p.ID, "worker", nil)
	if err != nil {
		t.Fatal(err)
	}

	auditService := audit.NewService(store)
	router := NewRouter(Dependencies{
		Build:       buildinfo.Current(),
		Audit:       auditService,
		AppAuth:     svc,
		TokenLimits: limits,
	})

	return tokenFixture{
		handler: router, svc: svc, audit: auditService, store: store,
		project: p.ID, client: client,
	}
}

func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func (f tokenFixture) post(t *testing.T, mutate func(*http.Request), body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", strings.NewReader(body))
	req.Header.Set("Authorization", basic(f.client.Client.ClientID, f.client.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.7:4000"
	if mutate != nil {
		mutate(req)
	}

	res := httptest.NewRecorder()
	f.handler.ServeHTTP(res, req)
	return res
}

func decodeTokenError(t *testing.T, res *httptest.ResponseRecorder) tokenError {
	t.Helper()
	var e tokenError
	if err := json.Unmarshal(res.Body.Bytes(), &e); err != nil {
		t.Fatalf("body %q: %v", res.Body.String(), err)
	}
	return e
}

func TestTokenEndpointIssuesScopedToken(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{})

	res := f.post(t, nil, "grant_type=client_credentials&scope=google.authorize+google.refresh")
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}

	var body tokenResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.AccessToken, "mw_at_") || body.TokenType != "Bearer" ||
		body.ExpiresIn != 900 || body.Scope != "google.authorize google.refresh" {
		t.Fatalf("unexpected response: %+v", body)
	}

	for header, want := range map[string]string{
		"Cache-Control": "no-store",
		"Pragma":        "no-cache",
		"Content-Type":  "application/json",
	} {
		if got := res.Header().Get(header); got != want {
			t.Fatalf("%s = %q; want %q", header, got, want)
		}
	}

	principal, err := f.svc.Authenticate(context.Background(), body.AccessToken)
	if err != nil || principal.ProjectID != f.project {
		t.Fatalf("issued token not usable: %+v, %v", principal, err)
	}
}

func TestTokenEndpointDefaultsAndNarrowsScope(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{})

	res := f.post(t, nil, "grant_type=client_credentials")
	var all tokenResponse
	_ = json.Unmarshal(res.Body.Bytes(), &all)
	if res.Code != http.StatusOK || all.Scope != "google.authorize google.refresh" {
		t.Fatalf("default scope: %d %s", res.Code, res.Body.String())
	}

	res = f.post(t, nil, "grant_type=client_credentials&scope=google.refresh")
	var one tokenResponse
	_ = json.Unmarshal(res.Body.Bytes(), &one)
	if res.Code != http.StatusOK || one.Scope != "google.refresh" {
		t.Fatalf("narrowed scope: %d %s", res.Code, res.Body.String())
	}

	res = f.post(t, nil, "grant_type=client_credentials&scope=google.refresh+admin")
	if res.Code != http.StatusBadRequest || decodeTokenError(t, res).Error != "invalid_scope" {
		t.Fatalf("unknown scope: %d %s", res.Code, res.Body.String())
	}
}

func TestTokenEndpointRejectsOverScopeForLimitedClient(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{})
	if _, err := f.svc.UpdateClient(context.Background(), f.project, nil, nil, []string{appauth.ScopeGoogleAuthorize}); err != nil {
		t.Fatal(err)
	}

	res := f.post(t, nil, "grant_type=client_credentials&scope=google.refresh")
	if res.Code != http.StatusBadRequest || decodeTokenError(t, res).Error != "invalid_scope" {
		t.Fatalf("over-scoped: %d %s", res.Code, res.Body.String())
	}
}

func TestTokenEndpointBadCredentialsAreUniform(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{})
	id, secret := f.client.Client.ClientID, f.client.ClientSecret
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	cases := map[string]func(*http.Request){
		"wrong secret":     func(r *http.Request) { r.Header.Set("Authorization", basic(id, secret+"x")) },
		"unknown client":   func(r *http.Request) { r.Header.Set("Authorization", basic("mwc_nope", secret)) },
		"no header":        func(r *http.Request) { r.Header.Del("Authorization") },
		"bearer scheme":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+secret) },
		"not base64":       func(r *http.Request) { r.Header.Set("Authorization", "Basic !!!notbase64") },
		"no colon":         func(r *http.Request) { r.Header.Set("Authorization", "Basic "+b64(id+secret)) },
		"extra colon":      func(r *http.Request) { r.Header.Set("Authorization", "Basic "+b64(id+":"+secret+":x")) },
		"empty client id":  func(r *http.Request) { r.Header.Set("Authorization", "Basic "+b64(":"+secret)) },
		"empty secret":     func(r *http.Request) { r.Header.Set("Authorization", "Basic "+b64(id+":")) },
		"payload with gap": func(r *http.Request) { r.Header.Set("Authorization", "Basic "+b64(id+":"+secret)+" extra") },
		"unpadded base64": func(r *http.Request) {
			r.Header.Set("Authorization", "Basic "+strings.TrimRight(b64(id+":"+secret+"1"), "="))
		},
		"two header values": func(r *http.Request) { r.Header.Add("Authorization", basic(id, secret)) },
		"bad url-encoding":  func(r *http.Request) { r.Header.Set("Authorization", "Basic "+b64(id+":%zz")) },
		"scheme only":       func(r *http.Request) { r.Header.Set("Authorization", "Basic") },
	}

	for name, mutate := range cases {
		res := f.post(t, mutate, "grant_type=client_credentials")
		e := decodeTokenError(t, res)
		if res.Code != http.StatusUnauthorized || e.Error != "invalid_client" {
			t.Fatalf("%s: status=%d body=%s", name, res.Code, res.Body.String())
		}
		if res.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s: missing WWW-Authenticate", name)
		}
		if strings.Contains(res.Body.String(), secret) {
			t.Fatalf("%s: body echoes the secret", name)
		}
		if res.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: error responses must not be cached", name)
		}
	}
}

func TestTokenEndpointRejectsCredentialsOutsideBasic(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{})
	id, secret := f.client.Client.ClientID, f.client.ClientSecret

	// In the URL.
	res := f.post(t, func(r *http.Request) {
		r.URL.RawQuery = "client_id=" + id + "&client_secret=" + url.QueryEscape(secret)
	}, "grant_type=client_credentials")
	if res.Code != http.StatusBadRequest || decodeTokenError(t, res).Error != "invalid_request" {
		t.Fatalf("query credentials: %d %s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), secret) {
		t.Fatal("response echoes the secret")
	}

	// Any query string at all.
	res = f.post(t, func(r *http.Request) { r.URL.RawQuery = "x=1" }, "grant_type=client_credentials")
	if res.Code != http.StatusBadRequest {
		t.Fatalf("query string: %d", res.Code)
	}

	// Duplicated in the body next to Basic: ambiguous.
	for _, extra := range []string{"&client_secret=" + secret, "&client_id=" + id} {
		res = f.post(t, nil, "grant_type=client_credentials"+extra)
		if res.Code != http.StatusBadRequest || decodeTokenError(t, res).Error != "invalid_request" {
			t.Fatalf("body credentials %q: %d %s", extra, res.Code, res.Body.String())
		}
	}
}

func TestTokenEndpointRequestShape(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{})

	bad := map[string]struct {
		mutate func(*http.Request)
		body   string
		status int
		code   string
	}{
		"json body": {func(r *http.Request) { r.Header.Set("Content-Type", "application/json") },
			`{"grant_type":"client_credentials"}`, 400, "invalid_request"},
		"no content type":    {func(r *http.Request) { r.Header.Del("Content-Type") }, "grant_type=client_credentials", 400, "invalid_request"},
		"missing grant":      {nil, "scope=google.refresh", 400, "invalid_request"},
		"empty body":         {nil, "", 400, "invalid_request"},
		"duplicate grant":    {nil, "grant_type=client_credentials&grant_type=client_credentials", 400, "invalid_request"},
		"duplicate scope":    {nil, "grant_type=client_credentials&scope=google.refresh&scope=google.authorize", 400, "invalid_request"},
		"other grant":        {nil, "grant_type=password&username=a&password=b", 400, "unsupported_grant_type"},
		"authorization_code": {nil, "grant_type=authorization_code&code=abc", 400, "unsupported_grant_type"},
		"malformed form":     {nil, "grant_type=%zz", 400, "invalid_request"},
		"oversized body":     {nil, "grant_type=client_credentials&pad=" + strings.Repeat("a", 9<<10), 400, "invalid_request"},
	}
	for name, tc := range bad {
		res := f.post(t, tc.mutate, tc.body)
		if res.Code != tc.status || decodeTokenError(t, res).Error != tc.code {
			t.Fatalf("%s: status=%d body=%s", name, res.Code, res.Body.String())
		}
	}

	// Other methods are not served.
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/v1/auth/token", nil)
		res := httptest.NewRecorder()
		f.handler.ServeHTTP(res, req)
		if res.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: status = %d", method, res.Code)
		}
	}
}

func TestTokenEndpointAcceptsContentTypeParameters(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{})
	res := f.post(t, func(r *http.Request) {
		r.Header.Set("Content-Type", "Application/X-WWW-Form-Urlencoded; charset=UTF-8")
	}, "grant_type=client_credentials")
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestTokenEndpointDisabledClientAndProject(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{})
	off := false
	if _, err := f.svc.UpdateClient(context.Background(), f.project, nil, &off, nil); err != nil {
		t.Fatal(err)
	}
	res := f.post(t, nil, "grant_type=client_credentials")
	if res.Code != http.StatusForbidden || decodeTokenError(t, res).Error != "unauthorized_client" {
		t.Fatalf("disabled client: %d %s", res.Code, res.Body.String())
	}

	// With a wrong secret the caller learns nothing about the disabled state.
	res = f.post(t, func(r *http.Request) {
		r.Header.Set("Authorization", basic(f.client.Client.ClientID, "wrong"))
	}, "grant_type=client_credentials")
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("disabled client + wrong secret: %d", res.Code)
	}

	on := true
	_, _ = f.svc.UpdateClient(context.Background(), f.project, nil, &on, nil)
	if _, err := f.store.DB().Exec(`UPDATE projects SET enabled = 0 WHERE id = ?`, f.project); err != nil {
		t.Fatal(err)
	}
	res = f.post(t, nil, "grant_type=client_credentials")
	if res.Code != http.StatusForbidden {
		t.Fatalf("disabled project: %d %s", res.Code, res.Body.String())
	}
}

func TestTokenEndpointRateLimitsPerClient(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{PerClient: appauth.NewLimiter(3, time.Minute, 100)})

	for i := 0; i < 3; i++ {
		if res := f.post(t, nil, "grant_type=client_credentials"); res.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, res.Code)
		}
	}

	res := f.post(t, nil, "grant_type=client_credentials")
	if res.Code != http.StatusTooManyRequests || decodeTokenError(t, res).Error != "rate_limited" {
		t.Fatalf("over limit: %d %s", res.Code, res.Body.String())
	}
	if res.Header().Get("Retry-After") == "" || res.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers = %v", res.Header())
	}

	// Another client is not affected.
	other, err := f.svc.CreateClient(context.Background(), f.projectOther(t), "other", nil)
	if err != nil {
		t.Fatal(err)
	}
	res = f.post(t, func(r *http.Request) {
		r.Header.Set("Authorization", basic(other.Client.ClientID, other.ClientSecret))
	}, "grant_type=client_credentials")
	if res.Code != http.StatusOK {
		t.Fatalf("other client throttled: %d", res.Code)
	}
}

func (f tokenFixture) projectOther(t *testing.T) int64 {
	t.Helper()
	p, err := f.store.CreateProject(context.Background(), project.CreateRecord{
		Name: "other", Enabled: true, TokenHash: "h2", CallbackSecretCiphertext: "c",
		CallbackSecretNonce: "n", CallbackSecretKeyVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.ID
}

func TestTokenEndpointFailureLockoutIsPerSource(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{Failures: appauth.NewLimiter(3, 5*time.Minute, 100)})

	wrong := func(r *http.Request) {
		r.Header.Set("Authorization", basic(f.client.Client.ClientID, "wrong-secret"))
	}
	for i := 0; i < 3; i++ {
		if res := f.post(t, wrong, "grant_type=client_credentials"); res.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, res.Code)
		}
	}

	// The attacker's address is now locked, even with the right secret.
	res := f.post(t, nil, "grant_type=client_credentials")
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("locked source: %d %s", res.Code, res.Body.String())
	}

	// The legitimate backend on another address still works.
	res = f.post(t, func(r *http.Request) { r.RemoteAddr = "198.51.100.20:5000" }, "grant_type=client_credentials")
	if res.Code != http.StatusOK {
		t.Fatalf("other source locked out: %d %s", res.Code, res.Body.String())
	}
}

func TestTokenEndpointSuccessClearsFailureCount(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{Failures: appauth.NewLimiter(3, 5*time.Minute, 100)})

	wrong := func(r *http.Request) {
		r.Header.Set("Authorization", basic(f.client.Client.ClientID, "wrong-secret"))
	}
	for i := 0; i < 2; i++ {
		f.post(t, wrong, "grant_type=client_credentials")
	}
	if res := f.post(t, nil, "grant_type=client_credentials"); res.Code != http.StatusOK {
		t.Fatalf("success below threshold: %d", res.Code)
	}
	// Counter was cleared, so two more failures do not lock out.
	for i := 0; i < 2; i++ {
		f.post(t, wrong, "grant_type=client_credentials")
	}
	if res := f.post(t, nil, "grant_type=client_credentials"); res.Code != http.StatusOK {
		t.Fatalf("counter not cleared: %d", res.Code)
	}
}

func TestTokenEndpointSourceLimit(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{PerSource: appauth.NewLimiter(2, time.Minute, 100)})

	for i := 0; i < 2; i++ {
		if res := f.post(t, nil, "grant_type=client_credentials"); res.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, res.Code)
		}
	}
	if res := f.post(t, nil, "grant_type=client_credentials"); res.Code != http.StatusTooManyRequests {
		t.Fatalf("over source limit: %d", res.Code)
	}
	if res := f.post(t, func(r *http.Request) { r.RemoteAddr = "198.51.100.9:1" }, "grant_type=client_credentials"); res.Code != http.StatusOK {
		t.Fatalf("other source: %d", res.Code)
	}
}

func TestTokenEndpointAuditsWithoutSecrets(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{})

	ok := f.post(t, nil, "grant_type=client_credentials")
	var issued tokenResponse
	_ = json.Unmarshal(ok.Body.Bytes(), &issued)

	f.post(t, func(r *http.Request) {
		r.Header.Set("Authorization", basic(f.client.Client.ClientID, "wrong-secret-value"))
	}, "grant_type=client_credentials")
	f.post(t, nil, "grant_type=password")

	page, err := f.audit.List(context.Background(), domain.AuditFilters{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}

	types := map[string]int{}
	var dump bytes.Buffer
	for _, e := range page.Items {
		types[e.EventType]++
		raw, _ := json.Marshal(e)
		dump.Write(raw)
	}
	if types["oauth.client.token_issued"] != 1 || types["oauth.client.token_rejected"] != 2 {
		t.Fatalf("audit types = %v", types)
	}

	for _, secret := range []string{f.client.ClientSecret, issued.AccessToken, "wrong-secret-value"} {
		if strings.Contains(dump.String(), secret) {
			t.Fatalf("audit data contains secret material %q", secret)
		}
	}
	if !strings.Contains(dump.String(), f.client.Client.ClientID) {
		t.Fatal("audit should record the (public) client ID")
	}
	if !strings.Contains(dump.String(), fmt.Sprintf(`"project_id":%d`, f.project)) {
		t.Fatal("issued event should carry the project ID")
	}
}

func TestV1AuthResponsesAreNotCachedByRouter(t *testing.T) {
	f := newTokenFixture(t, TokenLimits{})
	res := f.post(t, nil, "grant_type=client_credentials")
	if got := res.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("Cache-Control = %q", got)
	}
	if res.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers missing")
	}
}

func TestTokenEndpointNotRegisteredWithoutService(t *testing.T) {
	router := NewRouter(Dependencies{Build: buildinfo.Current()})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d", res.Code)
	}
}
