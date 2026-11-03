package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/providers/google"
	"github.com/vtmattedi/mw-oauth-service/internal/refresh"
)

const (
	projectGoogleClientID     = "project-client.apps.googleusercontent.com"
	projectGoogleClientSecret = "GOCSPX-project-secret"
	storedRefreshToken        = "1//stored-google-refresh-token-value"
	newGoogleAccessToken      = "ya29.new-google-access-token-value"
)

// fakeRefresher scripts Google's refresh grant and records every call.
type fakeRefresher struct {
	mu     sync.Mutex
	calls  []fakeRefreshCall
	tokens oauth.TokenSet
	err    error
}

type fakeRefreshCall struct {
	Client oauth.GoogleClient
	Token  string
}

func (f *fakeRefresher) Refresh(
	ctx context.Context,
	client oauth.GoogleClient,
	refreshToken string,
) (oauth.TokenSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeRefreshCall{Client: client, Token: refreshToken})

	if f.err != nil {
		return oauth.TokenSet{}, f.err
	}
	if f.tokens.AccessToken == "" {
		return oauth.TokenSet{
			AccessToken: newGoogleAccessToken, TokenType: "Bearer", ExpiresIn: 3599,
			Scopes: []string{testScope},
		}, nil
	}
	return f.tokens, nil
}

func (f *fakeRefresher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f authzFixture) refreshRequest(
	t *testing.T,
	handler http.Handler,
	bearer string,
	body string,
	mutate func(*http.Request),
) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/google/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if mutate != nil {
		mutate(req)
	}

	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func (f authzFixture) refreshBody(ref, token string) string {
	raw, _ := json.Marshal(map[string]string{"credential_ref": ref, "refresh_token": token})
	return string(raw)
}

// refresh sends a valid refresh request with a fresh google.refresh token.
func (f authzFixture) refreshWith(t *testing.T, ref, token string) *httptest.ResponseRecorder {
	t.Helper()
	return f.refreshRequest(t, f.handler, f.token(t, appauth.ScopeGoogleRefresh), f.refreshBody(ref, token), nil)
}

func providerErr(kind google.ErrorKind, status int, code string, retry time.Duration) error {
	return &google.ProviderError{
		Operation: "token refresh", StatusCode: status, ProviderCode: code, Kind: kind, RetryAfter: retry,
	}
}

func (f authzFixture) handlerWithRefresh(t *testing.T, svc *refresh.Service) http.Handler {
	t.Helper()
	return NewRouter(Dependencies{
		Build: buildinfo.Current(), Audit: f.audit, AppAuth: f.appAuth, Refresh: svc,
	})
}

func (f authzFixture) newRefreshService(t *testing.T, limits refresh.Limits, clk func() time.Time) *refresh.Service {
	t.Helper()
	svc, err := refresh.NewService(refresh.Options{
		Credentials: f.creds,
		Projects:    f.projects,
		Google:      f.google,
		Limits:      limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	if clk != nil {
		svc.WithClock(clk)
	}
	return svc
}

// ---- success ----

func TestRefreshReturnsRenewedAccessTokenUsingProjectClient(t *testing.T) {
	f := newAuthzFixture(t, true)

	res := f.refreshWith(t, f.credRef, storedRefreshToken)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["access_token"] != newGoogleAccessToken || body["token_type"] != "Bearer" ||
		body["expires_in"].(float64) != 3599 {
		t.Fatalf("body = %v", body)
	}
	if _, present := body["refresh_token"]; present {
		t.Fatalf("no refresh_token may be returned unless Google replaced it: %v", body)
	}
	if scopes, _ := body["scope"].([]any); len(scopes) != 1 || scopes[0] != testScope {
		t.Fatalf("scope = %v", body["scope"])
	}
	if !strings.Contains(res.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("Cache-Control = %q", res.Header().Get("Cache-Control"))
	}

	// Google got the project's own client and the consumer's refresh token.
	if f.google.callCount() != 1 {
		t.Fatalf("Google calls = %d", f.google.callCount())
	}
	call := f.google.calls[0]
	if call.Client.ClientID != projectGoogleClientID || call.Client.ClientSecret != projectGoogleClientSecret ||
		call.Token != storedRefreshToken {
		t.Fatalf("Google call = %+v", call)
	}

	cred, _ := f.creds.Get(context.Background(), f.project, f.credRef)
	if cred.LastRefreshedAt == "" {
		t.Fatal("a successful refresh must be recorded on the credential")
	}
}

func TestRefreshReturnsReplacementRefreshTokenOnlyWhenGoogleSendsOne(t *testing.T) {
	f := newAuthzFixture(t, true)
	f.google.tokens = oauth.TokenSet{
		AccessToken: newGoogleAccessToken, RefreshToken: "1//rotated-refresh-token", TokenType: "Bearer", ExpiresIn: 3599,
	}

	res := f.refreshWith(t, f.credRef, storedRefreshToken)
	var body refreshResponse
	_ = json.Unmarshal(res.Body.Bytes(), &body)
	if res.Code != http.StatusOK || body.RefreshToken != "1//rotated-refresh-token" {
		t.Fatalf("replacement not returned: %d %s", res.Code, res.Body.String())
	}
	if body.Scope == nil {
		t.Fatal("scope must be an array, never null")
	}
}

func TestRetiringCredentialCanStillRefresh(t *testing.T) {
	f := newAuthzFixture(t, true)
	if _, err := f.creds.Configure(context.Background(), f.project, "second.apps.googleusercontent.com", "GOCSPX-second-secret"); err != nil {
		t.Fatal(err)
	}

	res := f.refreshWith(t, f.credRef, storedRefreshToken) // now retiring
	if res.Code != http.StatusOK {
		t.Fatalf("retiring credential: %d %s", res.Code, res.Body.String())
	}
	if f.google.calls[0].Client.ClientID != projectGoogleClientID {
		t.Fatalf("must refresh with the issuing client, used %q", f.google.calls[0].Client.ClientID)
	}
}

// ---- authentication ----

func TestRefreshRequiresAnAccessTokenWithRefreshScope(t *testing.T) {
	f := newAuthzFixture(t, true)
	body := f.refreshBody(f.credRef, storedRefreshToken)

	for name, bearer := range map[string]string{
		"no credentials":        "",
		"old-style project key": "mw_live_old-style-project-key",
		"garbage":               "garbage",
		"unknown token":         "mw_at_unknown",
		"client secret":         f.client.ClientSecret,
		"google access token":   "ya29.something",
	} {
		res := f.refreshRequest(t, f.handler, bearer, body, nil)
		if res.Code != http.StatusUnauthorized || errorCode(t, res) != "invalid_token" {
			t.Fatalf("%s: %d %s", name, res.Code, res.Body.String())
		}
		if !strings.Contains(res.Header().Get("WWW-Authenticate"), "invalid_token") {
			t.Fatalf("%s: WWW-Authenticate = %q", name, res.Header().Get("WWW-Authenticate"))
		}
	}

	res := f.refreshRequest(t, f.handler, f.token(t, appauth.ScopeGoogleAuthorize), body, nil)
	if res.Code != http.StatusForbidden || errorCode(t, res) != "insufficient_scope" {
		t.Fatalf("authorize-only token: %d %s", res.Code, res.Body.String())
	}

	if f.google.callCount() != 0 {
		t.Fatalf("unauthenticated requests reached Google %d times", f.google.callCount())
	}
}

func TestRefreshRejectsExpiredRevokedAndDisabled(t *testing.T) {
	f := newAuthzFixture(t, true)
	ctx := context.Background()
	body := f.refreshBody(f.credRef, storedRefreshToken)

	expiring := f.token(t, appauth.ScopeGoogleRefresh)
	f.clock.Advance(901 * time.Second)
	if res := f.refreshRequest(t, f.handler, expiring, body, nil); res.Code != http.StatusUnauthorized {
		t.Fatalf("expired: %d", res.Code)
	}

	revoked := f.token(t, appauth.ScopeGoogleRefresh)
	if _, err := f.appAuth.RevokeTokens(ctx, f.project, nil); err != nil {
		t.Fatal(err)
	}
	if res := f.refreshRequest(t, f.handler, revoked, body, nil); res.Code != http.StatusUnauthorized {
		t.Fatalf("revoked: %d", res.Code)
	}

	live := f.token(t, appauth.ScopeGoogleRefresh)
	off := false
	if _, err := f.appAuth.UpdateClient(ctx, f.project, nil, &off, nil); err != nil {
		t.Fatal(err)
	}
	if res := f.refreshRequest(t, f.handler, live, body, nil); res.Code != http.StatusForbidden || errorCode(t, res) != "client_disabled" {
		t.Fatalf("disabled client: %d %s", res.Code, res.Body.String())
	}
	on := true
	_, _ = f.appAuth.UpdateClient(ctx, f.project, nil, &on, nil)

	if _, err := f.store.DB().Exec(`UPDATE projects SET enabled = 0 WHERE id = ?`, f.project); err != nil {
		t.Fatal(err)
	}
	if res := f.refreshRequest(t, f.handler, live, body, nil); res.Code != http.StatusForbidden || errorCode(t, res) != "project_disabled" {
		t.Fatalf("disabled project: %d %s", res.Code, res.Body.String())
	}
	if f.google.callCount() != 0 {
		t.Fatal("rejected requests reached Google")
	}
}

func TestRefreshHonoursDisabledGoogleProvider(t *testing.T) {
	f := newAuthzFixture(t, true)
	if _, err := f.store.DB().Exec(
		`UPDATE project_oauth_configs SET enabled = 0 WHERE project_id = ? AND provider = 'google'`, f.project,
	); err != nil {
		t.Fatal(err)
	}

	res := f.refreshWith(t, f.credRef, storedRefreshToken)
	if res.Code != http.StatusForbidden || errorCode(t, res) != "provider_disabled" {
		t.Fatalf("%d %s", res.Code, res.Body.String())
	}
	if f.google.callCount() != 0 {
		t.Fatal("provider-disabled project reached Google")
	}
}

// ---- request shape ----

func TestRefreshValidatesRequestShape(t *testing.T) {
	f := newAuthzFixture(t, true)
	bearer := f.token(t, appauth.ScopeGoogleRefresh)

	bodies := map[string]string{
		"empty body":          ``,
		"not json":            `credential_ref=a&refresh_token=b`,
		"array":               `[]`,
		"missing ref":         `{"refresh_token":"1//x"}`,
		"missing token":       `{"credential_ref":"` + f.credRef + `"}`,
		"blank token":         `{"credential_ref":"` + f.credRef + `","refresh_token":""}`,
		"unknown field":       `{"credential_ref":"` + f.credRef + `","refresh_token":"1//x","client_id":"evil"}`,
		"client secret field": `{"credential_ref":"` + f.credRef + `","refresh_token":"1//x","client_secret":"evil"}`,
		"token endpoint":      `{"credential_ref":"` + f.credRef + `","refresh_token":"1//x","token_url":"https://evil.example"}`,
		"project id":          `{"credential_ref":"` + f.credRef + `","refresh_token":"1//x","project_id":99}`,
		"two objects":         `{"credential_ref":"` + f.credRef + `","refresh_token":"1//x"}{}`,
		"ref with slash":      `{"credential_ref":"../x","refresh_token":"1//x"}`,
		"ref with space":      `{"credential_ref":"gcred x","refresh_token":"1//x"}`,
		"ref too long":        `{"credential_ref":"` + strings.Repeat("a", 65) + `","refresh_token":"1//x"}`,
		"token with space":    `{"credential_ref":"` + f.credRef + `","refresh_token":"1// x"}`,
		"token with newline":  `{"credential_ref":"` + f.credRef + `","refresh_token":"1//\nx"}`,
		"token too long":      `{"credential_ref":"` + f.credRef + `","refresh_token":"` + strings.Repeat("a", 2049) + `"}`,
		"oversized body":      `{"credential_ref":"` + f.credRef + `","refresh_token":"` + strings.Repeat("a", 9<<10) + `"}`,
		"wrong types":         `{"credential_ref":123,"refresh_token":true}`,
	}
	for name, body := range bodies {
		res := f.refreshRequest(t, f.handler, bearer, body, nil)
		if res.Code != http.StatusBadRequest || errorCode(t, res) != "invalid_request" {
			t.Fatalf("%s: %d %s", name, res.Code, res.Body.String())
		}
	}

	res := f.refreshRequest(t, f.handler, bearer, f.refreshBody(f.credRef, "1//x"), func(r *http.Request) {
		r.Header.Set("Content-Type", "text/plain")
	})
	if res.Code != http.StatusBadRequest {
		t.Fatalf("wrong content type: %d", res.Code)
	}

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/v1/oauth/google/refresh", nil)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: %d", method, rec.Code)
		}
	}

	if f.google.callCount() != 0 {
		t.Fatalf("invalid requests reached Google %d times", f.google.callCount())
	}
}

func TestRefreshEndpointNotRegisteredWithoutService(t *testing.T) {
	f := newAuthzFixture(t, false)
	res := f.refreshRequest(t, f.handler, "x", f.refreshBody(f.credRef, "1//x"), nil)
	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d", res.Code)
	}
}

// ---- credential resolution ----

func TestRefreshCredentialRefIsScopedToTheCallersProject(t *testing.T) {
	f := newAuthzFixture(t, true)

	// A second project with its own Google client.
	other := f.projectOther2(t)
	otherCred, err := f.creds.Configure(context.Background(), other, "other.apps.googleusercontent.com", "GOCSPX-other-secret")
	if err != nil {
		t.Fatal(err)
	}

	unknown := f.refreshWith(t, "gcred_doesnotexist", storedRefreshToken)
	foreign := f.refreshWith(t, otherCred.Credential.ID, storedRefreshToken)

	for name, res := range map[string]*httptest.ResponseRecorder{"unknown": unknown, "other project": foreign} {
		if res.Code != http.StatusNotFound || errorCode(t, res) != "credential_not_found" {
			t.Fatalf("%s: %d %s", name, res.Code, res.Body.String())
		}
	}
	// Non-enumerating: the two responses are byte-identical.
	if unknown.Body.String() != foreign.Body.String() {
		t.Fatalf("responses differ:\n%s\n%s", unknown.Body.String(), foreign.Body.String())
	}
	if f.google.callCount() != 0 {
		t.Fatal("a foreign credential must never be used")
	}
}

func (f authzFixture) projectOther2(t *testing.T) int64 {
	t.Helper()
	other, err := f.store.CreateProject(context.Background(), projectRecord("other-refresh"))
	if err != nil {
		t.Fatal(err)
	}
	return other.ID
}

func TestRefreshWithDisabledOrDeletedCredentialIsUnavailable(t *testing.T) {
	f := newAuthzFixture(t, true)
	ctx := context.Background()

	if _, err := f.creds.Disable(ctx, f.project, f.credRef); err != nil {
		t.Fatal(err)
	}
	res := f.refreshWith(t, f.credRef, storedRefreshToken)
	if res.Code != http.StatusConflict || errorCode(t, res) != "credential_unavailable" {
		t.Fatalf("disabled: %d %s", res.Code, res.Body.String())
	}

	if _, err := f.creds.DeleteSecret(ctx, f.project, f.credRef); err != nil {
		t.Fatal(err)
	}
	res = f.refreshWith(t, f.credRef, storedRefreshToken)
	if res.Code != http.StatusConflict || errorCode(t, res) != "credential_unavailable" {
		t.Fatalf("deleted: %d %s", res.Code, res.Body.String())
	}
	if f.google.callCount() != 0 {
		t.Fatal("unavailable credential reached Google")
	}
}

func TestRefreshWithLostKeyIsUnavailable(t *testing.T) {
	f := newAuthzFixture(t, true)

	svc, err := refresh.NewService(refresh.Options{
		Credentials: googlecredWithoutKeys(f),
		Projects:    f.projects,
		Google:      f.google,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := f.refreshRequest(t, f.handlerWithRefresh(t, svc), f.token(t, appauth.ScopeGoogleRefresh),
		f.refreshBody(f.credRef, storedRefreshToken), nil)
	if res.Code != http.StatusConflict || errorCode(t, res) != "credential_unavailable" {
		t.Fatalf("%d %s", res.Code, res.Body.String())
	}
	if f.google.callCount() != 0 {
		t.Fatal("a broken credential must not reach Google")
	}
}

// There is no shared global client: "legacy" is not special, it is simply a
// credential_ref that does not exist.
func TestRefreshHasNoLegacyReference(t *testing.T) {
	f := newAuthzFixture(t, true)

	for _, ref := range []string{"legacy", "default", "global"} {
		res := f.refreshWith(t, ref, storedRefreshToken)
		if res.Code != http.StatusNotFound || errorCode(t, res) != "credential_not_found" {
			t.Fatalf("%s: %d %s", ref, res.Code, res.Body.String())
		}
	}
	if f.google.callCount() != 0 {
		t.Fatalf("Google calls = %d; unknown references must never reach Google", f.google.callCount())
	}
}

// ---- Google failures ----

func TestRefreshMapsGoogleFailures(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		status     int
		code       string
		retryAfter string
	}{
		{"invalid_grant", providerErr(google.KindInvalidGrant, 400, "invalid_grant", 0), 409, "reauthorization_required", ""},
		{"rate limited", providerErr(google.KindRateLimited, 429, "", 30*time.Second), 503, "provider_rate_limited", "30"},
		{"rate limited without hint", providerErr(google.KindRateLimited, 429, "", 0), 503, "provider_rate_limited", ""},
		{"outage", providerErr(google.KindUnavailable, 503, "", 0), 502, "provider_unavailable", ""},
		{"timeout", &google.ProviderError{Operation: "token refresh", Kind: google.KindUnavailable}, 502, "provider_unavailable", ""},
		{"client rejected", providerErr(google.KindRejected, 401, "invalid_client", 0), 409, "credential_unavailable", ""},
		{"unknown error type", context.DeadlineExceeded, 502, "provider_unavailable", ""},
	}

	for _, tc := range cases {
		f := newAuthzFixture(t, true)
		f.google.err = tc.err

		res := f.refreshWith(t, f.credRef, storedRefreshToken)
		if res.Code != tc.status || errorCode(t, res) != tc.code {
			t.Fatalf("%s: %d %s", tc.name, res.Code, res.Body.String())
		}
		if got := res.Header().Get("Retry-After"); got != tc.retryAfter {
			t.Fatalf("%s: Retry-After = %q; want %q", tc.name, got, tc.retryAfter)
		}
		for _, leak := range []string{storedRefreshToken, projectGoogleClientSecret, "invalid_grant\"", "description"} {
			if strings.Contains(res.Body.String(), leak) && leak != "invalid_grant\"" {
				t.Fatalf("%s: body leaks %q: %s", tc.name, leak, res.Body.String())
			}
		}

		// A failed refresh is not recorded as a success.
		cred, _ := f.creds.Get(context.Background(), f.project, f.credRef)
		if cred.LastRefreshedAt != "" {
			t.Fatalf("%s: failed refresh marked credential as refreshed", tc.name)
		}
	}
}

func TestInvalidGrantIsRememberedSoLoopsDoNotReachGoogle(t *testing.T) {
	f := newAuthzFixture(t, true)
	now := time.Now()
	svc := f.newRefreshService(t, refresh.Limits{}, func() time.Time { return now })
	handler := f.handlerWithRefresh(t, svc)
	f.google.err = providerErr(google.KindInvalidGrant, 400, "invalid_grant", 0)

	send := func(token string) *httptest.ResponseRecorder {
		return f.refreshRequest(t, handler, f.token(t, appauth.ScopeGoogleRefresh), f.refreshBody(f.credRef, token), nil)
	}

	if res := send(storedRefreshToken); res.Code != http.StatusConflict || errorCode(t, res) != "reauthorization_required" {
		t.Fatalf("first: %d %s", res.Code, res.Body.String())
	}
	for i := 0; i < 5; i++ {
		if res := send(storedRefreshToken); res.Code != http.StatusConflict || errorCode(t, res) != "reauthorization_required" {
			t.Fatalf("retry %d: %d %s", i, res.Code, res.Body.String())
		}
	}
	if f.google.callCount() != 1 {
		t.Fatalf("Google calls = %d; retries of a dead token must be answered locally", f.google.callCount())
	}

	// A different token (for example after the user re-authorized) is tried.
	f.google.err = nil
	if res := send("1//a-brand-new-refresh-token"); res.Code != http.StatusOK {
		t.Fatalf("new token: %d %s", res.Code, res.Body.String())
	}

	// The memory expires, so a token is not blocked forever.
	now = now.Add(6 * time.Minute)
	if res := send(storedRefreshToken); res.Code != http.StatusOK {
		t.Fatalf("after expiry: %d %s", res.Code, res.Body.String())
	}
}

// ---- rate limits ----

func TestRefreshRateLimitsAreSeparateFromAuthorize(t *testing.T) {
	f := newAuthzFixture(t, true)
	svc := f.newRefreshService(t, refresh.Limits{
		PerToken: refresh.NewScopedLimiter(2, time.Minute, 100),
	}, nil)
	handler := f.handlerWithRefresh(t, svc)
	send := func(token string) *httptest.ResponseRecorder {
		return f.refreshRequest(t, handler, f.token(t, appauth.ScopeGoogleRefresh), f.refreshBody(f.credRef, token), nil)
	}

	for i := 0; i < 2; i++ {
		if res := send(storedRefreshToken); res.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, res.Code)
		}
	}
	res := send(storedRefreshToken)
	if res.Code != http.StatusTooManyRequests || errorCode(t, res) != "rate_limited" {
		t.Fatalf("over token limit: %d %s", res.Code, res.Body.String())
	}
	if res.Header().Get("Retry-After") == "" {
		t.Fatal("rate limited responses need Retry-After")
	}
	if f.google.callCount() != 2 {
		t.Fatalf("Google calls = %d; limited requests must not reach Google", f.google.callCount())
	}

	// Another user's token is not affected, and authorize is untouched.
	if res := send("1//another-users-refresh-token"); res.Code != http.StatusOK {
		t.Fatalf("other token: %d", res.Code)
	}
	if res := f.authorize(t, f.token(t, appauth.ScopeGoogleAuthorize)); res.Code != http.StatusOK {
		t.Fatalf("authorize affected by refresh limits: %d", res.Code)
	}
}

func TestRefreshProjectAndCredentialLimits(t *testing.T) {
	f := newAuthzFixture(t, true)
	second, err := f.creds.Configure(context.Background(), f.project, "second.apps.googleusercontent.com", "GOCSPX-second-secret")
	if err != nil {
		t.Fatal(err)
	}

	svc := f.newRefreshService(t, refresh.Limits{
		PerProject:    appauth.NewLimiter(3, time.Minute, 100),
		PerCredential: refresh.NewScopedLimiter(2, time.Minute, 100),
	}, nil)
	handler := f.handlerWithRefresh(t, svc)
	send := func(ref, token string) *httptest.ResponseRecorder {
		return f.refreshRequest(t, handler, f.token(t, appauth.ScopeGoogleRefresh), f.refreshBody(ref, token), nil)
	}

	send(f.credRef, "1//a")
	send(f.credRef, "1//b")
	if res := send(f.credRef, "1//c"); res.Code != http.StatusTooManyRequests {
		t.Fatalf("credential limit: %d", res.Code)
	}

	// The refused request did not use up the project's allowance, and another
	// credential has its own bucket.
	if res := send(second.Credential.ID, "1//d"); res.Code != http.StatusOK {
		t.Fatalf("second credential within project limit: %d %s", res.Code, res.Body.String())
	}
	if res := send(second.Credential.ID, "1//e"); res.Code != http.StatusTooManyRequests {
		t.Fatalf("project limit: %d", res.Code)
	}
}

// A caller with a valid token must not be able to fill the limiters with
// junk keys and starve other projects.
func TestRefreshCannotFloodTheLimiters(t *testing.T) {
	f := newAuthzFixture(t, true)
	other := f.projectOther2(t)
	otherCred, err := f.creds.Configure(context.Background(), other, "other.apps.googleusercontent.com", "GOCSPX-other-secret")
	if err != nil {
		t.Fatal(err)
	}
	otherApp, err := f.appAuth.CreateClient(context.Background(), other, "other", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB().Exec(
		`INSERT INTO project_oauth_configs(project_id, provider, enabled) VALUES (?, 'google', 1)`, other,
	); err != nil {
		t.Fatal(err)
	}

	// Tiny key budgets make exhaustion easy to observe.
	svc := f.newRefreshService(t, refresh.Limits{
		PerProject:    appauth.NewLimiter(40, time.Minute, 100),
		PerCredential: refresh.NewScopedLimiter(5, time.Minute, 4),
		PerToken:      refresh.NewScopedLimiter(5, time.Minute, 4),
	}, nil)
	handler := f.handlerWithRefresh(t, svc)
	attacker := f.token(t, appauth.ScopeGoogleRefresh)

	// Random credential_refs are rejected before they can create any
	// per-credential or per-token limiter state.
	for i := 0; i < 60; i++ {
		res := f.refreshRequest(t, handler, attacker, f.refreshBody("gcred_junk"+strings.Repeat("x", i%20)+string(rune('a'+i%26)), "1//junk"), nil)
		if res.Code != http.StatusNotFound && res.Code != http.StatusTooManyRequests {
			t.Fatalf("junk ref %d: %d", i, res.Code)
		}
	}

	// Random refresh tokens on a real credential are capped by the project
	// limit, which is checked before any token bucket is created.
	for i := 0; i < 60; i++ {
		f.refreshRequest(t, handler, attacker, f.refreshBody(f.credRef, "1//random-"+strings.Repeat("y", i)), nil)
	}
	if res := f.refreshRequest(t, handler, attacker, f.refreshBody(f.credRef, "1//one-more"), nil); res.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker project should be limited: %d", res.Code)
	}

	// Another project's refreshes are unaffected.
	tok, err := f.appAuth.IssueToken(context.Background(), otherApp.Client.ClientID, otherApp.ClientSecret, []string{appauth.ScopeGoogleRefresh})
	if err != nil {
		t.Fatal(err)
	}
	res := f.refreshRequest(t, handler, tok.AccessToken, f.refreshBody(otherCred.Credential.ID, "1//legit"), nil)
	if res.Code != http.StatusOK {
		t.Fatalf("other project starved by the attacker: %d %s", res.Code, res.Body.String())
	}
}

// A credential Google rejects is not sent to Google again on every retry.
func TestRejectedGoogleClientIsRememberedBriefly(t *testing.T) {
	f := newAuthzFixture(t, true)
	now := time.Now()
	svc := f.newRefreshService(t, refresh.Limits{}, func() time.Time { return now })
	handler := f.handlerWithRefresh(t, svc)
	f.google.err = providerErr(google.KindRejected, 401, "invalid_client", 0)

	send := func(token string) *httptest.ResponseRecorder {
		return f.refreshRequest(t, handler, f.token(t, appauth.ScopeGoogleRefresh), f.refreshBody(f.credRef, token), nil)
	}

	for i := 0; i < 6; i++ {
		res := send("1//token-" + strings.Repeat("z", i)) // different tokens: not the invalid_grant cache
		if res.Code != http.StatusConflict || errorCode(t, res) != "credential_unavailable" {
			t.Fatalf("attempt %d: %d %s", i, res.Code, res.Body.String())
		}
	}
	if f.google.callCount() != 1 {
		t.Fatalf("Google calls = %d; the rejected client secret must not be resent on every retry", f.google.callCount())
	}

	// After the memory expires, and the operator has fixed the secret, it works.
	f.google.err = nil
	now = now.Add(2 * time.Minute)
	if res := send("1//after-fix"); res.Code != http.StatusOK {
		t.Fatalf("after expiry: %d %s", res.Code, res.Body.String())
	}
}

type recordRefreshFails struct {
	oauth.CredentialSource
}

func (recordRefreshFails) RecordRefreshed(context.Context, int64, string) error {
	return errors.New("update credential usage: database is locked")
}

// A failure to record usage never fails the refresh, but it is logged.
func TestRecordRefreshedFailureIsLoggedNotFatal(t *testing.T) {
	logs := captureLogs(t)
	f := newAuthzFixture(t, true)

	svc, err := refresh.NewService(refresh.Options{
		Credentials: recordRefreshFails{f.creds},
		Projects:    f.projects,
		Google:      f.google,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := f.refreshRequest(t, f.handlerWithRefresh(t, svc), f.token(t, appauth.ScopeGoogleRefresh),
		f.refreshBody(f.credRef, storedRefreshToken), nil)
	if res.Code != http.StatusOK {
		t.Fatalf("refresh must still succeed: %d %s", res.Code, res.Body.String())
	}
	if !strings.Contains(logs.String(), "could not record Google credential refresh") ||
		!strings.Contains(logs.String(), f.credRef) {
		t.Fatalf("expected a warning naming the credential; logs:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), storedRefreshToken) || strings.Contains(logs.String(), projectGoogleClientSecret) {
		t.Fatal("log leaks token or secret")
	}
}

// ---- audit and secrecy ----

func TestRefreshAuditAndLogsNeverContainTokensOrSecrets(t *testing.T) {
	logs := captureLogs(t)
	f := newAuthzFixture(t, true)

	f.google.tokens = oauth.TokenSet{
		AccessToken: newGoogleAccessToken, RefreshToken: "1//rotated-secret-value", TokenType: "Bearer", ExpiresIn: 3599,
	}
	f.refreshWith(t, f.credRef, storedRefreshToken)

	f.google.err = providerErr(google.KindInvalidGrant, 400, "invalid_grant", 0)
	f.refreshWith(t, f.credRef, "1//dead-refresh-token")
	f.refreshWith(t, "gcred_missing", storedRefreshToken)
	f.refreshRequest(t, f.handler, f.token(t, appauth.ScopeGoogleAuthorize), f.refreshBody(f.credRef, storedRefreshToken), nil)

	page, err := f.audit.List(context.Background(), domain.AuditFilters{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}

	types := map[string]int{}
	var dump strings.Builder
	for _, e := range page.Items {
		types[e.EventType]++
		raw, _ := json.Marshal(e)
		dump.Write(raw)
	}
	if types["oauth.google.refresh_succeeded"] != 1 || types["oauth.google.refresh_failed"] != 3 {
		t.Fatalf("audit events = %v", types)
	}

	secrets := []string{
		storedRefreshToken, "1//dead-refresh-token", "1//rotated-secret-value",
		newGoogleAccessToken, projectGoogleClientSecret, f.client.ClientSecret,
	}
	for _, secret := range secrets {
		if strings.Contains(dump.String(), secret) {
			t.Fatalf("audit data contains %q", secret)
		}
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("logs contain %q", secret)
		}
	}

	// What an operator needs is there: who, which credential, what outcome.
	for _, want := range []string{f.credRef, f.client.Client.ClientID, "invalid_grant", "credential_not_found", "insufficient_scope"} {
		if !strings.Contains(dump.String(), want) {
			t.Fatalf("audit data lacks %q", want)
		}
	}
	if !strings.Contains(dump.String(), "duration_ms") {
		t.Fatal("audit data should include the duration")
	}
}

// Compile-time check that the real service satisfies the credential source the
// refresh service needs.
var _ oauth.CredentialSource = (*googlecred.Service)(nil)
