package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/delivery"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/providers/google"
	"github.com/vtmattedi/mw-oauth-service/internal/refresh"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
	"github.com/vtmattedi/mw-oauth-service/internal/transactioncrypto"
)

// e2eGoogle is a stand-in for Google's token endpoint with the one property
// that matters here: a refresh token only works with the client that issued it.
type e2eGoogle struct {
	mu      sync.Mutex
	secrets map[string]string // client_id -> secret
	issued  map[string]string // refresh token -> client_id
	seen    []string          // "grant:client_id"
	counter int
}

func newE2EGoogle() *e2eGoogle {
	return &e2eGoogle{secrets: map[string]string{}, issued: map[string]string{}}
}

func (g *e2eGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))

	g.mu.Lock()
	defer g.mu.Unlock()

	clientID, secret, grant := form.Get("client_id"), form.Get("client_secret"), form.Get("grant_type")
	g.seen = append(g.seen, grant+":"+clientID)
	w.Header().Set("Content-Type", "application/json")

	if want, ok := g.secrets[clientID]; !ok || want != secret {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"The OAuth client was not found."}`)
		return
	}

	g.counter++
	switch grant {
	case "authorization_code":
		if form.Get("code") == "" || form.Get("code_verifier") == "" ||
			form.Get("redirect_uri") != "https://oauth.example.com/oauth/google/callback" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_request"}`)
			return
		}
		refreshToken := fmt.Sprintf("1//rt-%s-%d", strings.SplitN(clientID, ".", 2)[0], g.counter)
		g.issued[refreshToken] = clientID
		_, _ = fmt.Fprintf(w, `{"access_token":"ya29.exchange-%d","refresh_token":%q,"expires_in":3599,"token_type":"Bearer","scope":%q}`,
			g.counter, refreshToken, testScope)

	case "refresh_token":
		if g.issued[form.Get("refresh_token")] != clientID {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"access_token":"ya29.refreshed-%d","expires_in":3599,"token_type":"Bearer","scope":%q}`,
			g.counter, testScope)

	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"unsupported_grant_type"}`)
	}
}

func (g *e2eGoogle) calls() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.seen...)
}

// e2eConsumer is a project backend that receives and verifies signed callbacks.
type e2eConsumer struct {
	server   *httptest.Server
	secret   string
	mu       sync.Mutex
	payloads []map[string]any
	t        *testing.T
}

func newE2EConsumer(t *testing.T) *e2eConsumer {
	c := &e2eConsumer{t: t}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)

		mac := hmac.New(sha256.New, []byte(c.secret))
		mac.Write([]byte(r.Header.Get("X-MW-Webhook-Id") + "." + r.Header.Get("X-MW-Timestamp") + "."))
		mac.Write(raw)
		if r.Header.Get("X-MW-Signature") != "v1="+hex.EncodeToString(mac.Sum(nil)) {
			t.Errorf("consumer rejected the signature")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Errorf("payload: %v", err)
		}
		c.mu.Lock()
		c.payloads = append(c.payloads, payload)
		c.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *e2eConsumer) last() (credentialRef, refreshToken string, hasRef bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.payloads) == 0 {
		c.t.Fatal("consumer received no callback")
	}
	p := c.payloads[len(c.payloads)-1]
	ref, hasRef := p["credential_ref"].(string)
	token, _ := p["token"].(map[string]any)
	rt, _ := token["refresh_token"].(string)
	return ref, rt, hasRef
}

type e2eProject struct {
	id       int64
	consumer *e2eConsumer
	client   appauth.CreatedClient
}

type e2e struct {
	t        *testing.T
	store    *sqlite.Store
	handler  http.Handler
	google   *e2eGoogle
	creds    *googlecred.Service
	projects *project.Service
	appAuth  *appauth.Service
	audit    *audit.Service
	logs     *bytes.Buffer
}

const e2eCallbackPath = "/api/oauth/google/result"

func newE2E(t *testing.T, names ...string) (*e2e, []e2eProject) {
	t.Helper()
	logs := captureLogs(t)

	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fakeGoogle := newE2EGoogle()
	googleServer := httptest.NewServer(fakeGoogle)
	t.Cleanup(googleServer.Close)

	callbackKeys, err := secretbox.NewKeyring("1:"+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32)), 1)
	if err != nil {
		t.Fatal(err)
	}
	projects := project.NewService(store, callbackKeys)

	googleKeys, err := secretbox.NewGoogleCredentialKeyring("1:"+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)), 1)
	if err != nil {
		t.Fatal(err)
	}
	creds := googlecred.NewService(store, googleKeys)

	pkce, err := transactioncrypto.New(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)))
	if err != nil {
		t.Fatal(err)
	}

	const redirect = "https://oauth.example.com/oauth/google/callback"
	oauthService, err := oauth.NewService(store, projects, pkce, oauth.Options{
		GoogleRedirectURI: redirect, Credentials: creds,
	})
	if err != nil {
		t.Fatal(err)
	}

	provider, err := google.NewClient(google.Options{
		RedirectURI: redirect, TokenEndpoint: googleServer.URL, HTTPClient: googleServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	deliverer, err := delivery.NewSignedDeliverer(projects, delivery.Options{})
	if err != nil {
		t.Fatal(err)
	}
	callbackService, err := oauth.NewCallbackService(store, pkce, provider, deliverer, oauth.WithCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}

	appAuthService := appauth.NewService(store, 0)
	refreshService, err := refresh.NewService(refresh.Options{
		Credentials: creds, Projects: projects, Google: provider,
	})
	if err != nil {
		t.Fatal(err)
	}

	auditService := audit.NewService(store)
	handler := NewRouter(Dependencies{
		Build: buildinfo.Current(), Audit: auditService, OAuth: oauthService,
		OAuthCallback: callbackService, AppAuth: appAuthService, Refresh: refreshService,
	})

	env := &e2e{
		t: t, store: store, handler: handler, google: fakeGoogle, creds: creds,
		projects: projects, appAuth: appAuthService, audit: auditService, logs: logs,
	}

	var result []e2eProject
	for _, name := range names {
		created, err := projects.Create(context.Background(), name, true)
		if err != nil {
			t.Fatal(err)
		}

		consumer := newE2EConsumer(t)
		consumer.secret = created.CallbackSecret

		if err := store.ReplaceGoogleOAuthConfig(context.Background(), created.Project.ID, domain.GoogleOAuthConfig{
			Enabled:             true,
			AllowedScopes:       []string{testScope},
			AllowedCallbackURLs: []string{consumer.server.URL + e2eCallbackPath},
			AllowedReturnURLs:   []string{testReturnURL},
			Limits:              domain.OAuthLimits{PerMinute: 1000, PerHour: 10000, MaxPending: 1000},
		}); err != nil {
			t.Fatal(err)
		}

		client, err := appAuthService.CreateClient(context.Background(), created.Project.ID, name, nil)
		if err != nil {
			t.Fatal(err)
		}

		result = append(result, e2eProject{id: created.Project.ID, consumer: consumer, client: client})
	}
	return env, result
}

func (e *e2e) configureGoogle(p e2eProject, clientID, secret string) googlecred.ConfigureResult {
	e.t.Helper()
	e.google.mu.Lock()
	e.google.secrets[clientID] = secret
	e.google.mu.Unlock()

	res, err := e.creds.Configure(context.Background(), p.id, clientID, secret)
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func (e *e2e) tokenFor(p e2eProject, scopes ...string) string {
	e.t.Helper()
	tok, err := e.appAuth.IssueToken(context.Background(), p.client.Client.ClientID, p.client.ClientSecret, scopes)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok.AccessToken
}

// authorize starts an authorization as the project's backend and returns the
// OAuth state Google would send back.
func (e *e2e) authorize(p e2eProject) (state, authorizationURL string) {
	e.t.Helper()
	body := `{"scopes":["` + testScope + `"],"callback_url":"` + p.consumer.server.URL + e2eCallbackPath +
		`","return_url":"` + testReturnURL + `","client_reference":"ref-` + fmt.Sprint(len(e.google.calls())) + `-` + fmt.Sprint(p.id) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/google/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.tokenFor(p, appauth.ScopeGoogleAuthorize))
	res := httptest.NewRecorder()
	e.handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		e.t.Fatalf("authorize: %d %s", res.Code, res.Body.String())
	}

	var out struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		e.t.Fatal(err)
	}
	parsed, _ := url.Parse(out.AuthorizationURL)
	return parsed.Query().Get("state"), out.AuthorizationURL
}

// consent plays Google redirecting the user back to MW OAuth.
func (e *e2e) consent(state string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state="+url.QueryEscape(state)+"&code=provider-code", nil)
	res := httptest.NewRecorder()
	e.handler.ServeHTTP(res, req)
	return res
}

func (e *e2e) refresh(p e2eProject, ref, refreshToken string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"credential_ref": ref, "refresh_token": refreshToken})
	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/google/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.tokenFor(p, appauth.ScopeGoogleRefresh))
	res := httptest.NewRecorder()
	e.handler.ServeHTTP(res, req)
	return res
}

func clientOf(authorizationURL string) string {
	parsed, _ := url.Parse(authorizationURL)
	return parsed.Query().Get("client_id")
}

// ---- the scenarios ----

func TestEndToEndTwoProjectsWithDifferentGoogleClients(t *testing.T) {
	env, ps := newE2E(t, "project-one", "project-two")
	one, two := ps[0], ps[1]

	credOne := env.configureGoogle(one, "one.apps.googleusercontent.com", "GOCSPX-one-secret-value")
	credTwo := env.configureGoogle(two, "two.apps.googleusercontent.com", "GOCSPX-two-secret-value")

	for _, tc := range []struct {
		p      e2eProject
		client string
		cred   string
	}{
		{one, "one.apps.googleusercontent.com", credOne.Credential.ID},
		{two, "two.apps.googleusercontent.com", credTwo.Credential.ID},
	} {
		state, url := env.authorize(tc.p)
		if clientOf(url) != tc.client {
			t.Fatalf("authorize used client %q; want %q", clientOf(url), tc.client)
		}

		if res := env.consent(state); res.Code != http.StatusSeeOther {
			t.Fatalf("callback: %d %s", res.Code, res.Body.String())
		}

		// The project's backend received a signed callback with the exact
		// credential that issued the token.
		ref, refreshToken, hasRef := tc.p.consumer.last()
		if !hasRef || ref != tc.cred || !strings.Contains(refreshToken, strings.SplitN(tc.client, ".", 2)[0]) {
			t.Fatalf("callback ref=%q token=%q", ref, refreshToken)
		}

		res := env.refresh(tc.p, ref, refreshToken)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "ya29.refreshed-") {
			t.Fatalf("refresh: %d %s", res.Code, res.Body.String())
		}
	}

	// Each Google call was made with the right client, and only those.
	for _, call := range env.google.calls() {
		if !strings.HasSuffix(call, ":one.apps.googleusercontent.com") && !strings.HasSuffix(call, ":two.apps.googleusercontent.com") {
			t.Fatalf("unexpected Google call %q", call)
		}
	}
	if got := strings.Join(env.google.calls(), ","); got !=
		"authorization_code:one.apps.googleusercontent.com,refresh_token:one.apps.googleusercontent.com,"+
			"authorization_code:two.apps.googleusercontent.com,refresh_token:two.apps.googleusercontent.com" {
		t.Fatalf("Google calls = %s", got)
	}
}

func TestEndToEndProjectCannotRefreshWithAnotherProjectsCredential(t *testing.T) {
	env, ps := newE2E(t, "project-one", "project-two")
	one, two := ps[0], ps[1]
	env.configureGoogle(one, "one.apps.googleusercontent.com", "GOCSPX-one-secret-value")
	credTwo := env.configureGoogle(two, "two.apps.googleusercontent.com", "GOCSPX-two-secret-value")

	state, _ := env.authorize(one)
	env.consent(state)
	_, refreshToken, _ := one.consumer.last()

	before := len(env.google.calls())
	res := env.refresh(one, credTwo.Credential.ID, refreshToken)
	if res.Code != http.StatusNotFound || errorCode(t, res) != "credential_not_found" {
		t.Fatalf("%d %s", res.Code, res.Body.String())
	}
	if len(env.google.calls()) != before {
		t.Fatal("a foreign credential reached Google")
	}
}

func TestEndToEndRotationBetweenAuthorizeAndCallback(t *testing.T) {
	env, ps := newE2E(t, "project-one")
	p := ps[0]

	first := env.configureGoogle(p, "old.apps.googleusercontent.com", "GOCSPX-old-secret-value")
	state, url := env.authorize(p)
	if clientOf(url) != "old.apps.googleusercontent.com" {
		t.Fatalf("client = %q", clientOf(url))
	}

	// Operator rotates while the user is on Google's consent screen.
	second := env.configureGoogle(p, "new.apps.googleusercontent.com", "GOCSPX-new-secret-value")

	if res := env.consent(state); res.Code != http.StatusSeeOther {
		t.Fatalf("callback: %d", res.Code)
	}
	ref, refreshToken, _ := p.consumer.last()
	if ref != first.Credential.ID {
		t.Fatalf("credential_ref = %q; want the pinned %q", ref, first.Credential.ID)
	}
	if calls := env.google.calls(); calls[0] != "authorization_code:old.apps.googleusercontent.com" {
		t.Fatalf("the code must be exchanged with the old client: %v", calls)
	}

	// The issuing (now retiring) client keeps refreshing that token.
	if res := env.refresh(p, ref, refreshToken); res.Code != http.StatusOK {
		t.Fatalf("refresh with issuing client: %d %s", res.Code, res.Body.String())
	}

	// Using the new client's ref with the old token is NOT silently accepted:
	// Google rejects it because the token belongs to the old client.
	res := env.refresh(p, second.Credential.ID, refreshToken)
	if res.Code != http.StatusConflict || errorCode(t, res) != "reauthorization_required" {
		t.Fatalf("token with the wrong client: %d %s", res.Code, res.Body.String())
	}

	// New authorizations use the new client.
	_, url = env.authorize(p)
	if clientOf(url) != "new.apps.googleusercontent.com" {
		t.Fatalf("new authorization used %q", clientOf(url))
	}
}

func TestEndToEndDisabledCredentialStopsRefreshAndCallbacks(t *testing.T) {
	env, ps := newE2E(t, "project-one")
	p := ps[0]
	cred := env.configureGoogle(p, "one.apps.googleusercontent.com", "GOCSPX-one-secret-value")

	state, _ := env.authorize(p)
	env.consent(state)
	ref, refreshToken, _ := p.consumer.last()

	pendingState, _ := env.authorize(p)

	if _, err := env.creds.Disable(context.Background(), p.id, cred.Credential.ID); err != nil {
		t.Fatal(err)
	}

	before := len(env.google.calls())
	if res := env.refresh(p, ref, refreshToken); res.Code != http.StatusConflict || errorCode(t, res) != "credential_unavailable" {
		t.Fatalf("refresh: %d %s", res.Code, res.Body.String())
	}
	// The in-flight authorization fails clearly and nothing reaches Google or
	// the project.
	consumerCallbacks := len(p.consumer.payloads)
	env.consent(pendingState)
	if len(env.google.calls()) != before {
		t.Fatal("disabled credential reached Google")
	}
	if len(p.consumer.payloads) != consumerCallbacks {
		t.Fatal("a failed authorization must not be delivered to the project")
	}

	// And the project is not silently moved to a shared client.
	body := `{"scopes":["` + testScope + `"],"callback_url":"` + p.consumer.server.URL + e2eCallbackPath +
		`","return_url":"` + testReturnURL + `","client_reference":"after-disable"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/google/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+env.tokenFor(p, appauth.ScopeGoogleAuthorize))
	res := httptest.NewRecorder()
	env.handler.ServeHTTP(res, req)
	if res.Code != http.StatusConflict || errorCode(t, res) != "google_client_missing" {
		t.Fatalf("authorize after disable: %d %s", res.Code, res.Body.String())
	}
}

func TestEndToEndConcurrentRefreshes(t *testing.T) {
	env, ps := newE2E(t, "project-one")
	p := ps[0]
	env.configureGoogle(p, "one.apps.googleusercontent.com", "GOCSPX-one-secret-value")

	state, _ := env.authorize(p)
	env.consent(state)
	ref, refreshToken, _ := p.consumer.last()

	const workers = 30
	var wg sync.WaitGroup
	codes := make(chan int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- env.refresh(p, ref, refreshToken).Code
		}()
	}
	wg.Wait()
	close(codes)

	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("concurrent refresh returned %d", code)
		}
	}
	refreshes := 0
	for _, c := range env.google.calls() {
		if strings.HasPrefix(c, "refresh_token:") {
			refreshes++
		}
	}
	if refreshes != workers {
		t.Fatalf("Google refreshes = %d; want %d", refreshes, workers)
	}
}

func TestEndToEndNoUserTokensOrSecretsAreStoredOrLogged(t *testing.T) {
	env, ps := newE2E(t, "project-one")
	p := ps[0]
	env.configureGoogle(p, "one.apps.googleusercontent.com", "GOCSPX-one-secret-value")

	state, _ := env.authorize(p)
	env.consent(state)
	ref, refreshToken, _ := p.consumer.last()

	res := env.refresh(p, ref, refreshToken)
	var refreshed struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &refreshed)

	// A failure too, so error paths are covered.
	env.refresh(p, ref, "1//a-token-google-never-issued")

	exchangeToken := ""
	if payload := p.consumer.payloads[len(p.consumer.payloads)-1]; payload != nil {
		exchangeToken, _ = payload["token"].(map[string]any)["access_token"].(string)
	}

	forbidden := map[string]string{
		"Google refresh token":           refreshToken,
		"Google access token (exchange)": exchangeToken,
		"Google access token (refresh)":  refreshed.AccessToken,
		"unknown refresh token":          "1//a-token-google-never-issued",
		"Google client secret":           "GOCSPX-one-secret-value",
		"MW client secret":               p.client.ClientSecret,
		"MW access token":                "mw_at_",
	}
	for name, value := range forbidden {
		if value == "" {
			t.Fatalf("test setup: %s is empty", name)
		}
	}

	// Every column of every table.
	rows, err := env.store.DB().Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		tables = append(tables, name)
	}
	rows.Close()

	var dump strings.Builder
	for _, table := range tables {
		data, err := env.store.DB().Query(`SELECT * FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		columns, _ := data.Columns()
		for data.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := data.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			for _, v := range values {
				dump.WriteString(fmt.Sprint(v))
				dump.WriteByte(' ')
			}
		}
		data.Close()
	}

	for name, value := range forbidden {
		if strings.Contains(dump.String(), value) {
			t.Fatalf("the database contains the %s", name)
		}
		if strings.Contains(env.logs.String(), value) {
			t.Fatalf("the logs contain the %s", name)
		}
	}
}
