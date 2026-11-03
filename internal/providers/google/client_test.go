package google

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testRedirectURI = "https://oauth.example.com/oauth/google/callback"

var credsA = Credentials{ClientID: "client-a", ClientSecret: "secret-a"}

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := NewClient(Options{
		RedirectURI:   testRedirectURI,
		TokenEndpoint: server.URL,
		HTTPClient:    server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func respond(status int, body string, headers map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
}

func readForm(t *testing.T, r *http.Request) url.Values {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Fatalf("method = %s; want POST", r.Method)
	}
	if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q", got)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	return form
}

func expectForm(t *testing.T, form url.Values, want map[string]string) {
	t.Helper()
	for key, value := range want {
		if got := form.Get(key); got != value {
			t.Fatalf("%s = %q; want %q", key, got, value)
		}
	}
}

func TestExchangeCodeUsesGivenCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectForm(t, readForm(t, r), map[string]string{
			"client_id":     "client-a",
			"client_secret": "secret-a",
			"code":          "provider-code",
			"code_verifier": "pkce-verifier",
			"grant_type":    "authorization_code",
			"redirect_uri":  testRedirectURI,
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"access","refresh_token":"refresh","expires_in":3599,"token_type":"Bearer","scope":"scope-a scope-b"}`)
	}))
	defer server.Close()

	tokens, err := newTestClient(t, server).ExchangeCode(context.Background(), credsA, "provider-code", "pkce-verifier")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "access" || tokens.RefreshToken != "refresh" ||
		tokens.ExpiresIn != 3599 || len(tokens.Scopes) != 2 {
		t.Fatalf("tokens = %+v", tokens)
	}
}

func TestOneClientServesDifferentCredentialsPerCall(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		form := readForm(t, r)
		seen = append(seen, form.Get("client_id")+"/"+form.Get("client_secret"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"a","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer server.Close()
	client := newTestClient(t, server)

	for _, c := range []Credentials{
		{ClientID: "one", ClientSecret: "s1"},
		{ClientID: "two", ClientSecret: "s2"},
		{ClientID: "one", ClientSecret: "s1"},
	} {
		if _, err := client.Refresh(context.Background(), c, "rt"); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(seen, ",") != "one/s1,two/s2,one/s1" {
		t.Fatalf("credentials sent = %v", seen)
	}
}

func TestRefreshRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		form := readForm(t, r)
		expectForm(t, form, map[string]string{
			"client_id":     "client-a",
			"client_secret": "secret-a",
			"refresh_token": "stored-refresh-token",
			"grant_type":    "refresh_token",
		})
		for _, absent := range []string{"code", "code_verifier", "redirect_uri"} {
			if form.Has(absent) {
				t.Fatalf("refresh must not send %s", absent)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new-access","expires_in":3599,"scope":"scope-a","token_type":"Bearer"}`)
	}))
	defer server.Close()

	tokens, err := newTestClient(t, server).Refresh(context.Background(), credsA, "stored-refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "new-access" || tokens.ExpiresIn != 3599 ||
		tokens.RefreshToken != "" || len(tokens.Scopes) != 1 {
		t.Fatalf("tokens = %+v", tokens)
	}
}

func TestRefreshReturnsReplacementRefreshTokenOnlyWhenSent(t *testing.T) {
	with := respond(200, `{"access_token":"a","refresh_token":"rotated","expires_in":3600,"token_type":"Bearer"}`, nil)
	defer with.Close()
	without := respond(200, `{"access_token":"a","expires_in":3600,"token_type":"Bearer"}`, nil)
	defer without.Close()

	got, err := newTestClient(t, with).Refresh(context.Background(), credsA, "old")
	if err != nil || got.RefreshToken != "rotated" {
		t.Fatalf("with replacement: %+v, %v", got, err)
	}
	got, err = newTestClient(t, without).Refresh(context.Background(), credsA, "old")
	if err != nil || got.RefreshToken != "" {
		t.Fatalf("without replacement must leave RefreshToken empty: %+v, %v", got, err)
	}
}

func TestProviderFailuresAreClassified(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		headers    map[string]string
		kind       ErrorKind
		code       string
		retryAfter time.Duration
	}{
		{"invalid_grant", 400, `{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`, nil, KindInvalidGrant, "invalid_grant", 0},
		{"invalid_grant on 401", 401, `{"error":"invalid_grant"}`, nil, KindInvalidGrant, "invalid_grant", 0},
		{"rate limited", 429, `{"error":"rate_limit_exceeded"}`, map[string]string{"Retry-After": "30"}, KindRateLimited, "rate_limit_exceeded", 30 * time.Second},
		{"retry-after capped", 429, `{}`, map[string]string{"Retry-After": "86400"}, KindRateLimited, "", 5 * time.Minute},
		{"retry-after garbage", 429, `{}`, map[string]string{"Retry-After": "soon"}, KindRateLimited, "", 0},
		{"server error", 500, `internal`, nil, KindUnavailable, "", 0},
		{"service unavailable", 503, `{"error":"backend_error"}`, nil, KindUnavailable, "backend_error", 0},
		{"invalid client", 401, `{"error":"invalid_client","error_description":"The OAuth client was not found."}`, nil, KindRejected, "invalid_client", 0},
		{"invalid request", 400, `{"error":"invalid_request"}`, nil, KindRejected, "invalid_request", 0},
		{"not json", 400, `<html>bad</html>`, nil, KindRejected, "", 0},
		{"odd error code is dropped", 400, `{"error":"has spaces & symbols"}`, nil, KindRejected, "", 0},
	}

	for _, tc := range cases {
		server := respond(tc.status, tc.body, tc.headers)
		client := newTestClient(t, server)

		for op, call := range map[string]func() error{
			"refresh": func() error { _, err := client.Refresh(context.Background(), credsA, "rt"); return err },
			"exchange": func() error {
				_, err := client.ExchangeCode(context.Background(), credsA, "code", "verifier")
				return err
			},
		} {
			err := call()
			var perr *ProviderError
			if !errors.As(err, &perr) {
				t.Fatalf("%s/%s: error type = %T (%v)", tc.name, op, err, err)
			}
			if perr.Kind != tc.kind || perr.ProviderCode != tc.code ||
				perr.StatusCode != tc.status || perr.RetryAfter != tc.retryAfter {
				t.Fatalf("%s/%s: %+v", tc.name, op, perr)
			}
			for _, leak := range []string{"description", "expired or revoked", "not found", "<html>", "secret-a", "rt"} {
				if strings.Contains(err.Error(), leak) && leak != "rt" {
					t.Fatalf("%s/%s: error leaks %q: %v", tc.name, op, leak, err)
				}
			}
		}
		server.Close()
	}
}

func TestExchangeErrorAliasStillWorks(t *testing.T) {
	server := respond(400, `{"error":"invalid_grant","error_description":"sensitive provider description"}`, nil)
	defer server.Close()

	_, err := newTestClient(t, server).ExchangeCode(context.Background(), credsA, "code", "verifier")
	exchangeError, ok := err.(*ExchangeError)
	if !ok || exchangeError.ProviderCode != "invalid_grant" {
		t.Fatalf("error = %T %v", err, err)
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("error includes provider description: %v", err)
	}
}

func TestUnusableSuccessResponsesAreUnavailable(t *testing.T) {
	bodies := map[string]string{
		"invalid json":       `{"access_token":`,
		"empty body":         ``,
		"no access token":    `{"expires_in":3600,"token_type":"Bearer"}`,
		"blank access token": `{"access_token":"  ","expires_in":3600}`,
		"bad expires_in":     `{"access_token":"a","expires_in":"soon","token_type":"Bearer"}`,
		"negative expires":   `{"access_token":"a","expires_in":-5,"token_type":"Bearer"}`,
		"array expires":      `{"access_token":"a","expires_in":[1],"token_type":"Bearer"}`,
		"missing expires":    `{"access_token":"a","token_type":"Bearer"}`,
	}
	for name, body := range bodies {
		server := respond(200, body, nil)
		_, err := newTestClient(t, server).Refresh(context.Background(), credsA, "rt")
		var perr *ProviderError
		if !errors.As(err, &perr) || perr.Kind != KindUnavailable {
			t.Fatalf("%s: err = %v", name, err)
		}
		server.Close()
	}
}

// Google has already consumed the one-time code when a response arrives, so an
// unexpected token_type must not turn a good exchange into a failure.
func TestUnexpectedTokenTypeDoesNotFailTheExchange(t *testing.T) {
	server := respond(200, `{"access_token":"a","refresh_token":"r","expires_in":3600,"token_type":"MAC"}`, nil)
	defer server.Close()

	tokens, err := newTestClient(t, server).ExchangeCode(context.Background(), credsA, "code", "verifier")
	if err != nil || tokens.AccessToken != "a" || tokens.RefreshToken != "r" {
		t.Fatalf("tokens = %+v, err = %v", tokens, err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":                                0,
		"30":                              30 * time.Second,
		" 45 ":                            45 * time.Second,
		"0":                               0,
		"-5":                              0,
		"soon":                            0,
		"86400":                           5 * time.Minute,
		"Tue, 03 Nov 2026 12:01:30 GMT":   90 * time.Second,
		"Tue, 03 Nov 2026 11:00:00 GMT":   0,
		"Wed, 04 Nov 2026 12:00:00 GMT":   5 * time.Minute,
		"Tuesday, 03-Nov-26 12:00:20 GMT": 20 * time.Second,
		"Tue Nov  3 12:00:10 2026":        10 * time.Second,
		"not a date":                      0,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in, now); got != want {
			t.Fatalf("parseRetryAfter(%q) = %v; want %v", in, got, want)
		}
	}
}

func TestRetryAfterDateFromGoogleIsHonoured(t *testing.T) {
	when := time.Now().Add(40 * time.Second).UTC().Format(http.TimeFormat)
	server := respond(429, `{}`, map[string]string{"Retry-After": when})
	defer server.Close()

	_, err := newTestClient(t, server).Refresh(context.Background(), credsA, "rt")
	var perr *ProviderError
	if !errors.As(err, &perr) || perr.Kind != KindRateLimited {
		t.Fatalf("err = %v", err)
	}
	if perr.RetryAfter < 30*time.Second || perr.RetryAfter > 41*time.Second {
		t.Fatalf("RetryAfter = %v; want about 40s", perr.RetryAfter)
	}
}

func TestExpiresInAsStringIsAccepted(t *testing.T) {
	server := respond(200, `{"access_token":"a","expires_in":"3599","token_type":"bearer"}`, nil)
	defer server.Close()

	got, err := newTestClient(t, server).Refresh(context.Background(), credsA, "rt")
	if err != nil || got.ExpiresIn != 3599 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestTimeoutIsUnavailableAndBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body so the server notices the client disconnecting.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()

	httpClient := server.Client()
	httpClient.Timeout = 80 * time.Millisecond
	client, err := NewClient(Options{RedirectURI: testRedirectURI, TokenEndpoint: server.URL, HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = client.Refresh(context.Background(), credsA, "rt")
	var perr *ProviderError
	if !errors.As(err, &perr) || perr.Kind != KindUnavailable || perr.StatusCode != 0 {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("call took %v; timeout not applied", time.Since(start))
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v", err)
	}
}

func TestContextCancellationIsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := newTestClient(t, server).Refresh(ctx, credsA, "rt")
	var perr *ProviderError
	if !errors.As(err, &perr) || perr.Kind != KindUnavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestNetworkErrorDoesNotExposeURLOrSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close() // connection refused

	client, err := NewClient(Options{RedirectURI: testRedirectURI, TokenEndpoint: url})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Refresh(context.Background(), credsA, "very-secret-refresh-token")
	var perr *ProviderError
	if !errors.As(err, &perr) || perr.Kind != KindUnavailable {
		t.Fatalf("err = %v", err)
	}
	for _, leak := range []string{url, "very-secret-refresh-token", "secret-a", "127.0.0.1"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error leaks %q: %v", leak, err)
		}
		if perr.Unwrap() != nil && strings.Contains(perr.Unwrap().Error(), leak) {
			t.Fatalf("cause leaks %q: %v", leak, perr.Unwrap())
		}
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	_, err := newTestClient(t, redirector).Refresh(context.Background(), credsA, "rt")
	var perr *ProviderError
	if !errors.As(err, &perr) || perr.Kind != KindRejected || perr.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("client followed a redirect and would have sent secrets elsewhere")
	}
}

func TestOversizedResponseIsBounded(t *testing.T) {
	server := respond(200, `{"access_token":"`+strings.Repeat("x", 1<<20)+`","expires_in":3600}`, nil)
	defer server.Close()

	_, err := newTestClient(t, server).Refresh(context.Background(), credsA, "rt")
	var perr *ProviderError
	if !errors.As(err, &perr) || perr.Kind != KindUnavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestInputValidation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newTestClient(t, server)
	ctx := context.Background()

	if _, err := client.Refresh(ctx, Credentials{}, "rt"); err == nil {
		t.Fatal("missing credentials must fail")
	}
	if _, err := client.Refresh(ctx, Credentials{ClientID: "a"}, "rt"); err == nil {
		t.Fatal("missing secret must fail")
	}
	if _, err := client.Refresh(ctx, credsA, "   "); err == nil {
		t.Fatal("blank refresh token must fail")
	}
	if _, err := client.ExchangeCode(ctx, Credentials{}, "c", "v"); err == nil {
		t.Fatal("exchange without credentials must fail")
	}
	if _, err := client.ExchangeCode(ctx, credsA, "", "v"); err == nil {
		t.Fatal("blank code must fail")
	}
	if _, err := client.ExchangeCode(ctx, credsA, "c", ""); err == nil {
		t.Fatal("blank verifier must fail")
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid input reached Google %d times", calls.Load())
	}
}

func TestDefaultEndpointIsGooglesAndOptionsAreValidated(t *testing.T) {
	client, err := NewClient(Options{RedirectURI: testRedirectURI})
	if err != nil {
		t.Fatal(err)
	}
	if client.tokenEndpoint != "https://oauth2.googleapis.com/token" {
		t.Fatalf("default endpoint = %q", client.tokenEndpoint)
	}

	if _, err := NewClient(Options{}); err == nil {
		t.Fatal("redirect URI is required")
	}
	if _, err := NewClient(Options{RedirectURI: testRedirectURI, TokenEndpoint: "not a url"}); err == nil {
		t.Fatal("relative token endpoint must be rejected")
	}
}
