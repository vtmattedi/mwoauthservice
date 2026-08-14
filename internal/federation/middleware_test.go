package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type introspectionStub struct {
	token Token
	err   error
	calls int
}

func (s *introspectionStub) Introspect(context.Context, string) (Token, error) {
	s.calls++
	return s.token, s.err
}

func TestFederatedMiddlewareAuthorization(t *testing.T) {
	tests := []struct {
		name   string
		header string
		token  Token
		err    error
		want   int
	}{
		{"valid", "Bearer opaque", activeToken("mw-oauth", "oauth.projects.read"), nil, 204},
		{"multiple scopes", "Bearer opaque", activeToken("mw-oauth", "other oauth.projects.read more"), nil, 204},
		{"inactive", "Bearer opaque", Token{Active: false}, nil, 401},
		{"empty subject", "Bearer opaque", Token{Active: true, Audience: []string{"mw-oauth"}, Scopes: []string{"oauth.projects.read"}}, nil, 401},
		{"wrong audience", "Bearer opaque", activeToken("mw-mail", "oauth.projects.read"), nil, 403},
		{"scope missing", "Bearer opaque", activeToken("mw-oauth", "oauth.projects.write"), nil, 403},
		{"malformed scheme", "Basic opaque", Token{}, nil, 401},
		{"malformed fields", "Bearer one two", Token{}, nil, 401},
		{"whitespace header", "   ", Token{}, nil, 401},
		{"Identity failure", "Bearer opaque", Token{}, errors.New("unavailable"), 401},
		{"missing", "", Token{}, nil, 401},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &introspectionStub{token: test.token, err: test.err}
			auth, _ := NewAuthenticator(ModeFederated, "mw-oauth", stub)
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				principal, ok := Current(r.Context())
				if !ok || principal.IdentitySubject == nil {
					t.Fatal("principal missing")
				}
				w.WriteHeader(http.StatusNoContent)
			})
			handler := auth.Require("oauth.projects.read", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) }), next)
			req := httptest.NewRequest(http.MethodGet, "/admin/api/projects", nil)
			if test.header != "" {
				req.Header.Set("Authorization", test.header)
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != test.want {
				t.Fatalf("status=%d want=%d", res.Code, test.want)
			}
		})
	}
}

func TestAuthenticationModesAndNoFallback(t *testing.T) {
	for _, mode := range []Mode{ModeLocal, ModeHybrid, ModeFederated} {
		t.Run(string(mode), func(t *testing.T) {
			stub := &introspectionStub{token: activeToken("mw-oauth", "oauth.projects.read")}
			auth, _ := NewAuthenticator(mode, "mw-oauth", stub)
			localCalls, federatedCalls := 0, 0
			handler := auth.Require("oauth.projects.read", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { localCalls++; w.WriteHeader(210) }), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { federatedCalls++; w.WriteHeader(211) }))

			plain := httptest.NewRecorder()
			handler.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/", nil))
			wantPlain := 210
			if mode == ModeFederated {
				wantPlain = 401
			}
			if plain.Code != wantPlain {
				t.Fatalf("plain=%d want=%d", plain.Code, wantPlain)
			}

			bearerReq := httptest.NewRequest(http.MethodGet, "/", nil)
			bearerReq.Header.Set("Authorization", "Bearer token")
			bearer := httptest.NewRecorder()
			handler.ServeHTTP(bearer, bearerReq)
			wantBearer := 211
			if mode == ModeLocal {
				wantBearer = 401
			}
			if bearer.Code != wantBearer {
				t.Fatalf("bearer=%d want=%d", bearer.Code, wantBearer)
			}

			badReq := httptest.NewRequest(http.MethodGet, "/", nil)
			badReq.Header.Set("Authorization", "Bearer bad")
			stub.err = errors.New("bad token")
			before := localCalls
			bad := httptest.NewRecorder()
			handler.ServeHTTP(bad, badReq)
			if bad.Code != 401 || localCalls != before {
				t.Fatalf("invalid Bearer fell back: status=%d local=%d before=%d", bad.Code, localCalls, before)
			}
		})
	}
}

func TestDuplicateAuthorizationHeadersAreRejected(t *testing.T) {
	stub := &introspectionStub{token: activeToken("mw-oauth", "oauth.projects.read")}
	auth, _ := NewAuthenticator(ModeHybrid, "mw-oauth", stub)
	handler := auth.Require("oauth.projects.read", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(210) }), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(211) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("Authorization", "Bearer first")
	req.Header.Add("Authorization", "Bearer second")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized || stub.calls != 0 {
		t.Fatalf("status=%d calls=%d", res.Code, stub.calls)
	}
}

func activeToken(audience, scopes string) Token {
	return Token{Active: true, Subject: "usr_123", Audience: []string{audience}, Scopes: splitScopes(scopes)}
}
func splitScopes(raw string) []string { return strings.Fields(raw) }
