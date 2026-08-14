package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientIntrospectsActiveToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/introspect" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		id, secret, ok := r.BasicAuth()
		if !ok || id != "resource" || secret != "secret" {
			t.Fatal("missing Basic credentials")
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("token") != "opaque-token" {
			t.Fatal("missing form token")
		}
		_, _ = w.Write([]byte(`{"active":true,"sub":"usr_1","aud":["other","mw-oauth"],"scope":"oauth.projects.read oauth.projects.write","auth_time":1700000000,"amr":["pwd","webauthn"]}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, server.Client())
	token, err := client.Introspect(t.Context(), "opaque-token")
	if err != nil {
		t.Fatal(err)
	}
	if !token.Active || token.Subject != "usr_1" || len(token.Scopes) != 2 || len(token.Audience) != 2 {
		t.Fatalf("unexpected token: %+v", token)
	}
	if token.AuthTime == nil || token.AuthTime.Unix() != 1700000000 || len(token.AMR) != 2 {
		t.Fatalf("authentication context lost: %+v", token)
	}
}

func TestClientAcceptsStringAudienceAndAuthTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"active":true,"sub":"usr_1","aud":"mw-oauth","scope":"oauth.projects.read","auth_time":"1700000000"}`))
	}))
	defer server.Close()
	token, err := newTestClient(t, server.URL, server.Client()).Introspect(t.Context(), "token")
	if err != nil || len(token.Audience) != 1 || token.AuthTime == nil {
		t.Fatalf("token=%+v err=%v", token, err)
	}
}

func TestClientFailsClosedForIdentityResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"identity 401", 401, `{}`}, {"identity 403", 403, `{}`}, {"identity 500", 500, `{}`},
		{"invalid JSON", 200, `{`}, {"invalid auth time", 200, `{"active":true,"auth_time":{}}`},
		{"oversized response", 200, strings.Repeat("x", maxIntrospectionBody+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := newTestClient(t, server.URL, server.Client()).Introspect(t.Context(), "token")
			if !errors.Is(err, ErrIntrospectionFailed) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestClientHonorsTimeout(t *testing.T) {
	client := &Client{endpoint: "http://identity.invalid/oauth/introspect", clientID: "id", clientSecret: "secret", httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	_, err := client.Introspect(ctx, "token")
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("err=%v", err)
	}
}

func TestClientDoesNotFollowCrossHostRedirect(t *testing.T) {
	redirected := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()

	_, err := newTestClient(t, source.URL, source.Client()).Introspect(t.Context(), "token")
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("err=%v", err)
	}
	if redirected {
		t.Fatal("introspection credentials followed a cross-host redirect")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newTestClient(t *testing.T, baseURL string, httpClient *http.Client) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{BaseURL: baseURL, ClientID: "resource", ClientSecret: "secret", HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
