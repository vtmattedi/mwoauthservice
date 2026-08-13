package google

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExchangeCode(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Fatalf("method = %s; want POST", r.Method)
				}

				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}

				form, err := url.ParseQuery(string(body))
				if err != nil {
					t.Fatal(err)
				}

				expected := map[string]string{
					"client_id":     "client-id",
					"client_secret": "client-secret",
					"code":          "provider-code",
					"code_verifier": "pkce-verifier",
					"grant_type":    "authorization_code",
					"redirect_uri":  "https://oauth.example.com/oauth/google/callback",
				}

				for key, want := range expected {
					if got := form.Get(key); got != want {
						t.Fatalf(
							"%s = %q; want %q",
							key,
							got,
							want,
						)
					}
				}

				w.Header().Set(
					"Content-Type",
					"application/json",
				)
				_, _ = io.WriteString(
					w,
					`{"access_token":"access","refresh_token":"refresh","expires_in":3599,"token_type":"Bearer","scope":"scope-a scope-b"}`,
				)
			},
		),
	)
	defer server.Close()

	client, err := NewClient(Options{
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
		RedirectURI:   "https://oauth.example.com/oauth/google/callback",
		TokenEndpoint: server.URL,
		HTTPClient:    server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := client.ExchangeCode(
		context.Background(),
		"provider-code",
		"pkce-verifier",
	)
	if err != nil {
		t.Fatal(err)
	}

	if tokens.AccessToken != "access" {
		t.Fatalf(
			"access token = %q; want access",
			tokens.AccessToken,
		)
	}
	if tokens.RefreshToken != "refresh" {
		t.Fatalf(
			"refresh token = %q; want refresh",
			tokens.RefreshToken,
		)
	}
	if tokens.ExpiresIn != 3599 {
		t.Fatalf(
			"expires_in = %d; want 3599",
			tokens.ExpiresIn,
		)
	}
	if len(tokens.Scopes) != 2 {
		t.Fatalf(
			"scope count = %d; want 2",
			len(tokens.Scopes),
		)
	}
}

func TestExchangeErrorDoesNotIncludeProviderDescription(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(
					"Content-Type",
					"application/json",
				)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(
					w,
					`{"error":"invalid_grant","error_description":"sensitive provider description"}`,
				)
			},
		),
	)
	defer server.Close()

	client, err := NewClient(Options{
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
		RedirectURI:   "https://oauth.example.com/oauth/google/callback",
		TokenEndpoint: server.URL,
		HTTPClient:    server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.ExchangeCode(
		context.Background(),
		"provider-code",
		"pkce-verifier",
	)
	if err == nil {
		t.Fatal("expected exchange failure")
	}

	exchangeError, ok := err.(*ExchangeError)
	if !ok {
		t.Fatalf(
			"error type = %T; want *ExchangeError",
			err,
		)
	}
	if exchangeError.ProviderCode != "invalid_grant" {
		t.Fatalf(
			"provider code = %q",
			exchangeError.ProviderCode,
		)
	}
}
