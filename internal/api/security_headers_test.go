package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersOnOAuthCallback(t *testing.T) {
	handler := SecurityHeaders(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/oauth/google/callback?code=secret&state=secret",
		nil,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got := response.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q; want no-referrer", got)
	}

	if got := response.Header().Get("Cache-Control"); got != "no-store, max-age=0" {
		t.Fatalf("Cache-Control = %q", got)
	}

	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
}
