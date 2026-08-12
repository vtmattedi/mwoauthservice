package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"oauth.mattediworks.com":     "oauth.mattediworks.com",
		"OAuth.MattediWorks.Com":     "oauth.mattediworks.com",
		"oauth.mattediworks.com:443": "oauth.mattediworks.com",
		"127.0.0.1:8282":             "127.0.0.1",
	}

	for input, want := range tests {
		if got := normalizeHost(input); got != want {
			t.Fatalf("normalizeHost(%q) = %q; want %q", input, got, want)
		}
	}
}

func TestConcealRejectsWrongHost(t *testing.T) {
	service := NewService(nil, Options{
		CheckSPHost: true,
		SPHost:      "oauth.mattediworks.com",
	})

	handler := service.Conceal(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		},
	))

	req := httptest.NewRequest(
		http.MethodGet,
		"http://example.test/admin/api/auth/me",
		nil,
	)
	req.Host = "wrong.example.com"

	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", res.Code)
	}
}

func TestConcealRejectsWrongOrigin(t *testing.T) {
	service := NewService(nil, Options{
		Origins: []string{"https://admin.mattediworks.com"},
	})

	handler := service.Conceal(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		},
	))

	req := httptest.NewRequest(
		http.MethodGet,
		"http://oauth.mattediworks.com/admin/api/auth/me",
		nil,
	)
	req.Header.Set("Origin", "https://evil.example")

	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", res.Code)
	}
}
