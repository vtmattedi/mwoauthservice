package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORSAllowsWebAuthnCeremonyHeader(t *testing.T) {
	service := NewService(nil, Options{
		Origins: []string{"https://admin.example.com"},
	})

	handler := service.CORS(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodOptions,
		"http://oauth.example.com/admin/api/auth/webauthn/login/verify",
		nil,
	)
	request.Header.Set("Origin", "https://admin.example.com")

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	headers := response.Header().Get(
		"Access-Control-Allow-Headers",
	)
	if !strings.Contains(
		headers,
		"X-MW-WebAuthn-Ceremony",
	) {
		t.Fatalf(
			"allowed headers = %q",
			headers,
		)
	}
}
