package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

func TestAdminAuthFlow(t *testing.T) {
	store, err := sqlite.Open(
		filepath.Join(t.TempDir(), "oauth.db"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	hash, err := admin.HashPassword("a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.CreateAdminUser(
		t.Context(),
		"admin@example.com",
		hash,
	)
	if err != nil {
		t.Fatal(err)
	}

	adminService := admin.NewService(
		store,
		admin.Options{
			CookieName:    "test_admin_session",
			SecureCookies: false,
		},
	)

	router := NewRouter(Dependencies{
		Build:  buildinfo.Current(),
		Health: store,
		Admin:  adminService,
	})

	loginBody := []byte(
		`{"email":"admin@example.com","password":"a-long-test-password"}`,
	)
	loginReq := httptest.NewRequest(
		http.MethodPost,
		"/admin/api/auth/login",
		bytes.NewReader(loginBody),
	)
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes := httptest.NewRecorder()
	router.ServeHTTP(loginRes, loginReq)

	if loginRes.Code != http.StatusOK {
		t.Fatalf(
			"login status = %d body=%s",
			loginRes.Code,
			loginRes.Body.String(),
		)
	}

	var loginPayload struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(
		loginRes.Body.Bytes(),
		&loginPayload,
	); err != nil {
		t.Fatal(err)
	}
	if loginPayload.CSRFToken == "" {
		t.Fatal("expected csrf token")
	}

	cookies := loginRes.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d; want 1", len(cookies))
	}
	sessionCookie := cookies[0]

	meReq := httptest.NewRequest(
		http.MethodGet,
		"/admin/api/auth/me",
		nil,
	)
	meReq.AddCookie(sessionCookie)
	meRes := httptest.NewRecorder()
	router.ServeHTTP(meRes, meReq)
	if meRes.Code != http.StatusOK {
		t.Fatalf(
			"me status = %d body=%s",
			meRes.Code,
			meRes.Body.String(),
		)
	}

	csrfReq := httptest.NewRequest(
		http.MethodPost,
		"/admin/api/auth/csrf",
		nil,
	)
	csrfReq.AddCookie(sessionCookie)
	csrfRes := httptest.NewRecorder()
	router.ServeHTTP(csrfRes, csrfReq)
	if csrfRes.Code != http.StatusOK {
		t.Fatalf(
			"csrf status = %d body=%s",
			csrfRes.Code,
			csrfRes.Body.String(),
		)
	}

	var csrfPayload struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(
		csrfRes.Body.Bytes(),
		&csrfPayload,
	); err != nil {
		t.Fatal(err)
	}

	badLogoutReq := httptest.NewRequest(
		http.MethodPost,
		"/admin/api/auth/logout",
		nil,
	)
	badLogoutReq.AddCookie(sessionCookie)
	badLogoutRes := httptest.NewRecorder()
	router.ServeHTTP(badLogoutRes, badLogoutReq)
	if badLogoutRes.Code != http.StatusForbidden {
		t.Fatalf(
			"logout without csrf = %d; want 403",
			badLogoutRes.Code,
		)
	}

	logoutReq := httptest.NewRequest(
		http.MethodPost,
		"/admin/api/auth/logout",
		nil,
	)
	logoutReq.AddCookie(sessionCookie)
	logoutReq.Header.Set("X-CSRF-Token", csrfPayload.CSRFToken)
	logoutRes := httptest.NewRecorder()
	router.ServeHTTP(logoutRes, logoutReq)
	if logoutRes.Code != http.StatusNoContent {
		t.Fatalf(
			"logout status = %d body=%s",
			logoutRes.Code,
			logoutRes.Body.String(),
		)
	}
}
