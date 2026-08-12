// MW_OAUTH_STEP_01
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
)

func TestHealth(t *testing.T) {
	router := NewRouter(Dependencies{
		Build: buildinfo.Current(),
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d; want %d", res.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	if body["status"] != "ok" {
		t.Fatalf("status body = %q; want ok", body["status"])
	}
}

func TestUnknownRouteIs404(t *testing.T) {
	router := NewRouter(Dependencies{
		Build: buildinfo.Current(),
	})

	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want %d", res.Code, http.StatusNotFound)
	}
}
