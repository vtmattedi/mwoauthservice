package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
)

type healthStub struct {
	err error
}

func (h healthStub) Ping(ctx context.Context) error {
	return h.err
}

func TestHealth(t *testing.T) {
	router := NewRouter(Dependencies{
		Build:  buildinfo.Current(),
		Health: healthStub{},
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
		t.Fatalf("status = %q; want ok", body["status"])
	}
}

func TestHealthUnavailableWhenDatabasePingFails(t *testing.T) {
	router := NewRouter(Dependencies{
		Build:  buildinfo.Current(),
		Health: healthStub{err: errors.New("db unavailable")},
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)

	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want %d", res.Code, http.StatusServiceUnavailable)
	}
}

func TestUnknownRouteIs404(t *testing.T) {
	router := NewRouter(Dependencies{
		Build:  buildinfo.Current(),
		Health: healthStub{},
	})
	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want %d", res.Code, http.StatusNotFound)
	}
}
