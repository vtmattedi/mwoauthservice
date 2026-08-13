package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDRejectsUnsafeIncomingValue(t *testing.T) {
	handler := RequestID(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/health",
		nil,
	)
	request.Header.Set(
		requestIDHeader,
		"unsafe request id",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	got := response.Header().Get(requestIDHeader)
	if got == "unsafe request id" {
		t.Fatal("unsafe request ID was reflected")
	}
	if got == "" {
		t.Fatal("replacement request ID is empty")
	}
}
