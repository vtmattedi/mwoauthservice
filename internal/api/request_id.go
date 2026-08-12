package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
)

const requestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		requestID := strings.TrimSpace(
			r.Header.Get(requestIDHeader),
		)

		if requestID == "" || len(requestID) > 160 {
			requestID = newRequestID()
		}

		w.Header().Set(requestIDHeader, requestID)

		ctx := context.WithValue(
			r.Context(),
			requestIDContextKey{},
			requestID,
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RequestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

func newRequestID() string {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "req_unknown"
	}

	return "req_" +
		base64.RawURLEncoding.EncodeToString(raw)
}
