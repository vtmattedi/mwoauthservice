// MW_OAUTH_STEP_01
package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/adminwebauthn"
	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/federation"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/refresh"
)

type HealthStore interface {
	Ping(ctx context.Context) error
}

type Dependencies struct {
	Build         buildinfo.Info
	Health        HealthStore
	Admin         *admin.Service
	AdminWebAuthn *adminwebauthn.Service
	Projects      *project.Service
	Audit         *audit.Service
	OAuth         *oauth.Service
	OAuthCallback *oauth.CallbackService
	AppAuth       *appauth.Service
	Refresh       *refresh.Service
	// TokenLimits guards POST /v1/auth/token. The zero value means no
	// limits; main supplies DefaultTokenLimits().
	TokenLimits TokenLimits
	Federation  *federation.Authenticator
}

func NewRouter(deps Dependencies) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if deps.Health != nil {
			if err := deps.Health.Ping(r.Context()); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{
					"status": "unavailable",
				})
				return
			}
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ok",
		})
	})

	if deps.AppAuth != nil {
		mux.HandleFunc(
			"POST /v1/auth/token",
			TokenEndpoint(
				deps.AppAuth,
				deps.Audit,
				deps.TokenLimits,
			),
		)
	}

	if deps.OAuth != nil && deps.AppAuth != nil {
		mux.HandleFunc(
			"POST /v1/oauth/google/authorize",
			PublicGoogleAuthorize(
				deps.OAuth,
				deps.Audit,
				deps.AppAuth,
			),
		)
	}

	if deps.AppAuth != nil && deps.Refresh != nil {
		mux.HandleFunc(
			"POST /v1/oauth/google/refresh",
			GoogleRefresh(
				deps.AppAuth,
				deps.Refresh,
				deps.Audit,
			),
		)
	}

	if deps.OAuthCallback != nil {
		mux.HandleFunc(
			"GET /oauth/google/callback",
			GoogleOAuthCallback(
				deps.OAuthCallback,
				deps.Audit,
			),
		)
	}

	if deps.Admin != nil {
		adminHandler := newAdminRouter(
			deps.Admin,
			deps.AdminWebAuthn,
			deps.Projects,
			deps.Audit,
			deps.Build,
			deps.Federation,
		)
		mux.Handle("/admin/api", adminHandler)
		mux.Handle("/admin/api/", adminHandler)
	}

	return SecurityHeaders(RequestID(requestLogging(mux)))
}

func requestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf(
			"request_id=%s method=%s path=%s remote_addr=%s",
			RequestIDFromContext(r.Context()),
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
		)

		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}
