// MW_OAUTH_STEP_01
package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/adminwebauthn"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
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

	if deps.OAuth != nil {
		mux.HandleFunc(
			"POST /v1/oauth/google/authorize",
			PublicGoogleAuthorize(
				deps.OAuth,
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
		)
		mux.Handle("/admin/api", adminHandler)
		mux.Handle("/admin/api/", adminHandler)
	}

	return SecurityHeaders(RequestID(mux))
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
