// MW_OAUTH_STEP_01
package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

type HealthStore interface {
	Ping(ctx context.Context) error
}

type Dependencies struct {
	Build    buildinfo.Info
	Health   HealthStore
	Admin    *admin.Service
	Projects *project.Service
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

	if deps.Admin != nil {
		adminHandler := newAdminRouter(
			deps.Admin,
			deps.Projects,
		)
		mux.Handle("/admin/api", adminHandler)
		mux.Handle("/admin/api/", adminHandler)
	}

	return mux
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
