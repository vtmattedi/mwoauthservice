// MW_OAUTH_STEP_01
package api

import (
	"encoding/json"
	"net/http"

	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
)

type Dependencies struct {
	Build buildinfo.Info
}

func NewRouter(deps Dependencies) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ok",
		})
	})

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
