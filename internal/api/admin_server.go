package api

import (
	"net/http"

	"github.com/vtmattedi/mw-oauth-service/internal/apidocs"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
)

type adminServerBuild struct {
	Commit    string `json:"commit"`
	BuiltAt   string `json:"built_at"`
	GoVersion string `json:"go_version"`
}

type adminServerAPI struct {
	Current    string   `json:"current"`
	Accepted   []string `json:"accepted"`
	Deprecated []string `json:"deprecated"`
}

type adminServerProvider struct {
	Supported bool   `json:"supported"`
	OAuthFlow string `json:"oauth_flow"`
}

type adminServerResponse struct {
	Service string           `json:"service"`
	Version string           `json:"version"`
	Build   adminServerBuild `json:"build"`
	API     adminServerAPI   `json:"api"`

	Providers map[string]adminServerProvider `json:"providers"`
}

type adminDocsListResponse struct {
	Versions []apidocs.Version `json:"versions"`
}

type adminDocResponse struct {
	Version       string `json:"version"`
	Status        string `json:"status"`
	ContentType   string `json:"content_type"`
	Documentation string `json:"documentation"`
}

func AdminServer(build buildinfo.Info) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(
			w,
			http.StatusOK,
			adminServerResponse{
				Service: build.Service,
				Version: build.Version,
				Build: adminServerBuild{
					Commit:    build.Commit,
					BuiltAt:   build.BuiltAt,
					GoVersion: build.GoVersion,
				},
				API: adminServerAPI{
					Current:    build.APICurrent,
					Accepted:   build.APIAccepted,
					Deprecated: []string{},
				},
				Providers: map[string]adminServerProvider{
					"google": {
						Supported: true,
						OAuthFlow: "authorization_code_pkce",
					},
				},
			},
		)
	}
}

func AdminDocsList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(
			w,
			http.StatusOK,
			adminDocsListResponse{
				Versions: apidocs.List(),
			},
		)
	}
}

func AdminDocsGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		version := r.PathValue("version")

		meta, documentation, err := apidocs.Get(version)
		if err != nil {
			writeError(
				w,
				http.StatusNotFound,
				"API documentation version not found",
			)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			adminDocResponse{
				Version:       meta.Version,
				Status:        meta.Status,
				ContentType:   meta.ContentType,
				Documentation: documentation,
			},
		)
	}
}
