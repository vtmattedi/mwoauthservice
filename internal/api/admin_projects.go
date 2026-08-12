package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

type adminProjectCreateRequest struct {
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled,omitempty"`
}

type adminProjectUpdateRequest struct {
	Name    *string `json:"name,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}

type adminProjectsResponse struct {
	Projects []domain.Project `json:"projects"`
}

type adminProjectCredentialsResponse struct {
	Project        domain.Project `json:"project"`
	APIKey         string         `json:"api_key"`
	CallbackSecret string         `json:"callback_secret"`
}

type adminAPIKeyResponse struct {
	APIKey string `json:"api_key"`
}

type adminCallbackSecretResponse struct {
	CallbackSecret string `json:"callback_secret"`
}

func AdminProjectsList(
	service *project.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		projects, err := service.List(r.Context())
		if err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				"could not list projects",
			)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			adminProjectsResponse{
				Projects: projects,
			},
		)
	}
}

func AdminProjectCreate(
	service *project.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request adminProjectCreateRequest
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		enabled := true
		if request.Enabled != nil {
			enabled = *request.Enabled
		}

		result, err := service.Create(
			r.Context(),
			request.Name,
			enabled,
		)
		if err != nil {
			writeProjectError(w, err)
			return
		}

		writeJSON(
			w,
			http.StatusCreated,
			adminProjectCredentialsResponse{
				Project:        result.Project,
				APIKey:         result.APIKey,
				CallbackSecret: result.CallbackSecret,
			},
		)
	}
}

func AdminProjectUpdate(
	service *project.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := adminProjectID(w, r)
		if !ok {
			return
		}

		var request adminProjectUpdateRequest
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		updated, err := service.Update(
			r.Context(),
			id,
			project.UpdateInput{
				Name:    request.Name,
				Enabled: request.Enabled,
			},
		)
		if err != nil {
			writeProjectError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, updated)
	}
}

func AdminProjectRotateAPIKey(
	service *project.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := adminProjectID(w, r)
		if !ok {
			return
		}

		apiKey, err := service.RotateAPIKey(
			r.Context(),
			id,
		)
		if err != nil {
			writeProjectError(w, err)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			adminAPIKeyResponse{
				APIKey: apiKey,
			},
		)
	}
}

func AdminProjectRotateCallbackSecret(
	service *project.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := adminProjectID(w, r)
		if !ok {
			return
		}

		secret, err := service.RotateCallbackSecret(
			r.Context(),
			id,
		)
		if err != nil {
			writeProjectError(w, err)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			adminCallbackSecretResponse{
				CallbackSecret: secret,
			},
		)
	}
}

func AdminProjectGoogleConfigGet(
	service *project.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := adminProjectID(w, r)
		if !ok {
			return
		}

		config, err := service.GoogleConfig(
			r.Context(),
			id,
		)
		if err != nil {
			writeProjectError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, config)
	}
}

func AdminProjectGoogleConfigPut(
	service *project.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := adminProjectID(w, r)
		if !ok {
			return
		}

		var request domain.GoogleOAuthConfig
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		config, err := service.ConfigureGoogle(
			r.Context(),
			id,
			request,
		)
		if err != nil {
			writeProjectError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, config)
	}
}

func adminProjectID(
	w http.ResponseWriter,
	r *http.Request,
) (int64, bool) {
	raw := strings.TrimSpace(r.PathValue("id"))
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return 0, false
	}

	return id, true
}

func writeProjectError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, project.ErrValidation):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, project.ErrNotFound):
		writeError(w, http.StatusNotFound, "project not found")
	case errors.Is(err, project.ErrConflict):
		writeError(w, http.StatusConflict, "project already exists")
	default:
		writeError(
			w,
			http.StatusInternalServerError,
			"project operation failed",
		)
	}
}
