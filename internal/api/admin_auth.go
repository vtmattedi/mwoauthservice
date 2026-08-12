package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

const maxAdminAuthBody = 1 << 20

type adminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type adminAuthResponse struct {
	User      domain.AdminUser `json:"user"`
	CSRFToken string           `json:"csrf_token,omitempty"`
	ExpiresAt string           `json:"expires_at,omitempty"`
}

type csrfResponse struct {
	CSRFToken string `json:"csrf_token"`
}

func AdminLogin(service *admin.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request adminLoginRequest
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		request.Email = strings.TrimSpace(request.Email)
		if request.Email == "" || request.Password == "" {
			writeError(
				w,
				http.StatusBadRequest,
				"email and password are required",
			)
			return
		}

		user, sessionToken, csrfToken, expiresAt, err :=
			service.Login(
				r.Context(),
				request.Email,
				request.Password,
			)
		if err != nil {
			if errors.Is(err, admin.ErrUnauthorized) {
				writeError(
					w,
					http.StatusUnauthorized,
					"invalid credentials",
				)
				return
			}

			writeError(
				w,
				http.StatusInternalServerError,
				"could not create admin session",
			)
			return
		}

		service.SetSessionCookie(
			w,
			sessionToken,
			expiresAt,
		)

		writeJSON(
			w,
			http.StatusOK,
			adminAuthResponse{
				User:      user,
				CSRFToken: csrfToken,
				ExpiresAt: expiresAt.Format(time.RFC3339),
			},
		)
	}
}

func AdminMe() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authCtx, ok := admin.Current(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			adminAuthResponse{
				User: authCtx.User,
			},
		)
	}
}

func AdminCSRF(service *admin.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authCtx, ok := admin.Current(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		token, err := service.RotateCSRF(
			r.Context(),
			authCtx.Session.TokenHash,
		)
		if err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				"could not rotate csrf token",
			)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			csrfResponse{
				CSRFToken: token,
			},
		)
	}
}

func AdminLogout(service *admin.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authCtx, ok := admin.Current(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		if err := service.Logout(
			r.Context(),
			authCtx.Session.TokenHash,
		); err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				"could not end admin session",
			)
			return
		}

		service.ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

func decodeAdminJSON(
	w http.ResponseWriter,
	r *http.Request,
	target any,
) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminAuthBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple or invalid json values")
	}

	return nil
}
