package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/adminwebauthn"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

const (
	webAuthnCeremonyHeader = "X-MW-WebAuthn-Ceremony"
	maxWebAuthnBody        = 1 << 20
)

type webAuthnRegistrationRequest struct {
	Label string `json:"label"`
}

type webAuthnDeleteRequest struct {
	Password string `json:"password"`
}

type webAuthnOptionsResponse struct {
	CeremonyToken string `json:"ceremony_token"`
	Options       any    `json:"options"`
}

type webAuthnCredentialList struct {
	Items []adminwebauthn.CredentialSummary `json:"items"`
}

func AdminWebAuthnList(
	service *adminwebauthn.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authCtx, ok := admin.Current(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		items, err := service.ListCredentials(
			r.Context(),
			authCtx.User.ID,
		)
		if err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				"could not list passkeys",
			)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			webAuthnCredentialList{Items: items},
		)
	}
}

func AdminWebAuthnRegisterOptions(
	service *adminwebauthn.Service,
	auditService *audit.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authCtx, ok := admin.Current(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var request webAuthnRegistrationRequest
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		options, ceremonyToken, err :=
			service.BeginRegistration(
				r.Context(),
				authCtx.User,
				request.Label,
			)
		if err != nil {
			status := http.StatusInternalServerError
			message := "could not begin passkey registration"
			reason := "internal_error"

			if errors.Is(err, adminwebauthn.ErrInvalidLabel) {
				status = http.StatusBadRequest
				message = "invalid passkey label"
				reason = "invalid_label"
			}

			recordAdminWebAuthnAudit(
				r,
				auditService,
				authCtx.User.ID,
				"admin.webauthn.registration.failed",
				"failed",
				status,
				reason,
			)
			writeError(w, status, message)
			return
		}

		recordAdminWebAuthnAudit(
			r,
			auditService,
			authCtx.User.ID,
			"admin.webauthn.registration.started",
			"accepted",
			http.StatusOK,
			"started",
		)

		writeJSON(
			w,
			http.StatusOK,
			webAuthnOptionsResponse{
				CeremonyToken: ceremonyToken,
				Options:       options,
			},
		)
	}
}

func AdminWebAuthnRegisterVerify(
	service *adminwebauthn.Service,
	auditService *audit.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authCtx, ok := admin.Current(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		if !isJSONContentType(r.Header.Get("Content-Type")) {
			writeError(
				w,
				http.StatusUnsupportedMediaType,
				"Content-Type must be application/json",
			)
			return
		}

		ceremonyToken := strings.TrimSpace(
			r.Header.Get(webAuthnCeremonyHeader),
		)
		if ceremonyToken == "" {
			writeError(
				w,
				http.StatusBadRequest,
				"missing WebAuthn ceremony",
			)
			return
		}

		r.Body = http.MaxBytesReader(
			w,
			r.Body,
			maxWebAuthnBody,
		)

		credential, err := service.FinishRegistration(
			r.Context(),
			authCtx.User.ID,
			ceremonyToken,
			r,
		)
		if err != nil {
			status := http.StatusBadRequest
			reason := "verification_failed"
			eventType := "admin.webauthn.registration.failed"

			if ceremonyEvent, ceremonyReason, ok :=
				webAuthnCeremonyFailureAudit(err); ok {
				eventType = ceremonyEvent
				reason = ceremonyReason
			} else if !errors.Is(
				err,
				adminwebauthn.ErrVerification,
			) && !errors.Is(
				err,
				adminwebauthn.ErrConflict,
			) {
				status = http.StatusInternalServerError
				reason = "internal_error"
			}

			recordAdminWebAuthnAudit(
				r,
				auditService,
				authCtx.User.ID,
				eventType,
				"failed",
				status,
				reason,
			)
			writeError(
				w,
				status,
				"passkey registration could not be verified",
			)
			return
		}

		recordAdminWebAuthnAudit(
			r,
			auditService,
			authCtx.User.ID,
			"admin.webauthn.credential.registered",
			"completed",
			http.StatusCreated,
			"registered",
		)

		writeJSON(w, http.StatusCreated, credential)
	}
}

func AdminWebAuthnLoginOptions(
	service *adminwebauthn.Service,
	auditService *audit.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		options, ceremonyToken, err := service.BeginLogin(
			r.Context(),
		)
		if err != nil {
			recordAdminWebAuthnAudit(
				r,
				auditService,
				0,
				"admin.webauthn.login.failed",
				"failed",
				http.StatusInternalServerError,
				"begin_failed",
			)
			writeError(
				w,
				http.StatusInternalServerError,
				"could not begin passkey login",
			)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			webAuthnOptionsResponse{
				CeremonyToken: ceremonyToken,
				Options:       options,
			},
		)
	}
}

func AdminWebAuthnLoginVerify(
	webAuthnService *adminwebauthn.Service,
	adminService *admin.Service,
	auditService *audit.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isJSONContentType(r.Header.Get("Content-Type")) {
			writeError(
				w,
				http.StatusUnsupportedMediaType,
				"Content-Type must be application/json",
			)
			return
		}

		ceremonyToken := strings.TrimSpace(
			r.Header.Get(webAuthnCeremonyHeader),
		)
		if ceremonyToken == "" {
			writeError(
				w,
				http.StatusBadRequest,
				"missing WebAuthn ceremony",
			)
			return
		}

		r.Body = http.MaxBytesReader(
			w,
			r.Body,
			maxWebAuthnBody,
		)

		user, err := webAuthnService.FinishLogin(
			r.Context(),
			ceremonyToken,
			r,
		)
		if err != nil {
			status := http.StatusUnauthorized
			reason := "verification_failed"
			eventType := "admin.webauthn.login.failed"

			if ceremonyEvent, ceremonyReason, ok :=
				webAuthnCeremonyFailureAudit(err); ok {
				eventType = ceremonyEvent
				reason = ceremonyReason
			} else if !errors.Is(
				err,
				adminwebauthn.ErrVerification,
			) && !errors.Is(
				err,
				adminwebauthn.ErrDisabledAdmin,
			) {
				status = http.StatusInternalServerError
				reason = "internal_error"
			}

			recordAdminWebAuthnAudit(
				r,
				auditService,
				0,
				eventType,
				"failed",
				status,
				reason,
			)
			writeError(
				w,
				status,
				"passkey authentication failed",
			)
			return
		}

		user, sessionToken, csrfToken, expiresAt, err :=
			adminService.CreateSessionForUser(
				r.Context(),
				user.ID,
			)
		if err != nil {
			recordAdminWebAuthnAudit(
				r,
				auditService,
				user.ID,
				"admin.webauthn.login.failed",
				"failed",
				http.StatusInternalServerError,
				"session_failed",
			)
			writeError(
				w,
				http.StatusInternalServerError,
				"could not create admin session",
			)
			return
		}

		adminService.SetSessionCookie(
			w,
			sessionToken,
			expiresAt,
		)

		recordAdminWebAuthnAudit(
			r,
			auditService,
			user.ID,
			"admin.webauthn.login.completed",
			"completed",
			http.StatusOK,
			"authenticated",
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

func AdminWebAuthnDelete(
	webAuthnService *adminwebauthn.Service,
	adminService *admin.Service,
	auditService *audit.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authCtx, ok := admin.Current(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var request webAuthnDeleteRequest
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		if request.Password == "" {
			writeError(
				w,
				http.StatusBadRequest,
				"password confirmation is required",
			)
			return
		}

		if err := adminService.VerifyPasswordForUser(
			r.Context(),
			authCtx.User.ID,
			request.Password,
		); err != nil {
			recordAdminWebAuthnAudit(
				r,
				auditService,
				authCtx.User.ID,
				"admin.webauthn.credential.remove_failed",
				"failed",
				http.StatusUnauthorized,
				"password_confirmation_failed",
			)
			writeError(
				w,
				http.StatusUnauthorized,
				"password confirmation failed",
			)
			return
		}

		err := webAuthnService.RevokeCredential(
			r.Context(),
			authCtx.User.ID,
			r.PathValue("credential_id"),
		)
		if err != nil {
			if errors.Is(err, adminwebauthn.ErrNotFound) {
				writeError(
					w,
					http.StatusNotFound,
					"passkey not found",
				)
				return
			}

			writeError(
				w,
				http.StatusInternalServerError,
				"could not remove passkey",
			)
			return
		}

		recordAdminWebAuthnAudit(
			r,
			auditService,
			authCtx.User.ID,
			"admin.webauthn.credential.removed",
			"completed",
			http.StatusNoContent,
			"removed",
		)

		w.WriteHeader(http.StatusNoContent)
	}
}

func webAuthnCeremonyFailureAudit(
	err error,
) (eventType string, reason string, ok bool) {
	switch {
	case errors.Is(err, adminwebauthn.ErrCeremonyExpired):
		return "admin.webauthn.challenge.expired",
			"challenge_expired", true
	case errors.Is(err, adminwebauthn.ErrCeremonyUsed):
		return "admin.webauthn.challenge.replayed",
			"challenge_replayed", true
	case errors.Is(err, adminwebauthn.ErrInvalidCeremony):
		return "admin.webauthn.challenge.invalid",
			"challenge_invalid", true
	default:
		return "", "", false
	}
}

func recordAdminWebAuthnAudit(
	r *http.Request,
	service *audit.Service,
	adminUserID int64,
	eventType string,
	status string,
	httpStatus int,
	reasonCode string,
) {
	if service == nil {
		return
	}

	metadata := map[string]any{}
	if adminUserID > 0 {
		metadata["admin_user_id"] = adminUserID
	}

	_, _ = service.Record(
		r.Context(),
		domain.AuditEvent{
			EventType:    eventType,
			Status:       status,
			Severity:     webAuthnAuditSeverity(status),
			RequestID:    RequestIDFromContext(r.Context()),
			Method:       r.Method,
			Path:         r.URL.Path,
			HTTPStatus:   &httpStatus,
			Origin:       r.Header.Get("Origin"),
			RemoteIP:     requestRemoteIP(r),
			ReasonCode:   reasonCode,
			Metadata:     metadata,
			AttemptCount: 1,
		},
	)
}

func webAuthnAuditSeverity(status string) string {
	if status == "failed" {
		return "warning"
	}
	return "info"
}
