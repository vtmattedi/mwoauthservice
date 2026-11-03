package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
)

const maxOAuthAuthorizeBody = 1 << 20

type publicOAuthErrorResponse struct {
	Error publicOAuthError `json:"error"`
}

type publicOAuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// PublicGoogleAuthorize starts a Google authorization. The caller authenticates
// with a short-lived MW access token (mw_at_...) carrying the google.authorize
// scope, obtained from POST /v1/auth/token.
func PublicGoogleAuthorize(
	oauthService *oauth.Service,
	auditService *audit.Service,
	appAuth *appauth.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken, ok := bearerToken(
			r.Header.Get("Authorization"),
		)
		if !ok || !strings.HasPrefix(rawToken, appauth.TokenPrefix) {
			recordOAuthAudit(
				r,
				auditService,
				domain.AuditEvent{
					EventType:    "oauth.request.rejected.invalid_token",
					Status:       "rejected",
					Severity:     "warning",
					RequestID:    RequestIDFromContext(r.Context()),
					Method:       r.Method,
					Path:         r.URL.Path,
					Origin:       r.Header.Get("Origin"),
					RemoteIP:     requestRemoteIP(r),
					ReasonCode:   "invalid_token",
					AttemptCount: 1,
				},
			)

			w.Header().Set(
				"WWW-Authenticate",
				`Bearer realm="mw-oauth", error="invalid_token"`,
			)
			writePublicOAuthError(
				w,
				http.StatusUnauthorized,
				"invalid_token",
				"a valid access token is required",
			)
			return
		}

		authorizeWithAppToken(
			w, r, oauthService, auditService, appAuth, rawToken,
		)
	}
}

// authorizeWithAppToken authenticates a short-lived MW access token, requires
// the google.authorize scope, and then runs the normal authorization flow.
func authorizeWithAppToken(
	w http.ResponseWriter,
	r *http.Request,
	oauthService *oauth.Service,
	auditService *audit.Service,
	appAuth *appauth.Service,
	rawToken string,
) {
	reject := func(
		status int,
		code string,
		message string,
		eventType string,
		projectID *int64,
		challenge string,
	) {
		recordOAuthAudit(r, auditService, domain.AuditEvent{
			EventType:    eventType,
			Status:       "rejected",
			Severity:     "warning",
			ProjectID:    projectID,
			RequestID:    RequestIDFromContext(r.Context()),
			Method:       r.Method,
			Path:         r.URL.Path,
			HTTPStatus:   &status,
			Origin:       r.Header.Get("Origin"),
			RemoteIP:     requestRemoteIP(r),
			ReasonCode:   code,
			AttemptCount: 1,
		})
		if challenge != "" {
			w.Header().Set("WWW-Authenticate", challenge)
		}
		writePublicOAuthError(w, status, code, message)
	}

	principal, err := appAuth.Authenticate(r.Context(), rawToken)
	if err != nil {
		switch {
		case errors.Is(err, appauth.ErrInvalidToken):
			reject(http.StatusUnauthorized, "invalid_token",
				"invalid, expired or revoked access token",
				"oauth.request.rejected.invalid_token", nil,
				`Bearer realm="mw-oauth", error="invalid_token"`)
		case errors.Is(err, appauth.ErrProjectDisabled):
			reject(http.StatusForbidden, "project_disabled",
				"project is disabled",
				"oauth.request.rejected.disabled_project", nil, "")
		case errors.Is(err, appauth.ErrClientDisabled):
			reject(http.StatusForbidden, "client_disabled",
				"application client is disabled",
				"oauth.request.rejected.disabled_client", nil, "")
		default:
			recordInternalOAuthFailure(r, auditService, nil, "", err)
			writePublicOAuthError(w, http.StatusInternalServerError,
				"internal_error", "could not authenticate project")
		}
		return
	}

	projectID := principal.ProjectID
	if !principal.HasScope(appauth.ScopeGoogleAuthorize) {
		reject(http.StatusForbidden, "insufficient_scope",
			"the access token does not grant "+appauth.ScopeGoogleAuthorize,
			"oauth.request.rejected.insufficient_scope", &projectID,
			`Bearer realm="mw-oauth", error="insufficient_scope", scope="`+
				appauth.ScopeGoogleAuthorize+`"`)
		return
	}

	completeGoogleAuthorize(
		w, r, oauthService, auditService,
		domain.Project{ID: principal.ProjectID},
		principal.ClientID,
	)
}

// completeGoogleAuthorize decodes the request, starts the Google
// authorization and audits it, recording which MW client made the request.
func completeGoogleAuthorize(
	w http.ResponseWriter,
	r *http.Request,
	oauthService *oauth.Service,
	auditService *audit.Service,
	authenticatedProject domain.Project,
	mwClientID string,
) {
	var request oauth.GoogleAuthorizationRequest
	if err := decodeOAuthAuthorizeJSON(
		w,
		r,
		&request,
	); err != nil {
		projectID := authenticatedProject.ID
		recordOAuthAudit(
			r,
			auditService,
			domain.AuditEvent{
				EventType:    "oauth.request.rejected.invalid_body",
				Status:       "rejected",
				Severity:     "warning",
				ProjectID:    &projectID,
				RequestID:    RequestIDFromContext(r.Context()),
				Method:       r.Method,
				Path:         r.URL.Path,
				Origin:       r.Header.Get("Origin"),
				RemoteIP:     requestRemoteIP(r),
				ReasonCode:   "invalid_body",
				AttemptCount: 1,
				Metadata:     map[string]any{"mw_client_id": mwClientID},
			},
		)

		writePublicOAuthError(
			w,
			http.StatusBadRequest,
			"invalid_request",
			"invalid request body",
		)
		return
	}

	result, err := oauthService.AuthorizeGoogle(
		r.Context(),
		authenticatedProject,
		request,
	)
	if err != nil {
		handleGoogleAuthorizeError(
			w,
			r,
			auditService,
			authenticatedProject.ID,
			err,
		)
		return
	}

	projectID := authenticatedProject.ID
	status200 := http.StatusOK

	metadata := map[string]any{"mw_client_id": mwClientID}

	recordOAuthAudit(
		r,
		auditService,
		domain.AuditEvent{
			EventType:     "oauth.request.accepted",
			Status:        "accepted",
			Severity:      "info",
			ProjectID:     &projectID,
			TransactionID: result.TransactionID,
			RequestID:     RequestIDFromContext(r.Context()),
			Method:        r.Method,
			Path:          r.URL.Path,
			HTTPStatus:    &status200,
			Origin:        r.Header.Get("Origin"),
			RemoteIP:      requestRemoteIP(r),
			ReasonCode:    "accepted",
			AttemptCount:  1,
			Metadata:      metadata,
		},
	)

	writeJSON(w, http.StatusOK, result)
}

func handleGoogleAuthorizeError(
	w http.ResponseWriter,
	r *http.Request,
	auditService *audit.Service,
	projectIDValue int64,
	err error,
) {
	projectID := projectIDValue

	type mappedError struct {
		status     int
		code       string
		message    string
		eventType  string
		reasonCode string
		metadata   map[string]any
	}

	mapped := mappedError{
		status:     http.StatusInternalServerError,
		code:       "internal_error",
		message:    "could not create OAuth authorization",
		eventType:  "oauth.request.failed.internal",
		reasonCode: "internal_error",
	}

	switch {
	case errors.Is(err, oauth.ErrInvalidRequest):
		mapped.status = http.StatusBadRequest
		mapped.code = "invalid_request"
		mapped.message = "invalid OAuth authorization request"
		mapped.eventType = "oauth.request.rejected.invalid_body"
		mapped.reasonCode = "invalid_request"

	case errors.Is(err, oauth.ErrProviderDisabled):
		mapped.status = http.StatusForbidden
		mapped.code = "provider_disabled"
		mapped.message = "Google OAuth is disabled for this project"
		mapped.eventType = "oauth.request.rejected.disabled_provider"
		mapped.reasonCode = "disabled_provider"

	case errors.Is(err, oauth.ErrNoGoogleClient):
		mapped.status = http.StatusConflict
		mapped.code = "google_client_missing"
		mapped.message = "no Google OAuth client is configured for this project"
		mapped.eventType = "oauth.request.rejected.google_client_missing"
		mapped.reasonCode = "google_client_missing"

	case errors.Is(err, oauth.ErrGoogleClientUnavailable):
		mapped.status = http.StatusServiceUnavailable
		mapped.code = "google_client_unavailable"
		mapped.message = "the project's Google OAuth client is unavailable"
		mapped.eventType = "oauth.request.failed.google_client_unavailable"
		mapped.reasonCode = "google_client_unavailable"

	case errors.Is(err, oauth.ErrScopeNotAllowed):
		mapped.status = http.StatusForbidden
		mapped.code = "scope_not_allowed"
		mapped.message = "one or more requested scopes are not allowed"
		mapped.eventType = "oauth.request.rejected.scope_not_allowed"
		mapped.reasonCode = "scope_not_allowed"

	case errors.Is(err, oauth.ErrCallbackNotAllowed):
		mapped.status = http.StatusForbidden
		mapped.code = "callback_not_allowed"
		mapped.message = "callback_url is not allowed"
		mapped.eventType = "oauth.request.rejected.callback_not_allowed"
		mapped.reasonCode = "callback_not_allowed"

	case errors.Is(err, oauth.ErrReturnURLNotAllowed):
		mapped.status = http.StatusForbidden
		mapped.code = "return_url_not_allowed"
		mapped.message = "return_url is not allowed"
		mapped.eventType = "oauth.request.rejected.return_url_not_allowed"
		mapped.reasonCode = "return_url_not_allowed"

	default:
		var rateLimit *oauth.RateLimitError
		if errors.As(err, &rateLimit) {
			mapped.status = http.StatusTooManyRequests
			mapped.code = "rate_limited"
			mapped.message = "OAuth authorization rate limit exceeded"
			mapped.eventType = "oauth.request.rejected.rate_limited"
			mapped.reasonCode = "rate_limited"
			mapped.metadata = map[string]any{
				"limit_reason": rateLimit.Reason,
			}
		}
	}

	httpStatus := mapped.status
	severity := "warning"
	if mapped.status >= 500 {
		severity = "error"
	}

	recordOAuthAudit(
		r,
		auditService,
		domain.AuditEvent{
			EventType:    mapped.eventType,
			Status:       auditStatusForHTTP(mapped.status),
			Severity:     severity,
			ProjectID:    &projectID,
			RequestID:    RequestIDFromContext(r.Context()),
			Method:       r.Method,
			Path:         r.URL.Path,
			HTTPStatus:   &httpStatus,
			Origin:       r.Header.Get("Origin"),
			RemoteIP:     requestRemoteIP(r),
			ReasonCode:   mapped.reasonCode,
			AttemptCount: 1,
			Metadata:     mapped.metadata,
		},
	)

	if mapped.status >= 500 {
		slog.ErrorContext(
			r.Context(),
			"OAuth authorization request failed",
			"request_id",
			RequestIDFromContext(r.Context()),
			"project_id",
			projectID,
			"error",
			err,
		)
	}

	writePublicOAuthError(
		w,
		mapped.status,
		mapped.code,
		mapped.message,
	)
}

func recordInternalOAuthFailure(
	r *http.Request,
	auditService *audit.Service,
	projectID *int64,
	transactionID string,
	err error,
) {
	status := http.StatusInternalServerError

	recordOAuthAudit(
		r,
		auditService,
		domain.AuditEvent{
			EventType:     "oauth.request.failed.internal",
			Status:        "failed",
			Severity:      "error",
			ProjectID:     projectID,
			TransactionID: transactionID,
			RequestID:     RequestIDFromContext(r.Context()),
			Method:        r.Method,
			Path:          r.URL.Path,
			HTTPStatus:    &status,
			Origin:        r.Header.Get("Origin"),
			RemoteIP:      requestRemoteIP(r),
			ReasonCode:    "internal_error",
			AttemptCount:  1,
		},
	)

	slog.ErrorContext(
		r.Context(),
		"OAuth request failed",
		"request_id",
		RequestIDFromContext(r.Context()),
		"error",
		err,
	)
}

func recordOAuthAudit(
	r *http.Request,
	auditService *audit.Service,
	event domain.AuditEvent,
) {
	if auditService == nil {
		return
	}

	if _, err := auditService.Record(
		r.Context(),
		event,
	); err != nil {
		slog.ErrorContext(
			r.Context(),
			"could not persist OAuth audit event",
			"request_id",
			RequestIDFromContext(r.Context()),
			"event_type",
			event.EventType,
			"error",
			err,
		)
	}
}

func auditStatusForHTTP(status int) string {
	if status >= 500 {
		return "failed"
	}
	return "rejected"
}

func bearerToken(raw string) (string, bool) {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) != 2 ||
		!strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", false
	}

	return token, true
}

func decodeOAuthAuthorizeJSON(
	w http.ResponseWriter,
	r *http.Request,
	target any,
) error {
	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		maxOAuthAuthorizeBody,
	)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple or invalid JSON values")
	}

	return nil
}

func writePublicOAuthError(
	w http.ResponseWriter,
	status int,
	code string,
	message string,
) {
	writeJSON(
		w,
		status,
		publicOAuthErrorResponse{
			Error: publicOAuthError{
				Code:    code,
				Message: message,
			},
		},
	)
}

func requestRemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(
		strings.TrimSpace(r.RemoteAddr),
	)
	if err == nil {
		return host
	}

	return strings.TrimSpace(r.RemoteAddr)
}
