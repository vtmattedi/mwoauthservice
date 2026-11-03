package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/refresh"
)

const maxRefreshRequestBody = 8 << 10

type refreshRequestBody struct {
	CredentialRef string `json:"credential_ref"`
	RefreshToken  string `json:"refresh_token"`
}

type refreshResponse struct {
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	ExpiresIn   int64    `json:"expires_in"`
	Scope       []string `json:"scope"`
	// RefreshToken is present only when Google issued a replacement. When it
	// is absent the consumer must keep the refresh token it already has.
	RefreshToken string `json:"refresh_token,omitempty"`
}

// GoogleRefresh renews a Google access token:
//
//	POST /v1/oauth/google/refresh
//	Authorization: Bearer <MW access token with google.refresh>
//	{"credential_ref": "gcred_...", "refresh_token": "..."}
//
// The MW token only authenticates the caller to MW. The project, the Google
// client and the token endpoint are all decided server-side.
func GoogleRefresh(
	appAuth *appauth.Service,
	refresher *refresh.Service,
	auditService *audit.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()

		auditEvent := func(
			eventType, status, severity, reason string,
			httpStatus int,
			principal *appauth.Principal,
			credentialRef string,
		) {
			var projectID *int64
			metadata := map[string]any{
				"duration_ms": time.Since(started).Milliseconds(),
			}
			if principal != nil {
				id := principal.ProjectID
				projectID = &id
				metadata["mw_client_id"] = principal.ClientID
			}
			if credentialRef != "" && len(credentialRef) <= 64 {
				metadata["credential_ref"] = credentialRef
			}
			recordOAuthAudit(r, auditService, domain.AuditEvent{
				EventType:    eventType,
				Status:       status,
				Severity:     severity,
				ProjectID:    projectID,
				RequestID:    RequestIDFromContext(r.Context()),
				Method:       r.Method,
				Path:         r.URL.Path,
				HTTPStatus:   &httpStatus,
				Origin:       r.Header.Get("Origin"),
				RemoteIP:     requestRemoteIP(r),
				ReasonCode:   reason,
				AttemptCount: 1,
				Metadata:     metadata,
			})
		}

		rejectAuth := func(status int, code, message, challenge string, principal *appauth.Principal) {
			auditEvent("oauth.google.refresh_failed", "rejected", "warning", code, status, principal, "")
			if challenge != "" {
				w.Header().Set("WWW-Authenticate", challenge)
			}
			writePublicOAuthError(w, status, code, message)
		}

		rawToken, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			rejectAuth(http.StatusUnauthorized, "invalid_token",
				"a valid access token is required",
				`Bearer realm="mw-oauth", error="invalid_token"`, nil)
			return
		}

		// Only short-lived MW access tokens may refresh; the legacy project
		// API key cannot.
		principal, err := appAuth.Authenticate(r.Context(), rawToken)
		if err != nil {
			switch {
			case errors.Is(err, appauth.ErrInvalidToken):
				rejectAuth(http.StatusUnauthorized, "invalid_token",
					"invalid, expired or revoked access token",
					`Bearer realm="mw-oauth", error="invalid_token"`, nil)
			case errors.Is(err, appauth.ErrProjectDisabled):
				rejectAuth(http.StatusForbidden, "project_disabled", "project is disabled", "", nil)
			case errors.Is(err, appauth.ErrClientDisabled):
				rejectAuth(http.StatusForbidden, "client_disabled", "application client is disabled", "", nil)
			default:
				slog.ErrorContext(r.Context(), "refresh authentication failed",
					"request_id", RequestIDFromContext(r.Context()), "error", err)
				auditEvent("oauth.google.refresh_failed", "failed", "error", "internal_error",
					http.StatusInternalServerError, nil, "")
				writePublicOAuthError(w, http.StatusInternalServerError,
					"internal_error", "could not authenticate request")
			}
			return
		}

		if !principal.HasScope(appauth.ScopeGoogleRefresh) {
			rejectAuth(http.StatusForbidden, "insufficient_scope",
				"the access token does not grant "+appauth.ScopeGoogleRefresh,
				`Bearer realm="mw-oauth", error="insufficient_scope", scope="`+appauth.ScopeGoogleRefresh+`"`,
				&principal)
			return
		}

		if !isJSONContentType(r.Header.Get("Content-Type")) {
			auditEvent("oauth.google.refresh_failed", "rejected", "warning", "invalid_content_type",
				http.StatusBadRequest, &principal, "")
			writePublicOAuthError(w, http.StatusBadRequest, "invalid_request",
				"Content-Type must be application/json")
			return
		}

		var body refreshRequestBody
		if err := decodeStrictJSON(w, r, &body, maxRefreshRequestBody); err != nil {
			auditEvent("oauth.google.refresh_failed", "rejected", "warning", "invalid_body",
				http.StatusBadRequest, &principal, "")
			writePublicOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
			return
		}

		result, err := refresher.Refresh(r.Context(), principal.ProjectID, refresh.Request{
			CredentialRef: body.CredentialRef,
			RefreshToken:  body.RefreshToken,
		})
		// The refresh token is not needed past this point.
		body.RefreshToken = ""

		if err != nil {
			writeRefreshError(w, r, auditEvent, &principal, body.CredentialRef, err)
			return
		}

		auditEvent("oauth.google.refresh_succeeded", "completed", "info", "refreshed",
			http.StatusOK, &principal, body.CredentialRef)

		response := refreshResponse{
			AccessToken:  result.AccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    result.ExpiresIn,
			Scope:        result.Scopes,
			RefreshToken: result.RefreshToken,
		}
		if response.Scope == nil {
			response.Scope = []string{}
		}
		writeJSON(w, http.StatusOK, response)
	}
}

func writeRefreshError(
	w http.ResponseWriter,
	r *http.Request,
	auditEvent func(eventType, status, severity, reason string, httpStatus int, principal *appauth.Principal, credentialRef string),
	principal *appauth.Principal,
	credentialRef string,
	err error,
) {
	status := http.StatusInternalServerError
	code := "internal_error"
	message := "could not refresh the Google access token"
	reason := "internal_error"
	var retryAfter time.Duration

	var refreshErr *refresh.Error
	if errors.As(err, &refreshErr) {
		reason = refreshErr.Reason
		retryAfter = refreshErr.RetryAfter

		switch {
		case errors.Is(err, refresh.ErrInvalidRequest):
			status, code, message = http.StatusBadRequest, "invalid_request", "invalid refresh request"
		case errors.Is(err, refresh.ErrCredentialNotFound):
			status, code, message = http.StatusNotFound, "credential_not_found", "unknown credential_ref"
		case errors.Is(err, refresh.ErrCredentialUnavailable):
			status, code, message = http.StatusConflict, "credential_unavailable",
				"the Google client for this credential_ref is unavailable"
		case errors.Is(err, refresh.ErrReauthorizationRequired):
			status, code, message = http.StatusConflict, "reauthorization_required",
				"the Google connection must be authorized again"
		case errors.Is(err, refresh.ErrProviderRateLimited):
			status, code, message = http.StatusServiceUnavailable, "provider_rate_limited",
				"Google is rate limiting requests; retry later"
		case errors.Is(err, refresh.ErrProviderUnavailable):
			status, code, message = http.StatusBadGateway, "provider_unavailable",
				"Google could not be reached; retry later"
		case errors.Is(err, refresh.ErrRateLimited):
			status, code, message = http.StatusTooManyRequests, "rate_limited",
				"refresh rate limit exceeded"
		}
	} else if errors.Is(err, oauth.ErrProviderDisabled) {
		status, code, message, reason = http.StatusForbidden, "provider_disabled",
			"Google OAuth is disabled for this project", "provider_disabled"
	} else {
		slog.ErrorContext(r.Context(), "Google refresh failed",
			"request_id", RequestIDFromContext(r.Context()),
			"project_id", principal.ProjectID, "error", err)
	}

	if retryAfter > 0 {
		seconds := int(math.Ceil(retryAfter.Seconds()))
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}

	severity := "warning"
	outcome := "rejected"
	if status >= 500 {
		severity = "error"
		outcome = "failed"
	}
	auditEvent("oauth.google.refresh_failed", outcome, severity, reason, status, principal, credentialRef)

	writePublicOAuthError(w, status, code, message)
}

// decodeStrictJSON decodes exactly one JSON object, rejects unknown fields and
// bounds the body size.
func decodeStrictJSON(w http.ResponseWriter, r *http.Request, target any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)

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
