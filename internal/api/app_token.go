package api

import (
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

const (
	maxTokenRequestBody = 8 << 10
	maxClientIDLogChars = 64
)

// TokenLimits are the flood guards for POST /v1/auth/token. Any may be nil.
type TokenLimits struct {
	// PerClient bounds every request naming one client ID.
	PerClient *appauth.Limiter
	// Failures bounds failed authentications per client ID; once exceeded,
	// even a correct secret is refused until the window resets.
	Failures *appauth.Limiter
	// PerSource is a coarse guard per remote address.
	PerSource *appauth.Limiter
}

// DefaultTokenLimits returns conservative defaults.
func DefaultTokenLimits() TokenLimits {
	return TokenLimits{
		PerClient: appauth.NewLimiter(30, time.Minute, 10000),
		Failures:  appauth.NewLimiter(10, 5*time.Minute, 10000),
		PerSource: appauth.NewLimiter(600, time.Minute, 10000),
	}
}

// TokenResponse is the RFC 6749 section 5.1 success body.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// tokenError is the RFC 6749 section 5.2 error body. Descriptions are fixed
// strings: nothing from the request is echoed back.
type tokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// TokenEndpoint serves the client credentials grant:
//
//	POST /v1/auth/token
//	Authorization: Basic base64(client_id:client_secret)
//	Content-Type: application/x-www-form-urlencoded
//
//	grant_type=client_credentials&scope=google.authorize google.refresh
func TokenEndpoint(
	service *appauth.Service,
	auditService *audit.Service,
	limits TokenLimits,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Responses carry credentials or reveal their state: never cache.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		reject := func(status int, code, description, reason string, projectID *int64, clientID string) {
			recordTokenAudit(r, auditService, "oauth.client.token_rejected", "rejected", "warning",
				projectID, status, reason, clientID)
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", `Basic realm="mw-oauth", charset="UTF-8"`)
			}
			writeJSON(w, status, tokenError{Error: code, ErrorDescription: description})
		}

		// Credentials must not travel in the URL.
		if r.URL.RawQuery != "" {
			reject(http.StatusBadRequest, "invalid_request",
				"parameters must be sent in the request body", "query_not_allowed", nil, "")
			return
		}

		if limits.PerSource != nil {
			if ok, retry := limits.PerSource.Allow(requestRemoteIP(r)); !ok {
				tooManyTokenRequests(w, retry)
				return
			}
		}

		clientID, clientSecret, err := parseBasicCredentials(r.Header.Values("Authorization"))
		if err != nil {
			reject(http.StatusUnauthorized, "invalid_client",
				"client authentication failed", "invalid_basic_credentials", nil, "")
			return
		}

		if limits.PerClient != nil {
			if ok, retry := limits.PerClient.Allow(clientID); !ok {
				tooManyTokenRequests(w, retry)
				return
			}
		}

		// Failures are tracked per client and source, so someone who only
		// knows the public client ID cannot lock the real client out from a
		// different address. Behind a shared proxy address this degrades to
		// per-client.
		failureKey := clientID + "|" + requestRemoteIP(r)
		if limits.Failures != nil {
			if exceeded, retry := limits.Failures.Exceeded(failureKey); exceeded {
				tooManyTokenRequests(w, retry)
				return
			}
		}

		if !isFormContentType(r.Header.Get("Content-Type")) {
			reject(http.StatusBadRequest, "invalid_request",
				"Content-Type must be application/x-www-form-urlencoded", "invalid_content_type", nil, clientID)
			return
		}

		form, err := readTokenForm(w, r)
		if err != nil {
			reject(http.StatusBadRequest, "invalid_request",
				"invalid request body", "invalid_body", nil, clientID)
			return
		}

		// Credentials are accepted only through HTTP Basic; a second place
		// would make authentication ambiguous.
		if _, ok := form["client_secret"]; ok {
			reject(http.StatusBadRequest, "invalid_request",
				"client credentials must be sent using HTTP Basic authentication", "ambiguous_credentials", nil, clientID)
			return
		}
		if _, ok := form["client_id"]; ok {
			reject(http.StatusBadRequest, "invalid_request",
				"client credentials must be sent using HTTP Basic authentication", "ambiguous_credentials", nil, clientID)
			return
		}

		grantType, ok := singleFormValue(form, "grant_type")
		if !ok {
			reject(http.StatusBadRequest, "invalid_request",
				"grant_type is required and must appear once", "invalid_grant_type_param", nil, clientID)
			return
		}
		if grantType != "client_credentials" {
			reject(http.StatusBadRequest, "unsupported_grant_type",
				"only client_credentials is supported", "unsupported_grant_type", nil, clientID)
			return
		}

		var scopes []string
		if values, present := form["scope"]; present {
			if len(values) != 1 {
				reject(http.StatusBadRequest, "invalid_request",
					"scope must appear at most once", "invalid_scope_param", nil, clientID)
				return
			}
			scopes = strings.Fields(values[0])
		}

		token, err := service.IssueToken(r.Context(), clientID, clientSecret, scopes)
		if err != nil {
			switch {
			case errors.Is(err, appauth.ErrInvalidClient):
				if limits.Failures != nil {
					limits.Failures.Allow(failureKey)
				}
				reject(http.StatusUnauthorized, "invalid_client",
					"client authentication failed", "invalid_client", nil, clientID)
			case errors.Is(err, appauth.ErrClientDisabled),
				errors.Is(err, appauth.ErrProjectDisabled):
				reject(http.StatusForbidden, "unauthorized_client",
					"client is not permitted to obtain tokens", "client_disabled", nil, clientID)
			case errors.Is(err, appauth.ErrInvalidScope):
				reject(http.StatusBadRequest, "invalid_scope",
					"requested scope is not allowed for this client", "invalid_scope", nil, clientID)
			default:
				slog.ErrorContext(r.Context(), "token issuance failed",
					"request_id", RequestIDFromContext(r.Context()), "error", err)
				recordTokenAudit(r, auditService, "oauth.client.token_failed", "failed", "error",
					nil, http.StatusInternalServerError, "internal_error", clientID)
				writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
			}
			return
		}

		if limits.Failures != nil {
			limits.Failures.Reset(failureKey)
		}

		projectID := token.ProjectID
		recordTokenAudit(r, auditService, "oauth.client.token_issued", "completed", "info",
			&projectID, http.StatusOK, "issued", token.ClientID)

		writeJSON(w, http.StatusOK, tokenResponse{
			AccessToken: token.AccessToken,
			TokenType:   "Bearer",
			ExpiresIn:   token.ExpiresIn,
			Scope:       strings.Join(token.Scopes, " "),
		})
	}
}

func tooManyTokenRequests(w http.ResponseWriter, retry time.Duration) {
	seconds := int(math.Ceil(retry.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeJSON(w, http.StatusTooManyRequests, tokenError{
		Error:            "rate_limited",
		ErrorDescription: "too many token requests",
	})
}

func isFormContentType(raw string) bool {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
	return err == nil && strings.EqualFold(mediaType, "application/x-www-form-urlencoded")
}

func readTokenForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTokenRequestBody))
	if err != nil {
		return nil, err
	}
	return url.ParseQuery(string(body))
}

func singleFormValue(form url.Values, key string) (string, bool) {
	values := form[key]
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

// parseBasicCredentials parses RFC 7617 HTTP Basic credentials strictly:
// exactly one Authorization header, scheme "Basic", canonical base64, exactly
// one colon, and non-empty client ID and secret, each form-urlencoded as
// RFC 6749 section 2.3.1 requires.
func parseBasicCredentials(headers []string) (clientID, clientSecret string, err error) {
	if len(headers) != 1 {
		return "", "", errors.New("exactly one Authorization header is required")
	}

	scheme, payload, found := strings.Cut(strings.TrimSpace(headers[0]), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", errors.New("Basic authentication is required")
	}
	payload = strings.TrimSpace(payload)
	if payload == "" || strings.ContainsAny(payload, " \t") {
		return "", "", errors.New("malformed Basic credentials")
	}

	decoded, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		return "", "", errors.New("malformed Basic credentials")
	}

	rawID, rawSecret, found := strings.Cut(string(decoded), ":")
	if !found || strings.Contains(rawSecret, ":") {
		return "", "", errors.New("malformed Basic credentials")
	}

	clientID, err = url.QueryUnescape(rawID)
	if err != nil {
		return "", "", errors.New("malformed Basic credentials")
	}
	clientSecret, err = url.QueryUnescape(rawSecret)
	if err != nil {
		return "", "", errors.New("malformed Basic credentials")
	}
	if clientID == "" || clientSecret == "" {
		return "", "", errors.New("malformed Basic credentials")
	}

	return clientID, clientSecret, nil
}

func recordTokenAudit(
	r *http.Request,
	auditService *audit.Service,
	eventType string,
	status string,
	severity string,
	projectID *int64,
	httpStatus int,
	reason string,
	clientID string,
) {
	metadata := map[string]any{}
	if clientID != "" {
		if len(clientID) > maxClientIDLogChars {
			clientID = clientID[:maxClientIDLogChars]
		}
		metadata["mw_client_id"] = clientID
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
