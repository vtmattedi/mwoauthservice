package api

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
)

func GoogleOAuthCallback(
	callbackService *oauth.CallbackService,
	auditService *audit.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		outcome, err := callbackService.HandleGoogle(
			r.Context(),
			oauth.GoogleCallbackInput{
				State:         r.URL.Query().Get("state"),
				Code:          r.URL.Query().Get("code"),
				ProviderError: r.URL.Query().Get("error"),
			},
		)

		if err == nil {
			recordCallbackAudit(
				r,
				auditService,
				outcome,
				"oauth.authorization.completed",
				"completed",
				"info",
				"completed",
				http.StatusSeeOther,
			)

			redirectCallbackResult(
				w,
				r,
				outcome,
			)
			return
		}

		switch {
		case errors.Is(err, oauth.ErrProviderDenied):
			recordCallbackAudit(
				r,
				auditService,
				outcome,
				"oauth.provider.denied",
				"denied",
				"info",
				"access_denied",
				http.StatusSeeOther,
			)
			redirectCallbackResult(w, r, outcome)
			return

		case errors.Is(err, oauth.ErrTransactionExpired):
			recordCallbackAudit(
				r,
				auditService,
				outcome,
				"oauth.provider.transaction_expired",
				"failed",
				"warning",
				"transaction_expired",
				http.StatusSeeOther,
			)
			redirectCallbackResult(w, r, outcome)
			return

		case errors.Is(err, oauth.ErrCredentialUnavailable):
			recordCallbackAudit(
				r,
				auditService,
				outcome,
				"oauth.provider.credential_unavailable",
				"failed",
				"error",
				"credential_unavailable",
				http.StatusSeeOther,
			)
			redirectCallbackResult(w, r, outcome)
			return

		case errors.Is(err, oauth.ErrProviderExchangeFailed):
			recordCallbackAudit(
				r,
				auditService,
				outcome,
				"oauth.provider.exchange_failed",
				"failed",
				"error",
				"provider_exchange_failed",
				http.StatusSeeOther,
			)
			redirectCallbackResult(w, r, outcome)
			return

		case errors.Is(err, oauth.ErrDeliveryFailed):
			recordCallbackAudit(
				r,
				auditService,
				outcome,
				"oauth.delivery.failed",
				"failed",
				"error",
				"delivery_failed",
				http.StatusSeeOther,
			)
			redirectCallbackResult(w, r, outcome)
			return

		case errors.Is(err, oauth.ErrTemporaryFailure):
			slog.WarnContext(
				r.Context(),
				"Google OAuth callback temporarily failed",
				"request_id", RequestIDFromContext(r.Context()),
				"transaction_id", outcome.TransactionID,
				"project_id", outcome.ProjectID,
				"error", err,
			)
			// The authorization is still pending; the same URL can be retried.
			w.Header().Set("Retry-After", "5")
			writePublicOAuthError(
				w,
				http.StatusServiceUnavailable,
				"temporarily_unavailable",
				"the callback could not be completed right now; try again",
			)
			return

		case errors.Is(err, oauth.ErrTransactionNotFound),
			errors.Is(err, oauth.ErrTransactionConsumed),
			errors.Is(err, oauth.ErrInvalidCallback):
			recordInvalidCallbackAudit(
				r,
				auditService,
				err,
			)

			writePublicOAuthError(
				w,
				http.StatusBadRequest,
				"invalid_callback",
				"invalid or expired OAuth callback",
			)
			return

		default:
			slog.ErrorContext(
				r.Context(),
				"Google OAuth callback failed",
				"request_id",
				RequestIDFromContext(r.Context()),
				"transaction_id",
				outcome.TransactionID,
				"project_id",
				outcome.ProjectID,
				"error",
				err,
			)

			writePublicOAuthError(
				w,
				http.StatusInternalServerError,
				"internal_error",
				"OAuth callback failed",
			)
		}
	}
}

func redirectCallbackResult(
	w http.ResponseWriter,
	r *http.Request,
	outcome oauth.CallbackOutcome,
) {
	if strings.TrimSpace(outcome.ReturnURL) == "" {
		writePublicOAuthError(
			w,
			http.StatusBadRequest,
			"invalid_callback",
			"OAuth callback has no trusted return URL",
		)
		return
	}

	target, err := url.Parse(outcome.ReturnURL)
	if err != nil ||
		!target.IsAbs() ||
		target.Host == "" {
		writePublicOAuthError(
			w,
			http.StatusInternalServerError,
			"invalid_return_url",
			"trusted return URL is invalid",
		)
		return
	}

	query := target.Query()
	query.Set("mw_oauth_status", outcome.Status)
	query.Set(
		"mw_oauth_transaction_id",
		outcome.TransactionID,
	)
	target.RawQuery = query.Encode()

	http.Redirect(
		w,
		r,
		target.String(),
		http.StatusSeeOther,
	)
}

func recordCallbackAudit(
	r *http.Request,
	auditService *audit.Service,
	outcome oauth.CallbackOutcome,
	eventType string,
	status string,
	severity string,
	reasonCode string,
	httpStatusValue int,
) {
	if auditService == nil {
		return
	}

	projectID := outcome.ProjectID
	httpStatus := httpStatusValue

	_, err := auditService.Record(
		r.Context(),
		domain.AuditEvent{
			EventType:     eventType,
			Status:        status,
			Severity:      severity,
			ProjectID:     &projectID,
			TransactionID: outcome.TransactionID,
			RequestID:     RequestIDFromContext(r.Context()),
			Method:        r.Method,
			Path:          r.URL.Path,
			HTTPStatus:    &httpStatus,
			RemoteIP:      requestRemoteIP(r),
			ReasonCode:    reasonCode,
			AttemptCount:  1,
		},
	)
	if err != nil {
		slog.ErrorContext(
			r.Context(),
			"could not persist callback audit event",
			"request_id",
			RequestIDFromContext(r.Context()),
			"event_type",
			eventType,
			"error",
			err,
		)
	}
}

func recordInvalidCallbackAudit(
	r *http.Request,
	auditService *audit.Service,
	callbackErr error,
) {
	if auditService == nil {
		return
	}

	reasonCode := "invalid_state"
	eventType := "oauth.provider.callback_invalid_state"

	if errors.Is(
		callbackErr,
		oauth.ErrTransactionConsumed,
	) {
		reasonCode = "transaction_consumed"
	}
	if errors.Is(
		callbackErr,
		oauth.ErrInvalidCallback,
	) {
		reasonCode = "invalid_callback"
	}

	httpStatus := http.StatusBadRequest

	_, err := auditService.Record(
		r.Context(),
		domain.AuditEvent{
			EventType:    eventType,
			Status:       "failed",
			Severity:     "warning",
			RequestID:    RequestIDFromContext(r.Context()),
			Method:       r.Method,
			Path:         r.URL.Path,
			HTTPStatus:   &httpStatus,
			RemoteIP:     requestRemoteIP(r),
			ReasonCode:   reasonCode,
			AttemptCount: 1,
		},
	)
	if err != nil {
		slog.ErrorContext(
			r.Context(),
			"could not persist invalid callback audit event",
			"request_id",
			RequestIDFromContext(r.Context()),
			"error",
			err,
		)
	}
}
