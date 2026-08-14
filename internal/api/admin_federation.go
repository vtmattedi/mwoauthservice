package api

import (
	"net/http"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/federation"
)

func adminAuthorized(
	authenticator *federation.Authenticator,
	adminService *admin.Service,
	auditService *audit.Service,
	requiredScope string,
	csrf bool,
	next http.Handler,
) http.Handler {
	audited := federatedActionAudit(auditService, requiredScope, next)
	localNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authContext, ok := admin.Current(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		id := authContext.User.ID
		principal := federation.Principal{Source: federation.SourceLocal, LocalAdminID: &id}
		audited.ServeHTTP(w, r.WithContext(federation.WithPrincipal(r.Context(), principal)))
	})

	var local http.Handler
	if csrf {
		local = adminService.SessionAndCSRF(localNext)
	} else {
		local = adminService.SessionOnly(localNext)
	}
	if authenticator == nil {
		return local
	}
	return authenticator.Require(requiredScope, local, audited)
}

func adminLocalOnly(authenticator *federation.Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authenticator != nil && authenticator.Mode() == federation.ModeFederated {
			http.NotFound(w, r)
			return
		}
		if len(r.Header.Values("Authorization")) > 0 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func federatedActionAudit(service *audit.Service, authorizedScope string, next http.Handler) http.Handler {
	if service == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := federation.Current(r.Context())
		if !ok || principal.Source != federation.SourceFederated || principal.IdentitySubject == nil {
			next.ServeHTTP(w, r)
			return
		}

		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		result := "completed"
		severity := "info"
		if status >= 400 {
			result, severity = "failed", "warning"
		}

		metadata := adminPrincipalAuditMetadata(
			principal,
			authorizedScope,
		)
		_, _ = service.Record(r.Context(), domain.AuditEvent{
			EventType: "admin.federated.operation", Status: result, Severity: severity,
			RequestID: RequestIDFromContext(r.Context()), Method: r.Method, Path: r.URL.Path,
			HTTPStatus: &status, Origin: r.Header.Get("Origin"), RemoteIP: requestRemoteIP(r),
			ReasonCode: "authorized", Metadata: metadata, AttemptCount: 1,
		})
	})
}

func adminPrincipalAuditMetadata(
	principal federation.Principal,
	authorizedScope string,
) map[string]any {
	metadata := map[string]any{
		"actor_type":       principal.Source,
		"authorized_scope": authorizedScope,
	}
	if principal.LocalAdminID != nil {
		metadata["local_admin_id"] = *principal.LocalAdminID
	}
	if principal.IdentitySubject != nil {
		metadata["actor_identity_sub"] = *principal.IdentitySubject
	}
	if principal.Audience != "" {
		metadata["delegated_audience"] = principal.Audience
	}
	if len(principal.AMR) > 0 {
		metadata["actor_amr"] = principal.AMR
	}
	if principal.AuthTime != nil {
		metadata["actor_auth_time"] = principal.AuthTime.UTC().Format(time.RFC3339)
	}
	return metadata
}
