package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/federation"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

// Admin routes for the two kinds of per-project credentials:
//
//   - the MW application client (client ID plus rotating client secrets), and
//   - the project's Google OAuth client (stored encrypted).
//
// Reads return metadata only. Secrets are returned exactly once, by the call
// that creates them, and never appear in audit entries or error bodies.

// AdminCredentialDeps are the services the credential routes need.
type AdminCredentialDeps struct {
	Projects *project.Service
	AppAuth  *appauth.Service
	Google   *googlecred.Service
	Audit    *audit.Service
}

type adminCodedError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeAdminCoded(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, adminCodedError{Error: message, Code: code})
}

// requireProject answers 404 itself when the project does not exist.
func requireProject(
	w http.ResponseWriter,
	r *http.Request,
	projects *project.Service,
) (int64, bool) {
	id, ok := adminProjectID(w, r)
	if !ok {
		return 0, false
	}
	if _, err := projects.Get(r.Context(), id); err != nil {
		writeProjectError(w, err)
		return 0, false
	}
	return id, true
}

// decodeOptionalAdminJSON accepts an empty body as "all defaults".
func decodeOptionalAdminJSON(w http.ResponseWriter, r *http.Request, target any) error {
	err := decodeAdminJSON(w, r, target)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func recordCredentialAudit(
	r *http.Request,
	service *audit.Service,
	projectID int64,
	eventType string,
	reason string,
	metadata map[string]any,
) {
	if service == nil {
		return
	}
	status := http.StatusOK
	if principal, ok := federation.Current(r.Context()); ok {
		merged := adminPrincipalAuditMetadata(principal, "")
		delete(merged, "authorized_scope")
		for key, value := range metadata {
			merged[key] = value
		}
		metadata = merged
	}
	_, _ = service.Record(r.Context(), domain.AuditEvent{
		EventType:    eventType,
		Status:       "completed",
		Severity:     "info",
		ProjectID:    &projectID,
		RequestID:    RequestIDFromContext(r.Context()),
		Method:       r.Method,
		Path:         r.URL.Path,
		HTTPStatus:   &status,
		Origin:       r.Header.Get("Origin"),
		RemoteIP:     requestRemoteIP(r),
		ReasonCode:   reason,
		Metadata:     metadata,
		AttemptCount: 1,
	})
}

// --- MW application client ------------------------------------------------

type adminClientCreateRequest struct {
	DisplayName   string   `json:"display_name"`
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
}

type adminClientSecretResponse struct {
	Client       appauth.Client      `json:"client"`
	Secret       *appauth.SecretInfo `json:"secret,omitempty"`
	ClientSecret string              `json:"client_secret"`
}

type adminTokensRevokeRequest struct {
	SecretID *int64 `json:"secret_id,omitempty"`
}

func writeAppAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, appauth.ErrNotFound):
		writeAdminCoded(w, http.StatusNotFound, "client_not_found",
			"application client not found")
	case errors.Is(err, appauth.ErrConflict):
		writeAdminCoded(w, http.StatusConflict, "configuration_conflict",
			"application client already exists")
	case errors.Is(err, appauth.ErrTooManySecrets):
		writeAdminCoded(w, http.StatusConflict, "too_many_active_secrets",
			"revoke an active client secret before adding another")
	case errors.Is(err, appauth.ErrValidation), errors.Is(err, appauth.ErrInvalidScope):
		writeAdminCoded(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		writeAdminCoded(w, http.StatusInternalServerError, "internal_error",
			"application client operation failed")
	}
}

func AdminClientGet(deps AdminCredentialDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireProject(w, r, deps.Projects)
		if !ok {
			return
		}
		client, err := deps.AppAuth.Get(r.Context(), id)
		if err != nil {
			writeAppAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, client)
	}
}

// AdminClientSecretCreate creates the project's client on first use and adds
// an overlapping secret afterwards. The secret is in this response only.
func AdminClientSecretCreate(deps AdminCredentialDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireProject(w, r, deps.Projects)
		if !ok {
			return
		}
		var request adminClientCreateRequest
		if err := decodeOptionalAdminJSON(w, r, &request); err != nil {
			writeAdminCoded(w, http.StatusBadRequest, "invalid_request", "invalid request")
			return
		}

		existing, err := deps.AppAuth.Get(r.Context(), id)
		switch {
		case err == nil:
			added, err := deps.AppAuth.AddSecret(r.Context(), id)
			if err != nil {
				writeAppAuthError(w, err)
				return
			}
			client, err := deps.AppAuth.Get(r.Context(), id)
			if err != nil {
				client = existing
			}
			recordCredentialAudit(r, deps.Audit, id, "oauth.client.credential_rotated",
				"secret_added", map[string]any{
					"client_id": client.ClientID, "secret_id": added.Secret.ID,
				})
			writeJSON(w, http.StatusCreated, adminClientSecretResponse{
				Client: client, Secret: &added.Secret, ClientSecret: added.ClientSecret,
			})
		case errors.Is(err, appauth.ErrNotFound):
			name := strings.TrimSpace(request.DisplayName)
			if name == "" {
				if p, perr := deps.Projects.Get(r.Context(), id); perr == nil {
					name = p.Name
				}
			}
			created, err := deps.AppAuth.CreateClient(
				r.Context(), id, name, request.AllowedScopes,
			)
			if err != nil {
				writeAppAuthError(w, err)
				return
			}
			recordCredentialAudit(r, deps.Audit, id, "oauth.client.created",
				"client_created", map[string]any{"client_id": created.Client.ClientID})
			writeJSON(w, http.StatusCreated, adminClientSecretResponse{
				Client: created.Client, ClientSecret: created.ClientSecret,
			})
		default:
			writeAppAuthError(w, err)
		}
	}
}

func AdminClientSecretRevoke(deps AdminCredentialDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireProject(w, r, deps.Projects)
		if !ok {
			return
		}
		secretID, ok := parsePositiveInt(r.PathValue("credentialID"))
		if !ok {
			writeAdminCoded(w, http.StatusBadRequest, "invalid_request",
				"invalid credential id")
			return
		}
		info, err := deps.AppAuth.RevokeSecret(r.Context(), id, secretID)
		if err != nil {
			writeAppAuthError(w, err)
			return
		}
		recordCredentialAudit(r, deps.Audit, id, "oauth.client.revoked",
			"secret_revoked", map[string]any{"secret_id": info.ID})
		writeJSON(w, http.StatusOK, info)
	}
}

func AdminClientTokensRevoke(deps AdminCredentialDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireProject(w, r, deps.Projects)
		if !ok {
			return
		}
		var request adminTokensRevokeRequest
		if err := decodeOptionalAdminJSON(w, r, &request); err != nil {
			writeAdminCoded(w, http.StatusBadRequest, "invalid_request", "invalid request")
			return
		}
		if request.SecretID != nil && *request.SecretID <= 0 {
			writeAdminCoded(w, http.StatusBadRequest, "invalid_request",
				"invalid secret id")
			return
		}
		if _, err := deps.AppAuth.Get(r.Context(), id); err != nil {
			writeAppAuthError(w, err)
			return
		}
		revoked, err := deps.AppAuth.RevokeTokens(r.Context(), id, request.SecretID)
		if err != nil {
			writeAppAuthError(w, err)
			return
		}
		recordCredentialAudit(r, deps.Audit, id, "oauth.client.tokens_revoked",
			"tokens_revoked", map[string]any{"revoked": revoked})
		writeJSON(w, http.StatusOK, map[string]int64{"revoked": revoked})
	}
}

// --- Google OAuth client ---------------------------------------------------

type adminGoogleClientPutRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type adminGoogleClientListResponse struct {
	Credentials []domain.GoogleCredential `json:"credentials"`
	// ActiveRef is the credential used for new authorizations, if any.
	ActiveRef string `json:"active_ref,omitempty"`
}

type adminGoogleTransitionRequest struct {
	Confirm bool `json:"confirm"`
}

func writeGoogleCredError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, googlecred.ErrNotConfigured):
		writeAdminCoded(w, http.StatusServiceUnavailable, "google_client_unavailable",
			"google client storage is not configured")
	case errors.Is(err, googlecred.ErrProjectNotFound):
		writeAdminCoded(w, http.StatusNotFound, "project_not_found", "project not found")
	case errors.Is(err, googlecred.ErrNotFound):
		writeAdminCoded(w, http.StatusNotFound, "credential_not_found",
			"credential not found")
	case errors.Is(err, googlecred.ErrInvalidTransition):
		writeAdminCoded(w, http.StatusConflict, "configuration_conflict",
			"the credential is not in a state that allows this change")
	case errors.Is(err, googlecred.ErrValidation):
		// The validation errors describe the field, never its value.
		writeAdminCoded(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		writeAdminCoded(w, http.StatusInternalServerError, "internal_error",
			"google client operation failed")
	}
}

func AdminGoogleClientGet(deps AdminCredentialDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireProject(w, r, deps.Projects)
		if !ok {
			return
		}
		list, err := deps.Google.List(r.Context(), id)
		if err != nil {
			writeGoogleCredError(w, err)
			return
		}
		if list == nil {
			list = []domain.GoogleCredential{}
		}
		response := adminGoogleClientListResponse{Credentials: list}
		for _, credential := range list {
			if credential.State == domain.GoogleCredentialActive {
				response.ActiveRef = credential.ID
			}
		}
		writeJSON(w, http.StatusOK, response)
	}
}

// AdminGoogleClientPut stores a new active Google client; an existing active
// one becomes retiring. The submitted secret is never echoed.
func AdminGoogleClientPut(deps AdminCredentialDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireProject(w, r, deps.Projects)
		if !ok {
			return
		}
		var request adminGoogleClientPutRequest
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeAdminCoded(w, http.StatusBadRequest, "invalid_request", "invalid request")
			return
		}

		result, err := deps.Google.Configure(
			r.Context(), id, request.ClientID, request.ClientSecret,
		)
		if err != nil {
			writeGoogleCredError(w, err)
			return
		}

		metadata := map[string]any{
			"credential_ref": result.Credential.ID,
			"client_id":      result.Credential.ClientID,
		}
		if result.Retired != nil {
			metadata["retired_ref"] = result.Retired.ID
		}
		recordCredentialAudit(r, deps.Audit, id, "oauth.google.credential_created",
			"credential_created", metadata)
		writeJSON(w, http.StatusOK, result)
	}
}

func AdminGoogleClientImpact(deps AdminCredentialDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireProject(w, r, deps.Projects)
		if !ok {
			return
		}
		impact, err := deps.Google.Impact(r.Context(), id, r.PathValue("credentialRef"))
		if err != nil {
			writeGoogleCredError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, impact)
	}
}

// adminGoogleTransition retires or disables a credential. Both change what
// existing consumers can do, so the caller must confirm; without
// {"confirm": true} the impact is returned with 409 confirmation_required.
func adminGoogleTransition(
	deps AdminCredentialDeps,
	eventType string,
	reason string,
	apply func(context.Context, int64, string) (domain.GoogleCredential, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireProject(w, r, deps.Projects)
		if !ok {
			return
		}
		ref := r.PathValue("credentialRef")

		var request adminGoogleTransitionRequest
		if err := decodeOptionalAdminJSON(w, r, &request); err != nil {
			writeAdminCoded(w, http.StatusBadRequest, "invalid_request", "invalid request")
			return
		}

		if !request.Confirm {
			impact, err := deps.Google.Impact(r.Context(), id, ref)
			if err != nil {
				writeGoogleCredError(w, err)
				return
			}
			writeJSON(w, http.StatusConflict, struct {
				adminCodedError
				Impact googlecred.Impact `json:"impact"`
			}{
				adminCodedError{
					Error: "confirm the change after reviewing its impact",
					Code:  "confirmation_required",
				},
				impact,
			})
			return
		}

		updated, err := apply(r.Context(), id, ref)
		if err != nil {
			writeGoogleCredError(w, err)
			return
		}
		recordCredentialAudit(r, deps.Audit, id, eventType, reason, map[string]any{
			"credential_ref": updated.ID,
		})
		writeJSON(w, http.StatusOK, updated)
	}
}

func AdminGoogleClientRetire(deps AdminCredentialDeps) http.HandlerFunc {
	return adminGoogleTransition(
		deps, "oauth.google.credential_retired", "credential_retired", deps.Google.Retire,
	)
}

func AdminGoogleClientDisable(deps AdminCredentialDeps) http.HandlerFunc {
	return adminGoogleTransition(
		deps, "oauth.google.credential_disabled", "credential_disabled", deps.Google.Disable,
	)
}

// --- Project summary --------------------------------------------------------

type adminProjectSummary struct {
	domain.Project
	// GoogleEnabled is the project's Google policy switch.
	GoogleEnabled bool `json:"google_enabled"`
	// GoogleClient is "none", "active", "retiring_only" or "disabled_only".
	GoogleClient string `json:"google_client"`
	// StatusError is true when the Google status could not be read, so the UI
	// never shows an unreadable status as "disabled".
	StatusError bool `json:"status_error,omitempty"`
}

type adminProjectSummaryResponse struct {
	Projects []adminProjectSummary `json:"projects"`
}

// AdminProjectsSummary returns every project with its setup state in one
// call, so the project list does not need one request per project.
func AdminProjectsSummary(deps AdminCredentialDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		projects, err := deps.Projects.List(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list projects")
			return
		}

		items := make([]adminProjectSummary, 0, len(projects))
		for _, p := range projects {
			item := adminProjectSummary{Project: p, GoogleClient: "none"}

			config, err := deps.Projects.GoogleConfig(r.Context(), p.ID)
			if err != nil {
				item.StatusError = true
			} else {
				item.GoogleEnabled = config.Enabled
			}

			list, err := deps.Google.List(r.Context(), p.ID)
			if err != nil {
				item.StatusError = true
			} else {
				item.GoogleClient = summarizeGoogleClient(list)
			}
			items = append(items, item)
		}

		writeJSON(w, http.StatusOK, adminProjectSummaryResponse{Projects: items})
	}
}

func summarizeGoogleClient(list []domain.GoogleCredential) string {
	var retiring, disabled bool
	for _, credential := range list {
		switch credential.State {
		case domain.GoogleCredentialActive:
			return "active"
		case domain.GoogleCredentialRetiring:
			retiring = true
		case domain.GoogleCredentialDisabled:
			disabled = true
		}
	}
	switch {
	case retiring:
		return "retiring_only"
	case disabled:
		return "disabled_only"
	}
	return "none"
}

func parsePositiveInt(raw string) (int64, bool) {
	var value int64
	if raw == "" {
		return 0, false
	}
	for _, c := range raw {
		if c < '0' || c > '9' || value > (1<<62)/10 {
			return 0, false
		}
		value = value*10 + int64(c-'0')
	}
	return value, value > 0
}
