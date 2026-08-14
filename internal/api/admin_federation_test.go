package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/federation"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

type apiIntrospectionStub struct {
	token federation.Token
	err   error
}

func (s apiIntrospectionStub) Introspect(context.Context, string) (federation.Token, error) {
	return s.token, s.err
}

func TestFederatedAdminRouteScopeOriginAndAudit(t *testing.T) {
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	adminService := admin.NewService(store, admin.Options{Origins: []string{"https://admin.example"}})
	auditService := audit.NewService(store)
	projectService := project.NewService(store, nil)
	token := federation.Token{
		Active: true, Subject: "usr_human", Audience: []string{"mw-oauth"},
		Scopes: []string{federation.ScopeProjectsRead}, AMR: []string{"webauthn"},
	}
	authenticator, err := federation.NewAuthenticator(federation.ModeHybrid, "mw-oauth", apiIntrospectionStub{token: token})
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(Dependencies{Build: buildinfo.Current(), Admin: adminService, Projects: projectService, Audit: auditService, Federation: authenticator})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/projects", nil)
	req.Header.Set("Authorization", "Bearer opaque")
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}

	page, err := auditService.List(t.Context(), domain.AuditFilters{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Metadata["actor_identity_sub"] != "usr_human" || page.Items[0].Metadata["authorized_scope"] != federation.ScopeProjectsRead {
		t.Fatalf("federated actor was not audited: %+v", page.Items)
	}
}

func TestFederatedAdminRouteMappingsRejectInsufficientScope(t *testing.T) {
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	adminService := admin.NewService(store, admin.Options{})
	projectService := project.NewService(store, nil)
	token := federation.Token{Active: true, Subject: "usr_human", Audience: []string{"mw-oauth"}, Scopes: []string{federation.ScopeProjectsRead}}
	authenticator, _ := federation.NewAuthenticator(federation.ModeHybrid, "mw-oauth", apiIntrospectionStub{token: token})
	router := NewRouter(Dependencies{Build: buildinfo.Current(), Admin: adminService, Projects: projectService, Federation: authenticator})

	for _, target := range []string{"/admin/api/projects/1/rotate-key", "/admin/api/projects/1/rotate-callback-secret"} {
		req := httptest.NewRequest(http.MethodPost, target, nil)
		req.Header.Set("Authorization", "Bearer opaque")
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d want=403", target, res.Code)
		}
	}
}

func TestFederatedModeDisablesLocalLogin(t *testing.T) {
	adminService := admin.NewService(nil, admin.Options{})
	authenticator, _ := federation.NewAuthenticator(federation.ModeFederated, "mw-oauth", apiIntrospectionStub{})
	router := NewRouter(Dependencies{Build: buildinfo.Current(), Admin: adminService, Federation: authenticator})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/auth/login", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code == http.StatusOK || res.Code == http.StatusUnauthorized {
		t.Fatalf("local login should be deliberately unavailable, status=%d", res.Code)
	}
}

func TestHybridLocalEndpointRejectsAuthorizationHeader(t *testing.T) {
	adminService := admin.NewService(nil, admin.Options{})
	authenticator, _ := federation.NewAuthenticator(federation.ModeHybrid, "mw-oauth", apiIntrospectionStub{})
	router := NewRouter(Dependencies{Build: buildinfo.Current(), Admin: adminService, Federation: authenticator})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/auth/login", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want=401", res.Code)
	}
}

func TestFederatedProjectDeletionEndpoint(t *testing.T) {
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	item := createAPIProject(t, store, "Delete through API", "api-delete")
	authTime := time.Unix(1700000000, 0).UTC()
	token := federation.Token{
		Active: true, Subject: "usr_control_plane",
		Audience: []string{"mw-oauth"},
		Scopes:   []string{federation.ScopeProjectsDelete},
		AuthTime: &authTime, AMR: []string{"webauthn"},
	}
	authenticator, _ := federation.NewAuthenticator(
		federation.ModeHybrid,
		"mw-oauth",
		apiIntrospectionStub{token: token},
	)
	projectService := project.NewService(store, nil)
	router := NewRouter(Dependencies{
		Build:      buildinfo.Current(),
		Admin:      admin.NewService(store, admin.Options{}),
		Projects:   projectService,
		Audit:      audit.NewService(store),
		Federation: authenticator,
	})

	request := httptest.NewRequest(
		http.MethodDelete,
		"/admin/api/projects/"+strconv.FormatInt(item.ID, 10),
		nil,
	)
	request.Header.Set("Authorization", "Bearer opaque")
	request.Header.Set("X-Request-ID", "req_control_plane_delete")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}

	page, err := audit.NewService(store).List(
		t.Context(),
		domain.AuditFilters{Limit: 10},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("audit count=%d want=1", len(page.Items))
	}
	event := page.Items[0]
	if event.EventType != "admin.project.deleted" ||
		event.RequestID != "req_control_plane_delete" ||
		event.Metadata["actor_identity_sub"] != "usr_control_plane" ||
		event.Metadata["project_id"] != float64(item.ID) ||
		event.Metadata["project_name"] != item.Name ||
		event.Metadata["authorized_scope"] != federation.ScopeProjectsDelete {
		t.Fatalf("unexpected audit event: %+v", event)
	}

	repeated := httptest.NewRequest(
		http.MethodDelete,
		"/admin/api/projects/"+strconv.FormatInt(item.ID, 10),
		nil,
	)
	repeated.Header.Set("Authorization", "Bearer opaque")
	repeatedResponse := httptest.NewRecorder()
	router.ServeHTTP(repeatedResponse, repeated)
	if repeatedResponse.Code != http.StatusNotFound {
		t.Fatalf("repeated delete status=%d want=404", repeatedResponse.Code)
	}
}

func TestProjectDeletionScopeAndDependencyConflict(t *testing.T) {
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	item := createAPIProject(t, store, "Retained API project", "api-retained")
	projectService := project.NewService(store, nil)
	adminService := admin.NewService(store, admin.Options{})

	readToken := federation.Token{
		Active: true, Subject: "usr_reader", Audience: []string{"mw-oauth"},
		Scopes: []string{federation.ScopeProjectsWrite},
	}
	readAuth, _ := federation.NewAuthenticator(
		federation.ModeHybrid, "mw-oauth", apiIntrospectionStub{token: readToken},
	)
	readRouter := NewRouter(Dependencies{
		Build: buildinfo.Current(), Admin: adminService,
		Projects: projectService, Federation: readAuth,
	})
	path := "/admin/api/projects/" + strconv.FormatInt(item.ID, 10)
	request := httptest.NewRequest(http.MethodDelete, path, nil)
	request.Header.Set("Authorization", "Bearer opaque")
	response := httptest.NewRecorder()
	readRouter.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing delete scope status=%d want=403", response.Code)
	}
	if _, err := projectService.Get(t.Context(), item.ID); err != nil {
		t.Fatalf("scope rejection deleted project: %v", err)
	}

	if _, err := store.DB().ExecContext(t.Context(), `
        CREATE TABLE retained_api_history (
            project_id INTEGER NOT NULL,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE RESTRICT
        );
        INSERT INTO retained_api_history(project_id) VALUES (?);
    `, item.ID); err != nil {
		t.Fatal(err)
	}
	deleteToken := federation.Token{
		Active: true, Subject: "usr_deleter", Audience: []string{"mw-oauth"},
		Scopes: []string{federation.ScopeProjectsDelete},
	}
	deleteAuth, _ := federation.NewAuthenticator(
		federation.ModeHybrid, "mw-oauth", apiIntrospectionStub{token: deleteToken},
	)
	deleteRouter := NewRouter(Dependencies{
		Build: buildinfo.Current(), Admin: adminService,
		Projects: projectService, Federation: deleteAuth,
	})
	request = httptest.NewRequest(http.MethodDelete, path, nil)
	request.Header.Set("Authorization", "Bearer opaque")
	response = httptest.NewRecorder()
	deleteRouter.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("dependency status=%d body=%s", response.Code, response.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["code"] != "project_has_dependencies" {
		t.Fatalf("code=%q", payload["code"])
	}
}

func createAPIProject(
	t *testing.T,
	store *sqlite.Store,
	name string,
	tokenHash string,
) domain.Project {
	t.Helper()
	item, err := store.CreateProject(t.Context(), project.CreateRecord{
		Name: name, Enabled: true, TokenHash: tokenHash,
		CallbackSecretCiphertext: "ciphertext-" + tokenHash,
		CallbackSecretNonce:      "nonce-" + tokenHash,
		CallbackSecretKeyVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return item
}
