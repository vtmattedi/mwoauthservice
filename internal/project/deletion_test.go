package project_test

import (
	"errors"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

func TestDeleteProjectAtomicallyRevokesDataAndPreservesAudit(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	deletedProject := createStoredProject(t, store, "Delete Me", "hash-delete")
	otherProject := createStoredProject(t, store, "Keep Me", "hash-keep")
	if err := store.ReplaceGoogleOAuthConfig(t.Context(), deletedProject.ID, domain.GoogleOAuthConfig{
		Enabled:             true,
		AllowedScopes:       []string{"scope"},
		AllowedCallbackURLs: []string{"https://app.example/callback"},
		AllowedReturnURLs:   []string{"https://app.example/return"},
		Limits:              domain.OAuthLimits{PerMinute: 1, PerHour: 2, MaxPending: 3},
	}); err != nil {
		t.Fatal(err)
	}
	insertOAuthTransaction(t, store, deletedProject.ID)

	service := project.NewService(store, nil)
	removed, err := service.Delete(t.Context(), deletedProject.ID, deletionAudit("usr_delete"))
	if err != nil {
		t.Fatal(err)
	}
	if removed.ID != deletedProject.ID || removed.Name != deletedProject.Name {
		t.Fatalf("removed=%+v", removed)
	}
	if _, err := service.Get(t.Context(), deletedProject.ID); !errors.Is(err, project.ErrNotFound) {
		t.Fatalf("deleted project lookup err=%v", err)
	}
	if _, err := store.GetProjectByTokenHash(t.Context(), "hash-delete"); !errors.Is(err, project.ErrNotFound) {
		t.Fatalf("deleted API key hash still resolves: %v", err)
	}
	if kept, err := service.Get(t.Context(), otherProject.ID); err != nil || kept.Name != otherProject.Name {
		t.Fatalf("other project changed: project=%+v err=%v", kept, err)
	}

	for _, table := range []string{
		"project_oauth_configs",
		"project_oauth_scopes",
		"project_oauth_callback_urls",
		"project_oauth_return_urls",
		"oauth_transactions",
	} {
		var count int
		if err := store.DB().QueryRowContext(
			t.Context(),
			"SELECT COUNT(*) FROM "+table+" WHERE project_id = ?",
			deletedProject.ID,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d deleted-project rows", table, count)
		}
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
		event.Metadata["actor_identity_sub"] != "usr_delete" ||
		event.Metadata["project_name"] != deletedProject.Name ||
		event.Metadata["project_id"] != float64(deletedProject.ID) ||
		event.RequestID != "req_delete" || event.CreatedAt == "" {
		t.Fatalf("unexpected deletion audit: %+v", event)
	}

	if _, err := store.DB().ExecContext(
		t.Context(),
		`UPDATE audit_events SET status = 'tampered' WHERE id = ?`,
		event.ID,
	); err == nil {
		t.Fatal("project deletion audit allowed update")
	}
	if _, err := store.DB().ExecContext(
		t.Context(),
		`DELETE FROM audit_events WHERE id = ?`,
		event.ID,
	); err == nil {
		t.Fatal("project deletion audit allowed delete")
	}

	if _, err := service.Delete(t.Context(), deletedProject.ID, deletionAudit("usr_delete")); !errors.Is(err, project.ErrNotFound) {
		t.Fatalf("repeated deletion err=%v want not found", err)
	}
	page, err = audit.NewService(store).List(t.Context(), domain.AuditFilters{Limit: 10})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("repeat deletion changed audit: count=%d err=%v", len(page.Items), err)
	}
}

func TestDeleteProjectRollsBackWhenAuditCannotBeStored(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	item := createStoredProject(t, store, "Rollback", "hash-rollback")
	if _, err := store.DB().ExecContext(t.Context(), `
        CREATE TRIGGER reject_deletion_audit
        BEFORE INSERT ON audit_events
        WHEN NEW.event_type = 'admin.project.deleted'
        BEGIN
            SELECT RAISE(ABORT, 'test audit failure');
        END;
    `); err != nil {
		t.Fatal(err)
	}

	service := project.NewService(store, nil)
	if _, err := service.Delete(t.Context(), item.ID, deletionAudit("usr_delete")); err == nil {
		t.Fatal("expected deletion audit failure")
	}
	if _, err := service.Get(t.Context(), item.ID); err != nil {
		t.Fatalf("project deletion was not rolled back: %v", err)
	}
}

func TestDeleteProjectReturnsDependencyConflict(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	item := createStoredProject(t, store, "Retained", "hash-retained")
	if _, err := store.DB().ExecContext(t.Context(), `
        CREATE TABLE retained_project_history (
            project_id INTEGER NOT NULL,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE RESTRICT
        );
        INSERT INTO retained_project_history(project_id) VALUES (?);
    `, item.ID); err != nil {
		t.Fatal(err)
	}

	service := project.NewService(store, nil)
	if _, err := service.Delete(t.Context(), item.ID, deletionAudit("usr_delete")); !errors.Is(err, project.ErrDependencies) {
		t.Fatalf("err=%v want dependency conflict", err)
	}
	if _, err := service.Get(t.Context(), item.ID); err != nil {
		t.Fatalf("conflicted project was deleted: %v", err)
	}
}

func createStoredProject(
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

func insertOAuthTransaction(t *testing.T, store *sqlite.Store, projectID int64) {
	t.Helper()
	_, err := store.DB().ExecContext(t.Context(), `
        INSERT INTO oauth_transactions(
            id, project_id, provider, state_hash,
            pkce_verifier_ciphertext, pkce_verifier_nonce,
            client_reference, callback_url, return_url,
            requested_scopes_json, status, expires_at_unix,
            created_at_unix
        ) VALUES (
            'tx_delete', ?, 'google', 'state_delete',
            'ciphertext', 'nonce', 'client-reference',
            'https://app.example/callback', 'https://app.example/return',
            '["scope"]', 'pending', 2000000000, 1700000000
        )`,
		projectID,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func deletionAudit(subject string) domain.AuditEvent {
	status := 204
	return domain.AuditEvent{
		RequestID: "req_delete", Method: "DELETE",
		Path: "/admin/api/projects/1", HTTPStatus: &status,
		Metadata: map[string]any{
			"actor_type": "federated", "actor_identity_sub": subject,
			"delegated_audience": "mw-oauth",
			"authorized_scope":   "oauth.projects.delete",
		},
	}
}
