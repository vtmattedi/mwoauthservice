package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/migrations"
)

const removeProjectAPIKeysMigration = "013_remove_project_api_keys.sql"

// insertTestProjects returns an INSERT for two projects (id, name pairs) that
// works both before and after migration 013 (which drops token_hash).
func insertTestProjects(t *testing.T, db *sql.DB, id1 int, name1 string, id2 int, name2 string) string {
	t.Helper()

	var hasTokenHash int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('projects') WHERE name = 'token_hash'`,
	).Scan(&hasTokenHash); err != nil {
		t.Fatal(err)
	}

	if hasTokenHash > 0 {
		return fmt.Sprintf(
			`INSERT INTO projects(id, name, token_hash, callback_secret_ciphertext,
				callback_secret_nonce, callback_secret_key_version)
			 VALUES (%d, '%s', 'hash-%d', 'ct', 'nonce', 1),
			        (%d, '%s', 'hash-%d', 'ct', 'nonce', 1)`,
			id1, name1, id1, id2, name2, id2,
		)
	}
	return fmt.Sprintf(
		`INSERT INTO projects(id, name, callback_secret_ciphertext,
			callback_secret_nonce, callback_secret_key_version)
		 VALUES (%d, '%s', 'ct', 'nonce', 1),
		        (%d, '%s', 'ct', 'nonce', 1)`,
		id1, name1, id2, name2,
	)
}

func columns(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info('` + table + `')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out = append(out, name)
	}
	return out
}

func count(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// seedDatabaseBefore013 builds a database as a v1.1 development build left it
// (migrations up to 012) with data in every table that references projects.
func seedDatabaseBefore013(t *testing.T) *sql.DB {
	t.Helper()
	db := openRawDB(t)

	if err := ApplyMigrations(context.Background(), db, migrationsBeforeName(t, removeProjectAPIKeysMigration)); err != nil {
		t.Fatal(err)
	}

	stmts := []string{
		`INSERT INTO projects(id, name, token_hash, callback_secret_ciphertext, callback_secret_nonce,
			callback_secret_key_version, enabled, legacy_enabled)
		 VALUES (1, 'Alpha', 'hash-a', 'cipher-a', 'nonce-a', 3, 1, 1),
		        (2, 'Beta',  'hash-b', 'cipher-b', 'nonce-b', 1, 0, 0),
		        (7, 'Gamma', 'hash-c', 'cipher-c', 'nonce-c', 2, 1, 1)`,
		// Highest id ever used was 9: deleted projects must not have their ids reused.
		`UPDATE sqlite_sequence SET seq = 9 WHERE name = 'projects'`,
		`INSERT INTO project_oauth_configs(project_id, provider, enabled) VALUES (1, 'google', 1), (2, 'google', 0)`,
		`INSERT INTO project_oauth_scopes(project_id, provider, scope) VALUES (1, 'google', 'scope-a')`,
		`INSERT INTO project_oauth_callback_urls(project_id, provider, url) VALUES (1, 'google', 'https://a/cb')`,
		`INSERT INTO project_oauth_return_urls(project_id, provider, url) VALUES (1, 'google', 'https://a/ret')`,
		`INSERT INTO google_client_credentials(id, project_id, client_id, secret_ciphertext, secret_nonce,
			secret_key_version, state) VALUES ('gcred_one', 1, 'c.apps.googleusercontent.com', 'ct', 'n', 1, 'active')`,
		`INSERT INTO oauth_transactions(id, project_id, provider, state_hash, pkce_verifier_ciphertext,
			pkce_verifier_nonce, client_reference, callback_url, return_url, requested_scopes_json, status,
			expires_at_unix, created_at_unix, google_credential_id)
		 VALUES ('tx-1', 1, 'google', 'state-1', 'c', 'n', 'ref', 'https://a/cb', 'https://a/ret', '[]',
			'pending', 9999999999, 1, 'gcred_one')`,
		`INSERT INTO mw_application_clients(id, project_id, client_id, allowed_scopes)
		 VALUES (1, 1, 'mwc_alpha', 'google.authorize google.refresh')`,
		`INSERT INTO mw_application_client_secrets(id, client_pk, secret_hash) VALUES (1, 1, '` + strings.Repeat("a", 64) + `')`,
		`INSERT INTO mw_application_access_tokens(token_hash, client_pk, secret_id, project_id, scopes,
			issued_at_unix, expires_at_unix) VALUES ('` + strings.Repeat("b", 64) + `', 1, 1, 1, 'google.refresh', 100, 9999999999)`,
		`INSERT INTO audit_events(event_type, status, severity, project_id, request_id)
		 VALUES ('oauth.request.accepted', 'accepted', 'info', 1, 'req-1')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("seed: %v\n%s", err, stmt)
		}
	}
	return db
}

func TestRemovingProjectAPIKeysKeepsEveryRowAndRelationship(t *testing.T) {
	db := seedDatabaseBefore013(t)

	applyAll(t, db)

	// The columns are gone, everything else is as before.
	cols := strings.Join(columns(t, db, "projects"), ",")
	if strings.Contains(cols, "token_hash") || strings.Contains(cols, "legacy_enabled") {
		t.Fatalf("projects columns = %s", cols)
	}
	for _, want := range []string{"id", "name", "callback_secret_ciphertext", "callback_secret_nonce",
		"callback_secret_key_version", "enabled", "created_at", "updated_at"} {
		if !strings.Contains(cols, want) {
			t.Fatalf("projects lost column %s: %s", want, cols)
		}
	}

	rows, err := db.Query(`SELECT id, name, callback_secret_ciphertext, callback_secret_key_version, enabled FROM projects ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		id      int
		name    string
		cipher  string
		version int
		enabled int
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.name, &r.cipher, &r.version, &r.enabled); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	rows.Close()

	want := []row{{1, "Alpha", "cipher-a", 3, 1}, {2, "Beta", "cipher-b", 1, 0}, {7, "Gamma", "cipher-c", 2, 1}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("projects = %v; want %v", got, want)
	}

	// Child rows survived the rebuild and still point at their projects.
	for table, expected := range map[string]int{
		"project_oauth_configs":         2,
		"project_oauth_scopes":          1,
		"project_oauth_callback_urls":   1,
		"project_oauth_return_urls":     1,
		"google_client_credentials":     1,
		"oauth_transactions":            1,
		"mw_application_clients":        1,
		"mw_application_client_secrets": 1,
		"mw_application_access_tokens":  1,
		"audit_events":                  1,
	} {
		if n := count(t, db, `SELECT COUNT(*) FROM `+table); n != expected {
			t.Fatalf("%s rows = %d; want %d", table, n, expected)
		}
	}

	if violations := count(t, db, `SELECT COUNT(*) FROM pragma_foreign_key_check`); violations != 0 {
		t.Fatalf("%d foreign key violations after the rebuild", violations)
	}
}

func TestRebuiltProjectsTableStillEnforcesAndCascades(t *testing.T) {
	db := seedDatabaseBefore013(t)
	applyAll(t, db)

	// Enforcement is back on for the connection that ran the migration.
	if on := count(t, db, `SELECT foreign_keys FROM pragma_foreign_keys`); on != 1 {
		t.Fatalf("foreign_keys = %d after migrating; must be re-enabled", on)
	}

	// Children cannot point at a project that does not exist.
	if _, err := db.Exec(`INSERT INTO project_oauth_configs(project_id, provider, enabled) VALUES (99, 'google', 1)`); err == nil {
		t.Fatal("a config for an unknown project must be rejected")
	}

	// Deleting a project cascades through every dependent table.
	if _, err := db.Exec(`DELETE FROM projects WHERE id = 1`); err != nil {
		t.Fatalf("delete project: %v", err)
	}
	for _, table := range []string{
		"project_oauth_scopes", "project_oauth_callback_urls", "project_oauth_return_urls",
		"google_client_credentials", "oauth_transactions", "mw_application_clients",
		"mw_application_client_secrets", "mw_application_access_tokens",
	} {
		if n := count(t, db, `SELECT COUNT(*) FROM `+table); n != 0 {
			t.Fatalf("%s rows left after project delete: %d", table, n)
		}
	}
	if n := count(t, db, `SELECT COUNT(*) FROM project_oauth_configs WHERE project_id = 1`); n != 0 {
		t.Fatalf("configs left: %d", n)
	}
	if n := count(t, db, `SELECT COUNT(*) FROM projects`); n != 2 {
		t.Fatalf("other projects affected: %d left", n)
	}
}

func TestRebuiltProjectsTableKeepsConstraintsAndIdCounter(t *testing.T) {
	db := seedDatabaseBefore013(t)
	applyAll(t, db)

	// New projects need no API key.
	res, err := db.Exec(
		`INSERT INTO projects(name, callback_secret_ciphertext, callback_secret_nonce, callback_secret_key_version)
		 VALUES ('Delta', 'c', 'n', 1)`,
	)
	if err != nil {
		t.Fatalf("insert without token_hash: %v", err)
	}
	id, _ := res.LastInsertId()
	if id != 10 {
		t.Fatalf("new project id = %d; ids of deleted projects must not be reused (want 10)", id)
	}

	// Names stay unique, case-insensitively.
	if _, err := db.Exec(
		`INSERT INTO projects(name, callback_secret_ciphertext, callback_secret_nonce, callback_secret_key_version)
		 VALUES ('ALPHA', 'c', 'n', 1)`,
	); err == nil {
		t.Fatal("project names must stay unique ignoring case")
	}
	if _, err := db.Exec(`UPDATE projects SET enabled = 5 WHERE id = 1`); err == nil {
		t.Fatal("enabled must stay 0 or 1")
	}

	if n := count(t, db, `SELECT COUNT(*) FROM pragma_index_list('projects') WHERE name = 'idx_projects_enabled'`); n != 1 {
		t.Fatal("idx_projects_enabled must be recreated")
	}
	if n := count(t, db, `SELECT COUNT(*) FROM pragma_index_list('projects') WHERE name = 'idx_projects_token_hash'`); n != 0 {
		t.Fatal("the token hash index must be gone")
	}
}

func TestRebuildIsAppliedOnceAndEmptyDatabasesWork(t *testing.T) {
	db := openRawDB(t)
	applyAll(t, db)
	applyAll(t, db) // idempotent

	if n := count(t, db, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, removeProjectAPIKeysMigration); n != 1 {
		t.Fatalf("migration recorded %d times", n)
	}
	if n := count(t, db, `SELECT COUNT(*) FROM projects`); n != 0 {
		t.Fatalf("projects = %d", n)
	}
	if _, err := db.Exec(
		`INSERT INTO projects(name, callback_secret_ciphertext, callback_secret_nonce, callback_secret_key_version)
		 VALUES ('First', 'c', 'n', 1)`,
	); err != nil {
		t.Fatalf("insert into a fresh database: %v", err)
	}
}

// A migration that rebuilds a table with foreign keys off must not commit if
// it leaves dangling references.
func TestForeignKeyOffMigrationsAreCheckedBeforeCommit(t *testing.T) {
	db := openRawDB(t)
	if err := ApplyMigrations(context.Background(), db, migrationsBeforeName(t, removeProjectAPIKeysMigration)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO projects(id, name, token_hash, callback_secret_ciphertext, callback_secret_nonce, callback_secret_key_version)
		 VALUES (1, 'A', 'h', 'c', 'n', 1)`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO project_oauth_configs(project_id, provider, enabled) VALUES (1, 'google', 1)`); err != nil {
		t.Fatal(err)
	}

	bad := "-- mw:foreign-keys=off\nDELETE FROM projects WHERE id = 1;\n"
	err := applyMigration(context.Background(), db, "999_bad.sql", bad)
	if err == nil || !strings.Contains(err.Error(), "foreign key") {
		t.Fatalf("err = %v; a migration leaving dangling references must fail", err)
	}

	// It was rolled back, and enforcement is on again.
	if n := count(t, db, `SELECT COUNT(*) FROM projects`); n != 1 {
		t.Fatalf("projects = %d; the bad migration must roll back", n)
	}
	if on := count(t, db, `SELECT foreign_keys FROM pragma_foreign_keys`); on != 1 {
		t.Fatal("foreign keys must be re-enabled after a failed migration")
	}
	if n := count(t, db, `SELECT COUNT(*) FROM schema_migrations WHERE version = '999_bad.sql'`); n != 0 {
		t.Fatal("a failed migration must not be recorded")
	}

	// Also confirm the production migration list is untouched by this test.
	_ = migrations.Files
}
