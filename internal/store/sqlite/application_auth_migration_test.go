package sqlite

import (
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/vtmattedi/mw-oauth-service/migrations"
)

const applicationAuthMigration = "011_application_auth.sql"

func migrationsBeforeName(t *testing.T, name string) fs.FS {
	t.Helper()

	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatal(err)
	}

	out := fstest.MapFS{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || e.Name() >= name {
			continue
		}
		data, err := fs.ReadFile(migrations.Files, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = &fstest.MapFile{Data: data}
	}
	return out
}

func seedAppAuth(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		insertTestProjects(t, db, 1, "app-1", 2, "app-2"),
		`INSERT INTO mw_application_clients(id, project_id, client_id, allowed_scopes)
		 VALUES (1, 1, 'mwc_one', 'google.authorize google.refresh')`,
		`INSERT INTO mw_application_client_secrets(id, client_pk, secret_hash)
		 VALUES (1, 1, '` + strings.Repeat("a", 64) + `')`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func TestApplicationAuthConstraints(t *testing.T) {
	db := openRawDB(t)
	applyAll(t, db)
	seedAppAuth(t, db)

	bad := map[string]string{
		"second client for one project": `INSERT INTO mw_application_clients(project_id, client_id, allowed_scopes)
			VALUES (1, 'mwc_two', 'google.authorize')`,
		"duplicate client id": `INSERT INTO mw_application_clients(project_id, client_id, allowed_scopes)
			VALUES (2, 'mwc_one', 'google.authorize')`,
		"client id without prefix": `INSERT INTO mw_application_clients(project_id, client_id, allowed_scopes)
			VALUES (2, 'plain', 'google.authorize')`,
		"unknown project": `INSERT INTO mw_application_clients(project_id, client_id, allowed_scopes)
			VALUES (99, 'mwc_x', 'google.authorize')`,
		"empty scopes": `INSERT INTO mw_application_clients(project_id, client_id, allowed_scopes)
			VALUES (2, 'mwc_y', '')`,
		"secret hash wrong length": `INSERT INTO mw_application_client_secrets(client_pk, secret_hash)
			VALUES (1, 'short')`,
		"duplicate secret hash": `INSERT INTO mw_application_client_secrets(client_pk, secret_hash)
			VALUES (1, '` + strings.Repeat("a", 64) + `')`,
		"revoked without timestamp": `INSERT INTO mw_application_client_secrets(client_pk, secret_hash, state)
			VALUES (1, '` + strings.Repeat("b", 64) + `', 'revoked')`,
		"invalid secret state": `INSERT INTO mw_application_client_secrets(client_pk, secret_hash, state)
			VALUES (1, '` + strings.Repeat("c", 64) + `', 'rotated')`,
		"token expiring before issue": `INSERT INTO mw_application_access_tokens(
			token_hash, client_pk, secret_id, project_id, scopes, issued_at_unix, expires_at_unix)
			VALUES ('` + strings.Repeat("d", 64) + `', 1, 1, 1, 'google.refresh', 100, 100)`,
		"token with unknown secret": `INSERT INTO mw_application_access_tokens(
			token_hash, client_pk, secret_id, project_id, scopes, issued_at_unix, expires_at_unix)
			VALUES ('` + strings.Repeat("e", 64) + `', 1, 99, 1, 'google.refresh', 100, 1000)`,
		"token hash wrong length": `INSERT INTO mw_application_access_tokens(
			token_hash, client_pk, secret_id, project_id, scopes, issued_at_unix, expires_at_unix)
			VALUES ('short', 1, 1, 1, 'google.refresh', 100, 1000)`,
	}
	for name, stmt := range bad {
		if _, err := db.Exec(stmt); err == nil {
			t.Fatalf("%s: expected constraint failure", name)
		}
	}

	if _, err := db.Exec(
		`INSERT INTO mw_application_access_tokens(
			token_hash, client_pk, secret_id, project_id, scopes, issued_at_unix, expires_at_unix)
		 VALUES ('` + strings.Repeat("f", 64) + `', 1, 1, 1, 'google.refresh', 100, 1000)`,
	); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

func TestApplicationAuthCascades(t *testing.T) {
	db := openRawDB(t)
	applyAll(t, db)
	seedAppAuth(t, db)

	tokenInsert := func(hash string) {
		t.Helper()
		if _, err := db.Exec(
			`INSERT INTO mw_application_access_tokens(
				token_hash, client_pk, secret_id, project_id, scopes, issued_at_unix, expires_at_unix)
			 VALUES (?, 1, 1, 1, 'google.refresh', 100, 1000)`, hash,
		); err != nil {
			t.Fatal(err)
		}
	}
	count := func(table string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Deleting a secret removes the tokens it issued.
	tokenInsert(strings.Repeat("1", 64))
	if _, err := db.Exec(`DELETE FROM mw_application_client_secrets WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if n := count("mw_application_access_tokens"); n != 0 {
		t.Fatalf("tokens left after secret delete: %d", n)
	}

	// Deleting the project removes client, secrets and tokens.
	if _, err := db.Exec(
		`INSERT INTO mw_application_client_secrets(id, client_pk, secret_hash)
		 VALUES (2, 1, '` + strings.Repeat("9", 64) + `')`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO mw_application_access_tokens(
			token_hash, client_pk, secret_id, project_id, scopes, issued_at_unix, expires_at_unix)
		 VALUES ('` + strings.Repeat("2", 64) + `', 1, 2, 1, 'google.refresh', 100, 1000)`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM projects WHERE id = 1`); err != nil {
		t.Fatalf("delete project: %v", err)
	}
	for _, table := range []string{
		"mw_application_clients", "mw_application_client_secrets", "mw_application_access_tokens",
	} {
		if n := count(table); n != 0 {
			t.Fatalf("%s rows left after project delete: %d", table, n)
		}
	}
}
