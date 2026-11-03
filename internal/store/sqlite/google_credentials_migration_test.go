package sqlite

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite"

	"github.com/vtmattedi/mw-oauth-service/migrations"
)

const googleCredentialsMigration = "010_google_client_credentials.sql"

func openRawDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		t.Fatal(err)
	}
	return db
}

// migrationsBefore returns every embedded migration older than the Google
// credential migration, simulating an already-deployed v1 database.
func migrationsBefore(t *testing.T) fs.FS {
	t.Helper()

	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatal(err)
	}

	out := fstest.MapFS{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || e.Name() >= googleCredentialsMigration {
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

func seedV1Database(t *testing.T, db *sql.DB) {
	t.Helper()

	stmts := []string{
		insertTestProjects(t, db, 1, "legacy-app", 2, "other-app"),
		`INSERT INTO oauth_transactions(id, project_id, provider, state_hash,
			pkce_verifier_ciphertext, pkce_verifier_nonce, client_reference,
			callback_url, return_url, requested_scopes_json, status,
			expires_at_unix, created_at_unix)
		 VALUES ('tx-old', 1, 'google', 'state1', 'c', 'n', 'ref',
			'https://app/cb', 'https://app/ret', '[]', 'pending', 9999999999, 1)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func applyAll(t *testing.T, db *sql.DB) {
	t.Helper()
	if err := ApplyMigrations(context.Background(), db, migrations.Files); err != nil {
		t.Fatalf("apply 010: %v", err)
	}
}

func insertCredential(db *sql.DB, id string, project int, state string) error {
	extra := ""
	switch state {
	case "retiring":
		extra = ", retired_at"
	case "disabled":
		extra = ", disabled_at"
	}
	vals := ""
	if extra != "" {
		vals = ", strftime('%Y-%m-%dT%H:%M:%fZ','now')"
	}
	_, err := db.Exec(
		`INSERT INTO google_client_credentials(
			id, project_id, client_id, secret_ciphertext, secret_nonce,
			secret_key_version, state`+extra+`)
		 VALUES (?, ?, 'cid.apps.googleusercontent.com', 'ct', 'nonce', 1, ?`+vals+`)`,
		id, project, state,
	)
	return err
}

func TestGoogleCredentialsMigrationPreservesV1Data(t *testing.T) {
	db := openRawDB(t)
	ctx := context.Background()

	if err := ApplyMigrations(ctx, db, migrationsBefore(t)); err != nil {
		t.Fatal(err)
	}
	seedV1Database(t, db)

	applyAll(t, db)

	var projects, transactions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM projects`).Scan(&projects); err != nil || projects != 2 {
		t.Fatalf("projects = %d, %v", projects, err)
	}

	var credential sql.NullString
	if err := db.QueryRow(
		`SELECT google_credential_id FROM oauth_transactions WHERE id = 'tx-old'`,
	).Scan(&credential); err != nil {
		t.Fatal(err)
	}
	if credential.Valid {
		t.Fatalf("pre-v1.1 transaction must stay legacy (NULL), got %q", credential.String)
	}

	if err := db.QueryRow(`SELECT COUNT(*) FROM oauth_transactions`).Scan(&transactions); err != nil || transactions != 1 {
		t.Fatalf("transactions = %d, %v", transactions, err)
	}

	var fkViolations int
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		fkViolations++
	}
	rows.Close()
	if fkViolations != 0 {
		t.Fatalf("foreign_key_check reported %d violations", fkViolations)
	}

	// Re-running is a no-op.
	applyAll(t, db)
}

func TestGoogleCredentialsOneActivePerProject(t *testing.T) {
	db := openRawDB(t)
	applyAll(t, db)
	seedV1Database(t, db)

	if err := insertCredential(db, "gcred_a", 1, "active"); err != nil {
		t.Fatal(err)
	}
	if err := insertCredential(db, "gcred_b", 1, "active"); err == nil {
		t.Fatal("second active credential for the same project must be rejected")
	}
	// Other projects and non-active states are unaffected.
	if err := insertCredential(db, "gcred_c", 2, "active"); err != nil {
		t.Fatalf("active credential for another project: %v", err)
	}
	if err := insertCredential(db, "gcred_d", 1, "retiring"); err != nil {
		t.Fatalf("retiring credential alongside active: %v", err)
	}
	if err := insertCredential(db, "gcred_e", 1, "disabled"); err != nil {
		t.Fatalf("disabled credential alongside active: %v", err)
	}
}

func TestGoogleCredentialsRejectInvalidRows(t *testing.T) {
	db := openRawDB(t)
	applyAll(t, db)
	seedV1Database(t, db)

	bad := map[string]string{
		"invalid state": `INSERT INTO google_client_credentials(id, project_id, client_id,
			secret_ciphertext, secret_nonce, secret_key_version, state)
			VALUES ('gcred_1', 1, 'c', 'ct', 'n', 1, 'deleted')`,
		"bad id prefix": `INSERT INTO google_client_credentials(id, project_id, client_id,
			secret_ciphertext, secret_nonce, secret_key_version, state)
			VALUES ('other_1', 1, 'c', 'ct', 'n', 1, 'active')`,
		"unknown project": `INSERT INTO google_client_credentials(id, project_id, client_id,
			secret_ciphertext, secret_nonce, secret_key_version, state)
			VALUES ('gcred_2', 99, 'c', 'ct', 'n', 1, 'active')`,
		"missing ciphertext without tombstone": `INSERT INTO google_client_credentials(id, project_id,
			client_id, state) VALUES ('gcred_3', 1, 'c', 'active')`,
		"tombstone on active": `INSERT INTO google_client_credentials(id, project_id, client_id,
			state, secret_deleted_at)
			VALUES ('gcred_4', 1, 'c', 'active', '2026-11-03T00:00:00Z')`,
		"tombstone keeping ciphertext": `INSERT INTO google_client_credentials(id, project_id, client_id,
			secret_ciphertext, secret_nonce, secret_key_version, state, disabled_at, secret_deleted_at)
			VALUES ('gcred_5', 1, 'c', 'ct', 'n', 1, 'disabled', '2026-11-03T00:00:00Z', '2026-11-03T00:00:00Z')`,
		"retiring without timestamp": `INSERT INTO google_client_credentials(id, project_id, client_id,
			secret_ciphertext, secret_nonce, secret_key_version, state)
			VALUES ('gcred_6', 1, 'c', 'ct', 'n', 1, 'retiring')`,
		"disabled without timestamp": `INSERT INTO google_client_credentials(id, project_id, client_id,
			secret_ciphertext, secret_nonce, secret_key_version, state)
			VALUES ('gcred_7', 1, 'c', 'ct', 'n', 1, 'disabled')`,
		"empty client id": `INSERT INTO google_client_credentials(id, project_id, client_id,
			secret_ciphertext, secret_nonce, secret_key_version, state)
			VALUES ('gcred_8', 1, '', 'ct', 'n', 1, 'active')`,
	}
	for name, stmt := range bad {
		if _, err := db.Exec(stmt); err == nil {
			t.Fatalf("%s: expected constraint failure", name)
		}
	}

	// A proper tombstone is accepted.
	if _, err := db.Exec(
		`INSERT INTO google_client_credentials(id, project_id, client_id, state,
			disabled_at, secret_deleted_at)
		 VALUES ('gcred_ok', 1, 'c', 'disabled', '2026-11-03T00:00:00Z', '2026-11-03T00:00:00Z')`,
	); err != nil {
		t.Fatalf("valid tombstone rejected: %v", err)
	}
}

func TestGoogleCredentialsTransactionPinAndCascade(t *testing.T) {
	db := openRawDB(t)
	applyAll(t, db)
	seedV1Database(t, db)

	if err := insertCredential(db, "gcred_a", 1, "active"); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(
		`UPDATE oauth_transactions SET google_credential_id = 'gcred_missing' WHERE id = 'tx-old'`,
	); err == nil {
		t.Fatal("transaction must not pin a nonexistent credential")
	}

	if _, err := db.Exec(
		`UPDATE oauth_transactions SET google_credential_id = 'gcred_a' WHERE id = 'tx-old'`,
	); err != nil {
		t.Fatalf("pin existing credential: %v", err)
	}

	// Deleting the project removes its credentials and transactions together.
	if _, err := db.Exec(`DELETE FROM projects WHERE id = 1`); err != nil {
		t.Fatalf("delete project with credentials and pinned transactions: %v", err)
	}
	var remaining int
	if err := db.QueryRow(
		`SELECT (SELECT COUNT(*) FROM google_client_credentials)
		      + (SELECT COUNT(*) FROM oauth_transactions)`,
	).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("remaining rows = %d, %v", remaining, err)
	}
}
