package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

const createSchemaMigrations = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version TEXT PRIMARY KEY,
	applied_at TEXT NOT NULL
);
`

func ApplyMigrations(ctx context.Context, db *sql.DB, migrationFS fs.FS) error {
	if _, err := db.ExecContext(ctx, createSchemaMigrations); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		applied, err := migrationApplied(ctx, db, name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		contents, err := fs.ReadFile(migrationFS, name)
		if err != nil {
			return fmt.Errorf("read migration %q: %w", name, err)
		}
		if err := applyMigration(ctx, db, name, string(contents)); err != nil {
			return err
		}
	}
	return nil
}

func migrationApplied(ctx context.Context, db *sql.DB, version string) (bool, error) {
	var exists int
	err := db.QueryRowContext(
		ctx,
		`SELECT EXISTS(
			SELECT 1 FROM schema_migrations WHERE version = ?
		)`,
		version,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check migration %q: %w", version, err)
	}
	return exists == 1, nil
}

// foreignKeysOffDirective, as the first line of a migration, runs it with
// foreign key enforcement off. SQLite needs this to rebuild a table that other
// tables reference (it cannot drop a UNIQUE column in place), because dropping
// the old table would otherwise cascade into the referencing tables. The
// pragma cannot be changed inside a transaction, so it is set around it, and
// the migration only commits if no foreign key is violated afterwards.
const foreignKeysOffDirective = "-- mw:foreign-keys=off"

func applyMigration(ctx context.Context, db *sql.DB, version, sqlText string) error {
	// One dedicated connection, so connection-level pragmas apply to the
	// whole migration.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open connection for migration %q: %w", version, err)
	}
	defer conn.Close()

	foreignKeysOff := strings.HasPrefix(
		strings.TrimSpace(sqlText),
		foreignKeysOffDirective,
	)
	if foreignKeysOff {
		if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
			return fmt.Errorf("disable foreign keys for migration %q: %w", version, err)
		}
		// Always restore enforcement, even when the migration fails.
		defer func() {
			_, _ = conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON")
		}()
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %q: %w", version, err)
	}

	if _, err := tx.ExecContext(ctx, sqlText); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("execute migration %q: %w", version, err)
	}

	if foreignKeysOff {
		violations, err := countForeignKeyViolations(ctx, tx)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("check foreign keys after migration %q: %w", version, err)
		}
		if violations > 0 {
			_ = tx.Rollback()
			return fmt.Errorf(
				"migration %q would leave %d foreign key violations",
				version, violations,
			)
		}
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO schema_migrations(version, applied_at)
		 VALUES (?, CURRENT_TIMESTAMP)`,
		version,
	); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("record migration %q: %w", version, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %q: %w", version, err)
	}
	return nil
}

func countForeignKeyViolations(ctx context.Context, tx *sql.Tx) (int, error) {
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}
