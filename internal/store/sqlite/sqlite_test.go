package sqlite

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/migrations"
)

func TestOpenConfiguresSQLiteAndAppliesMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth.db")

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := store.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	var foreignKeys int
	if err := store.DB().QueryRowContext(ctx, "PRAGMA foreign_keys;").Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d; want 1", foreignKeys)
	}

	var journalMode string
	if err := store.DB().QueryRowContext(ctx, "PRAGMA journal_mode;").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %q; want wal", journalMode)
	}

	expectedMigrationCount, err := embeddedMigrationCount()
	if err != nil {
		t.Fatal(err)
	}

	var count int
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expectedMigrationCount {
		t.Fatalf(
			"migration count = %d; want %d",
			count,
			expectedMigrationCount,
		)
	}

	if err := ApplyMigrations(ctx, store.DB(), migrations.Files); err != nil {
		t.Fatalf("second ApplyMigrations: %v", err)
	}

	var after int
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != count {
		t.Fatalf("migration count after second run = %d; want %d", after, count)
	}
}

func embeddedMigrationCount() (int, error) {
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		return 0, err
	}

	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if strings.HasSuffix(entry.Name(), ".sql") {
			count++
		}
	}

	return count, nil
}
