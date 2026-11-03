-- mw:foreign-keys=off
--
-- MW OAuth v1.1: projects no longer authenticate with a long-lived mw_live_
-- API key, and there is no per-project legacy mode. Applications use MW client
-- credentials (migration 011) exclusively.
--
-- This drops projects.token_hash (UNIQUE, so SQLite cannot drop it in place)
-- and projects.legacy_enabled by rebuilding the table. Foreign keys are off
-- for the rebuild (see the directive above); the runner verifies
-- foreign_key_check before committing. Child tables keep referencing
-- "projects" by name, and the rebuilt table takes that name.

CREATE TABLE projects_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    callback_secret_ciphertext TEXT NOT NULL,
    callback_secret_nonce TEXT NOT NULL,
    callback_secret_key_version INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
        CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    updated_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    )
);

INSERT INTO projects_new(
    id, name,
    callback_secret_ciphertext, callback_secret_nonce, callback_secret_key_version,
    enabled, created_at, updated_at
)
SELECT
    id, name,
    callback_secret_ciphertext, callback_secret_nonce, callback_secret_key_version,
    enabled, created_at, updated_at
FROM projects;

-- Keep the AUTOINCREMENT counter, so IDs of deleted projects are never reused.
DELETE FROM sqlite_sequence WHERE name = 'projects_new';
INSERT INTO sqlite_sequence(name, seq)
SELECT 'projects_new', seq FROM sqlite_sequence WHERE name = 'projects';

DROP TABLE projects;
ALTER TABLE projects_new RENAME TO projects;

CREATE INDEX idx_projects_enabled
    ON projects(enabled);
