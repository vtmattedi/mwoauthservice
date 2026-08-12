CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    token_hash TEXT NOT NULL UNIQUE,
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

CREATE INDEX idx_projects_enabled
    ON projects(enabled);

CREATE INDEX idx_projects_token_hash
    ON projects(token_hash);
