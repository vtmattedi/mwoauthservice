-- MW OAuth v1.1: per-project Google OAuth client credentials.
--
-- Additive only. Existing tables keep working; the legacy global Google
-- client is NOT stored here (it stays a virtual source in code), so
-- oauth_transactions.google_credential_id = NULL means "legacy source".
--
-- Secrets are AES-256-GCM ciphertext bound to (id, project_id, provider) via
-- AAD. A disabled credential may be deleted: the secret columns are cleared
-- and secret_deleted_at is set, but the row stays as a tombstone so existing
-- references resolve to "unavailable" instead of dangling.

CREATE TABLE google_client_credentials (
    id TEXT PRIMARY KEY
        CHECK (id LIKE 'gcred\_%' ESCAPE '\'),
    project_id INTEGER NOT NULL,
    provider TEXT NOT NULL DEFAULT 'google'
        CHECK (provider IN ('google')),
    client_id TEXT NOT NULL
        CHECK (length(client_id) > 0),

    secret_ciphertext TEXT NULL,
    secret_nonce TEXT NULL,
    secret_key_version INTEGER NULL
        CHECK (secret_key_version IS NULL OR secret_key_version > 0),
    secret_deleted_at TEXT NULL,

    state TEXT NOT NULL
        CHECK (state IN ('active', 'retiring', 'disabled')),
    source TEXT NOT NULL DEFAULT 'project'
        CHECK (source IN ('project', 'legacy')),

    created_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    updated_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    retired_at TEXT NULL,
    disabled_at TEXT NULL,
    last_authorized_at TEXT NULL,
    last_refreshed_at TEXT NULL,

    -- Either a complete encrypted secret, or a tombstone with none of it.
    CHECK (
        (
            secret_deleted_at IS NULL
            AND secret_ciphertext IS NOT NULL
            AND secret_nonce IS NOT NULL
            AND secret_key_version IS NOT NULL
        )
        OR
        (
            secret_deleted_at IS NOT NULL
            AND state = 'disabled'
            AND secret_ciphertext IS NULL
            AND secret_nonce IS NULL
            AND secret_key_version IS NULL
        )
    ),
    CHECK (state != 'retiring' OR retired_at IS NOT NULL),
    CHECK (state != 'disabled' OR disabled_at IS NOT NULL),

    FOREIGN KEY (project_id)
        REFERENCES projects(id)
        ON DELETE CASCADE
);

-- Deterministic selection: at most one active credential per project and
-- provider for new authorizations.
CREATE UNIQUE INDEX one_active_google_client_per_project
    ON google_client_credentials(project_id, provider)
    WHERE state = 'active';

CREATE INDEX idx_google_client_credentials_project
    ON google_client_credentials(project_id, provider, state);

-- Pin the credential used at authorization start so the callback exchanges
-- the code with the same Google client even if credentials rotate meanwhile.
-- NULL = legacy global client (all transactions created before v1.1).
ALTER TABLE oauth_transactions
    ADD COLUMN google_credential_id TEXT NULL
        REFERENCES google_client_credentials(id)
        ON DELETE CASCADE;

CREATE INDEX idx_oauth_transactions_google_credential
    ON oauth_transactions(google_credential_id)
    WHERE google_credential_id IS NOT NULL;
