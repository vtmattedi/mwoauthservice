-- MW OAuth v1.1: machine-to-machine application authentication.
--
-- A project gets one MW client (stable client_id) with up to two overlapping
-- client secrets. A secret is exchanged for a short-lived opaque access token
-- (client credentials grant). Only hashes are stored: neither the client
-- secret nor the access token can be recovered from the database.
--
-- Additive only. The legacy projects.token_hash (mw_live_ API key) is not
-- touched and keeps working for legacy-enabled projects.

CREATE TABLE mw_application_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL UNIQUE,
    client_id TEXT NOT NULL UNIQUE
        CHECK (client_id LIKE 'mwc\_%' ESCAPE '\'),
    display_name TEXT NOT NULL DEFAULT ''
        CHECK (length(display_name) <= 160),
    enabled INTEGER NOT NULL DEFAULT 1
        CHECK (enabled IN (0, 1)),
    -- Space-separated MW scopes this client may be granted.
    allowed_scopes TEXT NOT NULL
        CHECK (length(allowed_scopes) > 0),
    created_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    updated_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),

    FOREIGN KEY (project_id)
        REFERENCES projects(id)
        ON DELETE CASCADE
);

CREATE TABLE mw_application_client_secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_pk INTEGER NOT NULL,
    -- Hex SHA-256 of a >= 256-bit random secret.
    secret_hash TEXT NOT NULL UNIQUE
        CHECK (length(secret_hash) = 64),
    state TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'revoked')),
    created_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    revoked_at TEXT NULL,
    last_used_at TEXT NULL,

    CHECK (state != 'revoked' OR revoked_at IS NOT NULL),

    FOREIGN KEY (client_pk)
        REFERENCES mw_application_clients(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_mw_application_client_secrets_client
    ON mw_application_client_secrets(client_pk, state);

CREATE TABLE mw_application_access_tokens (
    -- Hex SHA-256 of the opaque bearer token.
    token_hash TEXT PRIMARY KEY
        CHECK (length(token_hash) = 64),
    client_pk INTEGER NOT NULL,
    -- The client secret version that obtained the token, so revoking a
    -- secret also revokes the tokens it issued.
    secret_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    scopes TEXT NOT NULL,
    issued_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    revoked_at_unix INTEGER NULL,

    CHECK (expires_at_unix > issued_at_unix),

    FOREIGN KEY (client_pk)
        REFERENCES mw_application_clients(id)
        ON DELETE CASCADE,
    FOREIGN KEY (secret_id)
        REFERENCES mw_application_client_secrets(id)
        ON DELETE CASCADE,
    FOREIGN KEY (project_id)
        REFERENCES projects(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_mw_application_access_tokens_expiry
    ON mw_application_access_tokens(expires_at_unix);

CREATE INDEX idx_mw_application_access_tokens_secret
    ON mw_application_access_tokens(secret_id);

CREATE INDEX idx_mw_application_access_tokens_client
    ON mw_application_access_tokens(client_pk);
