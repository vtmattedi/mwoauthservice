CREATE TABLE oauth_transactions (
    id TEXT PRIMARY KEY,

    project_id INTEGER NOT NULL,
    provider TEXT NOT NULL,

    state_hash TEXT NOT NULL UNIQUE,

    pkce_verifier_ciphertext TEXT NOT NULL,
    pkce_verifier_nonce TEXT NOT NULL,

    client_reference TEXT NOT NULL,
    callback_url TEXT NOT NULL,
    return_url TEXT NOT NULL,
    requested_scopes_json TEXT NOT NULL,

    status TEXT NOT NULL,

    expires_at_unix INTEGER NOT NULL,
    consumed_at_unix INTEGER NULL,

    created_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    created_at_unix INTEGER NOT NULL,

    FOREIGN KEY (project_id)
        REFERENCES projects(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_oauth_transactions_project_created
    ON oauth_transactions(
        project_id,
        provider,
        created_at_unix DESC
    );

CREATE INDEX idx_oauth_transactions_project_pending
    ON oauth_transactions(
        project_id,
        provider,
        status,
        expires_at_unix
    );

CREATE INDEX idx_oauth_transactions_state_hash
    ON oauth_transactions(state_hash);
