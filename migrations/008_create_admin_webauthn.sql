ALTER TABLE admin_users
    ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'password_or_webauthn'
        CHECK (
            auth_mode IN (
                'password_or_webauthn',
                'password_webauthn',
                'webauthn'
            )
        );

CREATE TABLE admin_webauthn_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user_id INTEGER NOT NULL,
    rpid TEXT NOT NULL,
    user_handle BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    UNIQUE (admin_user_id, rpid),
    UNIQUE (rpid, user_handle),
    FOREIGN KEY (admin_user_id)
        REFERENCES admin_users(id)
        ON DELETE CASCADE
);

CREATE TABLE admin_webauthn_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user_id INTEGER NOT NULL,
    rpid TEXT NOT NULL,
    credential_id BLOB NOT NULL,
    credential_ciphertext TEXT NOT NULL,
    credential_nonce TEXT NOT NULL,
    credential_key_version INTEGER NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    transports_json TEXT NOT NULL DEFAULT '[]',
    aaguid BLOB,
    sign_count INTEGER NOT NULL DEFAULT 0,
    clone_warning INTEGER NOT NULL DEFAULT 0
        CHECK (clone_warning IN (0, 1)),
    backup_eligible INTEGER NOT NULL DEFAULT 0
        CHECK (backup_eligible IN (0, 1)),
    backup_state INTEGER NOT NULL DEFAULT 0
        CHECK (backup_state IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    last_used_at TEXT,
    revoked_at TEXT,
    UNIQUE (rpid, credential_id),
    FOREIGN KEY (admin_user_id)
        REFERENCES admin_users(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_admin_webauthn_credentials_user
    ON admin_webauthn_credentials(admin_user_id, rpid);

CREATE INDEX idx_admin_webauthn_credentials_active
    ON admin_webauthn_credentials(admin_user_id, rpid, revoked_at);

CREATE TABLE admin_webauthn_ceremonies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    admin_user_id INTEGER,
    rpid TEXT NOT NULL,
    purpose TEXT NOT NULL
        CHECK (purpose IN ('registration', 'authentication')),
    session_ciphertext TEXT NOT NULL,
    session_nonce TEXT NOT NULL,
    session_key_version INTEGER NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    expires_at_unix INTEGER NOT NULL,
    consumed_at_unix INTEGER,
    created_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    FOREIGN KEY (admin_user_id)
        REFERENCES admin_users(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_admin_webauthn_ceremonies_expiry
    ON admin_webauthn_ceremonies(expires_at_unix);

CREATE INDEX idx_admin_webauthn_ceremonies_user
    ON admin_webauthn_ceremonies(admin_user_id, purpose);
