CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,

    project_id INTEGER NULL,
    transaction_id TEXT NULL,
    request_id TEXT NOT NULL,

    method TEXT NULL,
    path TEXT NULL,
    http_status INTEGER NULL,

    origin TEXT NULL,
    remote_ip TEXT NULL,

    reason_code TEXT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    attempt_count INTEGER NOT NULL DEFAULT 1
        CHECK (attempt_count > 0),

    created_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),

    FOREIGN KEY (project_id)
        REFERENCES projects(id)
        ON DELETE SET NULL
);

CREATE INDEX idx_audit_events_created_at_unix
    ON audit_events(created_at_unix DESC, id DESC);

CREATE INDEX idx_audit_events_project_created
    ON audit_events(project_id, created_at_unix DESC, id DESC);

CREATE INDEX idx_audit_events_status_created
    ON audit_events(status, created_at_unix DESC, id DESC);

CREATE INDEX idx_audit_events_event_type_created
    ON audit_events(event_type, created_at_unix DESC, id DESC);

CREATE INDEX idx_audit_events_request_id
    ON audit_events(request_id);
