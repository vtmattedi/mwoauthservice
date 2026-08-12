CREATE TABLE project_oauth_configs (
    project_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0
        CHECK (enabled IN (0, 1)),
    rate_per_minute INTEGER NOT NULL DEFAULT 10
        CHECK (rate_per_minute > 0),
    rate_per_hour INTEGER NOT NULL DEFAULT 100
        CHECK (rate_per_hour > 0),
    max_pending_transactions INTEGER NOT NULL DEFAULT 50
        CHECK (max_pending_transactions > 0),
    created_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    updated_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    PRIMARY KEY (project_id, provider),
    FOREIGN KEY (project_id)
        REFERENCES projects(id)
        ON DELETE CASCADE
);

CREATE TABLE project_oauth_scopes (
    project_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    scope TEXT NOT NULL,
    PRIMARY KEY (project_id, provider, scope),
    FOREIGN KEY (project_id, provider)
        REFERENCES project_oauth_configs(project_id, provider)
        ON DELETE CASCADE
);

CREATE TABLE project_oauth_callback_urls (
    project_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    url TEXT NOT NULL,
    PRIMARY KEY (project_id, provider, url),
    FOREIGN KEY (project_id, provider)
        REFERENCES project_oauth_configs(project_id, provider)
        ON DELETE CASCADE
);

CREATE TABLE project_oauth_return_urls (
    project_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    url TEXT NOT NULL,
    PRIMARY KEY (project_id, provider, url),
    FOREIGN KEY (project_id, provider)
        REFERENCES project_oauth_configs(project_id, provider)
        ON DELETE CASCADE
);
