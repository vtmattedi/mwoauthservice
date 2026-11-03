-- MW OAuth v1.1: explicit legacy mode per project.
--
-- legacy_enabled = 1 keeps the pre-v1.1 integration working: the long-lived
-- mw_live_ API key is accepted on /v1/oauth/google/authorize and (in later
-- phases) the global Google client may be used. Every existing project
-- defaults to 1, so upgrading changes nothing. An operator turns it off once a
-- consumer has migrated to MW client credentials.

ALTER TABLE projects
    ADD COLUMN legacy_enabled INTEGER NOT NULL DEFAULT 1
        CHECK (legacy_enabled IN (0, 1));
