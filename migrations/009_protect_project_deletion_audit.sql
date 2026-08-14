CREATE TRIGGER protect_project_deletion_audit_update
BEFORE UPDATE ON audit_events
WHEN OLD.event_type = 'admin.project.deleted'
BEGIN
    SELECT RAISE(
        ABORT,
        'project deletion audit events are immutable'
    );
END;

CREATE TRIGGER protect_project_deletion_audit_delete
BEFORE DELETE ON audit_events
WHEN OLD.event_type = 'admin.project.deleted'
BEGIN
    SELECT RAISE(
        ABORT,
        'project deletion audit events are immutable'
    );
END;
