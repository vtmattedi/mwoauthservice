package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

func (s *Store) InsertAuditEvent(
	ctx context.Context,
	event domain.AuditEvent,
) (domain.AuditEvent, error) {
	id, err := insertAuditEvent(ctx, s.db, event)
	if err != nil {
		return domain.AuditEvent{}, err
	}

	return s.GetAuditEvent(ctx, id)
}

type auditEventExecutor interface {
	ExecContext(
		ctx context.Context,
		query string,
		args ...any,
	) (sql.Result, error)
}

func insertAuditEvent(
	ctx context.Context,
	executor auditEventExecutor,
	event domain.AuditEvent,
) (int64, error) {
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return 0, fmt.Errorf(
			"encode audit metadata: %w",
			err,
		)
	}

	result, err := executor.ExecContext(
		ctx,
		`INSERT INTO audit_events(
            event_type,
            status,
            severity,
            project_id,
            transaction_id,
            request_id,
            method,
            path,
            http_status,
            origin,
            remote_ip,
            reason_code,
            metadata_json,
            attempt_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.EventType,
		event.Status,
		event.Severity,
		nullableInt64(event.ProjectID),
		nullableString(event.TransactionID),
		event.RequestID,
		nullableString(event.Method),
		nullableString(event.Path),
		nullableInt(event.HTTPStatus),
		nullableString(event.Origin),
		nullableString(event.RemoteIP),
		nullableString(event.ReasonCode),
		string(metadataJSON),
		event.AttemptCount,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"insert audit event: %w",
			err,
		)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf(
			"read audit event id: %w",
			err,
		)
	}

	return id, nil
}

func (s *Store) GetAuditEvent(
	ctx context.Context,
	id int64,
) (domain.AuditEvent, error) {
	if id <= 0 {
		return domain.AuditEvent{}, audit.ErrNotFound
	}

	row := s.db.QueryRowContext(
		ctx,
		`SELECT
            id,
            event_type,
            status,
            severity,
            project_id,
            transaction_id,
            request_id,
            method,
            path,
            http_status,
            origin,
            remote_ip,
            reason_code,
            metadata_json,
            attempt_count,
            created_at
         FROM audit_events
         WHERE id = ?
         LIMIT 1`,
		id,
	)

	event, err := scanAuditEvent(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AuditEvent{}, audit.ErrNotFound
		}
		return domain.AuditEvent{}, fmt.Errorf(
			"get audit event: %w",
			err,
		)
	}

	return event, nil
}

func (s *Store) ListAuditEvents(
	ctx context.Context,
	filters domain.AuditFilters,
) (domain.AuditPage, error) {
	where, args := auditWhere(filters, "a")

	var total int64
	countQuery := `SELECT COUNT(*) FROM audit_events AS a` + where
	if err := s.db.QueryRowContext(
		ctx,
		countQuery,
		args...,
	).Scan(&total); err != nil {
		return domain.AuditPage{}, fmt.Errorf(
			"count audit events: %w",
			err,
		)
	}

	queryArgs := append(
		append([]any{}, args...),
		filters.Limit,
		filters.Offset,
	)

	rows, err := s.db.QueryContext(
		ctx,
		`SELECT
            a.id,
            a.event_type,
            a.status,
            a.severity,
            a.project_id,
            a.transaction_id,
            a.request_id,
            a.method,
            a.path,
            a.http_status,
            a.origin,
            a.remote_ip,
            a.reason_code,
            a.metadata_json,
            a.attempt_count,
            a.created_at
         FROM audit_events AS a`+
			where+
			` ORDER BY a.created_at_unix DESC, a.id DESC
              LIMIT ? OFFSET ?`,
		queryArgs...,
	)
	if err != nil {
		return domain.AuditPage{}, fmt.Errorf(
			"list audit events: %w",
			err,
		)
	}
	defer rows.Close()

	items := make([]domain.AuditEvent, 0, filters.Limit)

	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return domain.AuditPage{}, fmt.Errorf(
				"scan audit event: %w",
				err,
			)
		}
		items = append(items, event)
	}

	if err := rows.Err(); err != nil {
		return domain.AuditPage{}, fmt.Errorf(
			"iterate audit events: %w",
			err,
		)
	}

	return domain.AuditPage{
		Items: items,
		Pagination: domain.Pagination{
			Limit:   filters.Limit,
			Offset:  filters.Offset,
			Count:   len(items),
			Total:   total,
			HasMore: int64(filters.Offset+len(items)) < total,
		},
	}, nil
}

func (s *Store) OAuthMetrics(
	ctx context.Context,
	filters domain.AuditFilters,
) (domain.OAuthMetricsPage, error) {
	where, args := auditWhere(filters, "a")

	var summary domain.OAuthMetricSummary
	summaryQuery := `
        SELECT
            COUNT(*),
            COALESCE(SUM(CASE WHEN a.status = 'completed' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN a.status = 'failed' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN a.status = 'denied' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN a.status = 'rejected' THEN 1 ELSE 0 END), 0)
        FROM audit_events AS a` + where

	if err := s.db.QueryRowContext(
		ctx,
		summaryQuery,
		args...,
	).Scan(
		&summary.Total,
		&summary.Completed,
		&summary.Failed,
		&summary.Denied,
		&summary.Rejected,
	); err != nil {
		return domain.OAuthMetricsPage{}, fmt.Errorf(
			"load OAuth metric summary: %w",
			err,
		)
	}

	projectWhere := ""
	projectArgs := make([]any, 0, 1)
	if filters.ProjectID != nil {
		projectWhere = " WHERE p.id = ?"
		projectArgs = append(projectArgs, *filters.ProjectID)
	}

	var projectTotal int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM projects AS p`+projectWhere,
		projectArgs...,
	).Scan(&projectTotal); err != nil {
		return domain.OAuthMetricsPage{}, fmt.Errorf(
			"count metric project groups: %w",
			err,
		)
	}

	joinConditions, joinArgs := auditJoinConditions(filters)

	groupArgs := make([]any, 0, len(joinArgs)+len(projectArgs)+2)
	groupArgs = append(groupArgs, joinArgs...)
	groupArgs = append(groupArgs, projectArgs...)
	groupArgs = append(
		groupArgs,
		filters.Limit,
		filters.Offset,
	)

	query := `
        SELECT
            p.id,
            p.name,
            COUNT(a.id),
            COALESCE(SUM(CASE WHEN a.status = 'completed' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN a.status = 'failed' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN a.status = 'denied' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN a.status = 'rejected' THEN 1 ELSE 0 END), 0)
        FROM projects AS p
        LEFT JOIN audit_events AS a
          ON a.project_id = p.id` +
		joinConditions +
		projectWhere +
		`
        GROUP BY p.id, p.name
        ORDER BY p.name COLLATE NOCASE ASC, p.id ASC
        LIMIT ? OFFSET ?`

	rows, err := s.db.QueryContext(
		ctx,
		query,
		groupArgs...,
	)
	if err != nil {
		return domain.OAuthMetricsPage{}, fmt.Errorf(
			"load project OAuth metrics: %w",
			err,
		)
	}
	defer rows.Close()

	items := make(
		[]domain.OAuthMetricProject,
		0,
		filters.Limit,
	)

	for rows.Next() {
		var item domain.OAuthMetricProject

		if err := rows.Scan(
			&item.ProjectID,
			&item.ProjectName,
			&item.Total,
			&item.Completed,
			&item.Failed,
			&item.Denied,
			&item.Rejected,
		); err != nil {
			return domain.OAuthMetricsPage{}, fmt.Errorf(
				"scan project OAuth metrics: %w",
				err,
			)
		}

		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		return domain.OAuthMetricsPage{}, fmt.Errorf(
			"iterate project OAuth metrics: %w",
			err,
		)
	}

	return domain.OAuthMetricsPage{
		Summary: summary,
		Items:   items,
		Pagination: domain.Pagination{
			Limit:   filters.Limit,
			Offset:  filters.Offset,
			Count:   len(items),
			Total:   projectTotal,
			HasMore: int64(filters.Offset+len(items)) < projectTotal,
		},
	}, nil
}

type auditScanner interface {
	Scan(dest ...any) error
}

func scanAuditEvent(
	row auditScanner,
) (domain.AuditEvent, error) {
	var event domain.AuditEvent

	var projectID sql.NullInt64
	var transactionID sql.NullString
	var method sql.NullString
	var path sql.NullString
	var httpStatus sql.NullInt64
	var origin sql.NullString
	var remoteIP sql.NullString
	var reasonCode sql.NullString
	var metadataJSON string

	err := row.Scan(
		&event.ID,
		&event.EventType,
		&event.Status,
		&event.Severity,
		&projectID,
		&transactionID,
		&event.RequestID,
		&method,
		&path,
		&httpStatus,
		&origin,
		&remoteIP,
		&reasonCode,
		&metadataJSON,
		&event.AttemptCount,
		&event.CreatedAt,
	)
	if err != nil {
		return domain.AuditEvent{}, err
	}

	if projectID.Valid {
		value := projectID.Int64
		event.ProjectID = &value
	}
	if transactionID.Valid {
		event.TransactionID = transactionID.String
	}
	if method.Valid {
		event.Method = method.String
	}
	if path.Valid {
		event.Path = path.String
	}
	if httpStatus.Valid {
		value := int(httpStatus.Int64)
		event.HTTPStatus = &value
	}
	if origin.Valid {
		event.Origin = origin.String
	}
	if remoteIP.Valid {
		event.RemoteIP = remoteIP.String
	}
	if reasonCode.Valid {
		event.ReasonCode = reasonCode.String
	}

	event.Metadata = map[string]any{}
	if strings.TrimSpace(metadataJSON) != "" {
		if err := json.Unmarshal(
			[]byte(metadataJSON),
			&event.Metadata,
		); err != nil {
			return domain.AuditEvent{}, fmt.Errorf(
				"decode audit metadata: %w",
				err,
			)
		}
	}

	return event, nil
}

func auditWhere(
	filters domain.AuditFilters,
	alias string,
) (string, []any) {
	prefix := alias + "."
	clauses := make([]string, 0, 4)
	args := make([]any, 0, 4)

	if filters.FromUnix != nil {
		clauses = append(
			clauses,
			prefix+"created_at_unix >= ?",
		)
		args = append(args, *filters.FromUnix)
	}
	if filters.ToUnix != nil {
		clauses = append(
			clauses,
			prefix+"created_at_unix <= ?",
		)
		args = append(args, *filters.ToUnix)
	}
	if filters.ProjectID != nil {
		clauses = append(
			clauses,
			prefix+"project_id = ?",
		)
		args = append(args, *filters.ProjectID)
	}
	if filters.Status != "" {
		clauses = append(
			clauses,
			prefix+"status = ?",
		)
		args = append(args, filters.Status)
	}

	if len(clauses) == 0 {
		return "", args
	}

	return " WHERE " + strings.Join(clauses, " AND "), args
}

func auditJoinConditions(
	filters domain.AuditFilters,
) (string, []any) {
	clauses := make([]string, 0, 3)
	args := make([]any, 0, 3)

	if filters.FromUnix != nil {
		clauses = append(
			clauses,
			"a.created_at_unix >= ?",
		)
		args = append(args, *filters.FromUnix)
	}
	if filters.ToUnix != nil {
		clauses = append(
			clauses,
			"a.created_at_unix <= ?",
		)
		args = append(args, *filters.ToUnix)
	}
	if filters.Status != "" {
		clauses = append(
			clauses,
			"a.status = ?",
		)
		args = append(args, filters.Status)
	}

	if len(clauses) == 0 {
		return "", args
	}

	return " AND " + strings.Join(clauses, " AND "), args
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}
