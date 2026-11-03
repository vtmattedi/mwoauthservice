package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

func (s *Store) ListProjects(
	ctx context.Context,
) ([]domain.Project, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT `+projectColumns+`
         FROM projects
         ORDER BY name COLLATE NOCASE ASC, id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	projects := make([]domain.Project, 0)
	for rows.Next() {
		item, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		projects = append(projects, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate projects: %w", err)
	}

	return projects, nil
}

func (s *Store) CreateProject(
	ctx context.Context,
	record project.CreateRecord,
) (domain.Project, error) {
	result, err := s.db.ExecContext(
		ctx,
		`INSERT INTO projects(
            name,
            callback_secret_ciphertext,
            callback_secret_nonce,
            callback_secret_key_version,
            enabled
        ) VALUES (?, ?, ?, ?, ?)`,
		record.Name,
		record.CallbackSecretCiphertext,
		record.CallbackSecretNonce,
		record.CallbackSecretKeyVersion,
		boolInt(record.Enabled),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return domain.Project{}, project.ErrConflict
		}
		return domain.Project{}, fmt.Errorf(
			"create project: %w",
			err,
		)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return domain.Project{}, fmt.Errorf(
			"read project id: %w",
			err,
		)
	}

	return s.GetProject(ctx, id)
}

func (s *Store) GetProject(
	ctx context.Context,
	id int64,
) (domain.Project, error) {
	return scanProject(
		s.db.QueryRowContext(
			ctx,
			`SELECT `+projectColumns+`
             FROM projects
             WHERE id = ?
             LIMIT 1`,
			id,
		),
	)
}

func (s *Store) UpdateProject(
	ctx context.Context,
	id int64,
	name string,
	enabled bool,
) (domain.Project, error) {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE projects
         SET
            name = ?,
            enabled = ?,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?`,
		name,
		boolInt(enabled),
		id,
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return domain.Project{}, project.ErrConflict
		}
		return domain.Project{}, fmt.Errorf(
			"update project: %w",
			err,
		)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return domain.Project{}, fmt.Errorf(
			"read project update rows: %w",
			err,
		)
	}
	if affected == 0 {
		return domain.Project{}, project.ErrNotFound
	}

	return s.GetProject(ctx, id)
}

func (s *Store) DeleteProject(
	ctx context.Context,
	id int64,
	event domain.AuditEvent,
) (domain.Project, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Project{}, fmt.Errorf(
			"begin project deletion: %w",
			err,
		)
	}
	defer func() { _ = tx.Rollback() }()

	deleted, err := scanProject(tx.QueryRowContext(
		ctx,
		`SELECT `+projectColumns+`
         FROM projects
         WHERE id = ?
         LIMIT 1`,
		id,
	))
	if err != nil {
		return domain.Project{}, err
	}

	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM projects WHERE id = ?`,
		id,
	)
	if err != nil {
		if isForeignKeyConstraint(err) {
			return domain.Project{}, project.ErrDependencies
		}
		return domain.Project{}, fmt.Errorf("delete project: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.Project{}, fmt.Errorf(
			"read project deletion rows: %w",
			err,
		)
	}
	if affected != 1 {
		return domain.Project{}, project.ErrNotFound
	}

	metadata := make(map[string]any, len(event.Metadata)+2)
	for key, value := range event.Metadata {
		metadata[key] = value
	}
	metadata["project_id"] = deleted.ID
	metadata["project_name"] = deleted.Name
	event.Metadata = metadata

	if _, err := insertAuditEvent(ctx, tx, event); err != nil {
		return domain.Project{}, fmt.Errorf(
			"record project deletion audit: %w",
			err,
		)
	}

	if err := tx.Commit(); err != nil {
		if isForeignKeyConstraint(err) {
			return domain.Project{}, project.ErrDependencies
		}
		return domain.Project{}, fmt.Errorf(
			"commit project deletion: %w",
			err,
		)
	}

	return deleted, nil
}

func (s *Store) UpdateProjectCallbackSecret(
	ctx context.Context,
	id int64,
	ciphertext string,
	nonce string,
	keyVersion int,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE projects
         SET
            callback_secret_ciphertext = ?,
            callback_secret_nonce = ?,
            callback_secret_key_version = ?,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?`,
		ciphertext,
		nonce,
		keyVersion,
		id,
	)
	if err != nil {
		return fmt.Errorf(
			"rotate project callback secret: %w",
			err,
		)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf(
			"read callback secret rotation rows: %w",
			err,
		)
	}
	if affected == 0 {
		return project.ErrNotFound
	}

	return nil
}

// projectColumns lists the columns scanProject expects, in order.
const projectColumns = `id, name, enabled,
	EXISTS(
		SELECT 1 FROM mw_application_clients c
		WHERE c.project_id = projects.id
	),
	created_at, updated_at`

func scanProject(row rowScanner) (domain.Project, error) {
	var item domain.Project
	var enabled, hasClient int

	err := row.Scan(
		&item.ID,
		&item.Name,
		&enabled,
		&hasClient,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Project{}, project.ErrNotFound
		}
		return domain.Project{}, fmt.Errorf(
			"scan project: %w",
			err,
		)
	}

	item.Enabled = enabled != 0
	item.AppCredentialsConfigured = hasClient != 0
	return item, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func isUniqueConstraint(err error) bool {
	return strings.Contains(
		strings.ToLower(err.Error()),
		"unique constraint failed",
	)
}
