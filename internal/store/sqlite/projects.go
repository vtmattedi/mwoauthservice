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
		`SELECT id, name, enabled, created_at, updated_at
         FROM projects
         ORDER BY name COLLATE NOCASE ASC, id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	projects := make([]domain.Project, 0)
	for rows.Next() {
		var item domain.Project
		var enabled int

		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&enabled,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}

		item.Enabled = enabled != 0
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
            token_hash,
            callback_secret_ciphertext,
            callback_secret_nonce,
            callback_secret_key_version,
            enabled
        ) VALUES (?, ?, ?, ?, ?, ?)`,
		record.Name,
		record.TokenHash,
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
			`SELECT id, name, enabled, created_at, updated_at
             FROM projects
             WHERE id = ?
             LIMIT 1`,
			id,
		),
	)
}

func (s *Store) GetProjectByTokenHash(
	ctx context.Context,
	tokenHash string,
) (domain.Project, error) {
	return scanProject(
		s.db.QueryRowContext(
			ctx,
			`SELECT id, name, enabled, created_at, updated_at
             FROM projects
             WHERE token_hash = ?
             LIMIT 1`,
			tokenHash,
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

func (s *Store) UpdateProjectTokenHash(
	ctx context.Context,
	id int64,
	tokenHash string,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE projects
         SET
            token_hash = ?,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?`,
		tokenHash,
		id,
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return project.ErrConflict
		}
		return fmt.Errorf("rotate project API key: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read API key rotation rows: %w", err)
	}
	if affected == 0 {
		return project.ErrNotFound
	}

	return nil
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

func scanProject(row *sql.Row) (domain.Project, error) {
	var item domain.Project
	var enabled int

	err := row.Scan(
		&item.ID,
		&item.Name,
		&enabled,
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
