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

const googleProvider = "google"

func (s *Store) GetGoogleOAuthConfig(
	ctx context.Context,
	projectID int64,
) (domain.GoogleOAuthConfig, error) {
	var config domain.GoogleOAuthConfig
	var enabled int

	err := s.db.QueryRowContext(
		ctx,
		`SELECT
            enabled,
            rate_per_minute,
            rate_per_hour,
            max_pending_transactions
         FROM project_oauth_configs
         WHERE project_id = ?
           AND provider = ?
         LIMIT 1`,
		projectID,
		googleProvider,
	).Scan(
		&enabled,
		&config.Limits.PerMinute,
		&config.Limits.PerHour,
		&config.Limits.MaxPending,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.GoogleOAuthConfig{}, project.ErrNotFound
		}
		return domain.GoogleOAuthConfig{}, fmt.Errorf(
			"get Google OAuth config: %w",
			err,
		)
	}

	config.Enabled = enabled != 0

	config.AllowedScopes, err = s.queryProjectPolicyValues(
		ctx,
		`SELECT scope
         FROM project_oauth_scopes
         WHERE project_id = ?
           AND provider = ?
         ORDER BY scope ASC`,
		projectID,
		googleProvider,
	)
	if err != nil {
		return domain.GoogleOAuthConfig{}, err
	}

	config.AllowedCallbackURLs, err = s.queryProjectPolicyValues(
		ctx,
		`SELECT url
         FROM project_oauth_callback_urls
         WHERE project_id = ?
           AND provider = ?
         ORDER BY url ASC`,
		projectID,
		googleProvider,
	)
	if err != nil {
		return domain.GoogleOAuthConfig{}, err
	}

	config.AllowedReturnURLs, err = s.queryProjectPolicyValues(
		ctx,
		`SELECT url
         FROM project_oauth_return_urls
         WHERE project_id = ?
           AND provider = ?
         ORDER BY url ASC`,
		projectID,
		googleProvider,
	)
	if err != nil {
		return domain.GoogleOAuthConfig{}, err
	}

	return config, nil
}

func (s *Store) ReplaceGoogleOAuthConfig(
	ctx context.Context,
	projectID int64,
	config domain.GoogleOAuthConfig,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin Google config update: %w", err)
	}

	rollback := func() {
		_ = tx.Rollback()
	}

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO project_oauth_configs(
            project_id,
            provider,
            enabled,
            rate_per_minute,
            rate_per_hour,
            max_pending_transactions
         ) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(project_id, provider) DO UPDATE SET
            enabled = excluded.enabled,
            rate_per_minute = excluded.rate_per_minute,
            rate_per_hour = excluded.rate_per_hour,
            max_pending_transactions = excluded.max_pending_transactions,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`,
		projectID,
		googleProvider,
		boolInt(config.Enabled),
		config.Limits.PerMinute,
		config.Limits.PerHour,
		config.Limits.MaxPending,
	)
	if err != nil {
		rollback()
		if isForeignKeyConstraint(err) {
			return project.ErrNotFound
		}
		return fmt.Errorf("upsert Google OAuth config: %w", err)
	}

	for _, table := range []string{
		"project_oauth_scopes",
		"project_oauth_callback_urls",
		"project_oauth_return_urls",
	} {
		query := fmt.Sprintf(
			"DELETE FROM %s WHERE project_id = ? AND provider = ?",
			table,
		)
		if _, err := tx.ExecContext(
			ctx,
			query,
			projectID,
			googleProvider,
		); err != nil {
			rollback()
			return fmt.Errorf(
				"clear Google policy table %s: %w",
				table,
				err,
			)
		}
	}

	if err := insertPolicyValues(
		ctx,
		tx,
		`INSERT INTO project_oauth_scopes(
            project_id,
            provider,
            scope
         ) VALUES (?, ?, ?)`,
		projectID,
		config.AllowedScopes,
	); err != nil {
		rollback()
		return err
	}

	if err := insertPolicyValues(
		ctx,
		tx,
		`INSERT INTO project_oauth_callback_urls(
            project_id,
            provider,
            url
         ) VALUES (?, ?, ?)`,
		projectID,
		config.AllowedCallbackURLs,
	); err != nil {
		rollback()
		return err
	}

	if err := insertPolicyValues(
		ctx,
		tx,
		`INSERT INTO project_oauth_return_urls(
            project_id,
            provider,
            url
         ) VALUES (?, ?, ?)`,
		projectID,
		config.AllowedReturnURLs,
	); err != nil {
		rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Google config update: %w", err)
	}

	return nil
}

func (s *Store) queryProjectPolicyValues(
	ctx context.Context,
	query string,
	projectID int64,
	provider string,
) ([]string, error) {
	rows, err := s.db.QueryContext(
		ctx,
		query,
		projectID,
		provider,
	)
	if err != nil {
		return nil, fmt.Errorf("query project OAuth policy: %w", err)
	}

	values := make([]string, 0)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf(
				"scan project OAuth policy: %w",
				err,
			)
		}
		values = append(values, value)
	}

	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf(
			"iterate project OAuth policy: %w",
			err,
		)
	}

	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf(
			"close project OAuth policy rows: %w",
			err,
		)
	}

	return values, nil
}

func insertPolicyValues(
	ctx context.Context,
	tx *sql.Tx,
	statement string,
	projectID int64,
	values []string,
) error {
	for _, value := range values {
		if _, err := tx.ExecContext(
			ctx,
			statement,
			projectID,
			googleProvider,
			value,
		); err != nil {
			return fmt.Errorf(
				"insert project OAuth policy: %w",
				err,
			)
		}
	}

	return nil
}

func isForeignKeyConstraint(err error) bool {
	return strings.Contains(
		strings.ToLower(err.Error()),
		"foreign key constraint failed",
	)
}
