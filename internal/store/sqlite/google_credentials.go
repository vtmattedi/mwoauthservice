package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
)

// googleCredentialMetadataColumns never includes secret_ciphertext or
// secret_nonce: metadata reads cannot leak ciphertext by construction.
const googleCredentialMetadataColumns = `
	id, project_id, client_id, state, source,
	secret_key_version, secret_deleted_at,
	created_at, updated_at, retired_at, disabled_at,
	last_authorized_at, last_refreshed_at`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanGoogleCredential(row rowScanner) (domain.GoogleCredential, error) {
	var (
		c                                                  domain.GoogleCredential
		state, source                                      string
		keyVersion                                         sql.NullInt64
		secretDeleted, retired, disabled, authorized, refr sql.NullString
	)

	if err := row.Scan(
		&c.ID, &c.ProjectID, &c.ClientID, &state, &source,
		&keyVersion, &secretDeleted,
		&c.CreatedAt, &c.UpdatedAt, &retired, &disabled,
		&authorized, &refr,
	); err != nil {
		return domain.GoogleCredential{}, err
	}

	c.State = domain.GoogleCredentialState(state)
	c.Source = domain.GoogleCredentialSource(source)
	c.SecretAvailable = !secretDeleted.Valid && keyVersion.Valid
	if keyVersion.Valid {
		c.KeyVersion = int(keyVersion.Int64)
	}
	c.SecretDeletedAt = secretDeleted.String
	c.RetiredAt = retired.String
	c.DisabledAt = disabled.String
	c.LastAuthorizedAt = authorized.String
	c.LastRefreshedAt = refr.String

	return c, nil
}

func (s *Store) ActivateCredential(
	ctx context.Context,
	record googlecred.NewRecord,
	now string,
) (domain.GoogleCredential, *domain.GoogleCredential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.GoogleCredential{}, nil, fmt.Errorf(
			"begin google credential activation: %w", err,
		)
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?)`,
		record.ProjectID,
	).Scan(&exists); err != nil {
		return domain.GoogleCredential{}, nil, fmt.Errorf(
			"check project for google credential: %w", err,
		)
	}
	if exists == 0 {
		return domain.GoogleCredential{}, nil, googlecred.ErrProjectNotFound
	}

	// Demote the current active credential first so the partial unique index
	// is never violated.
	var retired *domain.GoogleCredential
	var previousID sql.NullString
	err = tx.QueryRowContext(
		ctx,
		`SELECT id FROM google_client_credentials
		 WHERE project_id = ? AND provider = ? AND state = 'active'`,
		record.ProjectID, googleProvider,
	).Scan(&previousID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return domain.GoogleCredential{}, nil, fmt.Errorf(
			"find active google credential: %w", err,
		)
	}

	if previousID.Valid {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE google_client_credentials
			 SET state = 'retiring', retired_at = ?, updated_at = ?
			 WHERE id = ? AND project_id = ? AND state = 'active'`,
			now, now, previousID.String, record.ProjectID,
		); err != nil {
			return domain.GoogleCredential{}, nil, fmt.Errorf(
				"retire previous google credential: %w", err,
			)
		}
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO google_client_credentials(
			id, project_id, provider, client_id,
			secret_ciphertext, secret_nonce, secret_key_version,
			state, source, created_at, updated_at
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 'project', ?, ?)`,
		record.ID, record.ProjectID, googleProvider, record.ClientID,
		record.Ciphertext, record.Nonce, record.KeyVersion, now, now,
	); err != nil {
		return domain.GoogleCredential{}, nil, fmt.Errorf(
			"insert google credential: %w", err,
		)
	}

	created, err := scanGoogleCredential(tx.QueryRowContext(
		ctx,
		`SELECT`+googleCredentialMetadataColumns+`
		 FROM google_client_credentials WHERE id = ?`,
		record.ID,
	))
	if err != nil {
		return domain.GoogleCredential{}, nil, fmt.Errorf(
			"read created google credential: %w", err,
		)
	}

	if previousID.Valid {
		prev, err := scanGoogleCredential(tx.QueryRowContext(
			ctx,
			`SELECT`+googleCredentialMetadataColumns+`
			 FROM google_client_credentials WHERE id = ?`,
			previousID.String,
		))
		if err != nil {
			return domain.GoogleCredential{}, nil, fmt.Errorf(
				"read retired google credential: %w", err,
			)
		}
		retired = &prev
	}

	if err := tx.Commit(); err != nil {
		return domain.GoogleCredential{}, nil, fmt.Errorf(
			"commit google credential activation: %w", err,
		)
	}

	return created, retired, nil
}

func (s *Store) GetCredential(
	ctx context.Context,
	projectID int64,
	id string,
) (domain.GoogleCredential, error) {
	c, err := scanGoogleCredential(s.db.QueryRowContext(
		ctx,
		`SELECT`+googleCredentialMetadataColumns+`
		 FROM google_client_credentials
		 WHERE id = ? AND project_id = ? AND provider = ?`,
		id, projectID, googleProvider,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.GoogleCredential{}, googlecred.ErrNotFound
		}
		return domain.GoogleCredential{}, fmt.Errorf("get google credential: %w", err)
	}
	return c, nil
}

func (s *Store) GetActiveCredential(
	ctx context.Context,
	projectID int64,
) (domain.GoogleCredential, error) {
	c, err := scanGoogleCredential(s.db.QueryRowContext(
		ctx,
		`SELECT`+googleCredentialMetadataColumns+`
		 FROM google_client_credentials
		 WHERE project_id = ? AND provider = ? AND state = 'active'`,
		projectID, googleProvider,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.GoogleCredential{}, googlecred.ErrNotFound
		}
		return domain.GoogleCredential{}, fmt.Errorf("get active google credential: %w", err)
	}
	return c, nil
}

func (s *Store) ListCredentials(
	ctx context.Context,
	projectID int64,
) ([]domain.GoogleCredential, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT`+googleCredentialMetadataColumns+`
		 FROM google_client_credentials
		 WHERE project_id = ? AND provider = ?
		 ORDER BY created_at DESC, id ASC`,
		projectID, googleProvider,
	)
	if err != nil {
		return nil, fmt.Errorf("list google credentials: %w", err)
	}
	defer rows.Close()

	result := []domain.GoogleCredential{}
	for rows.Next() {
		c, err := scanGoogleCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("scan google credential: %w", err)
		}
		result = append(result, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list google credentials: %w", err)
	}
	return result, nil
}

func (s *Store) GetCredentialSecret(
	ctx context.Context,
	projectID int64,
	id string,
) (googlecred.SecretRecord, error) {
	credential, err := s.GetCredential(ctx, projectID, id)
	if err != nil {
		return googlecred.SecretRecord{}, err
	}
	if !credential.SecretAvailable {
		return googlecred.SecretRecord{}, googlecred.ErrSecretUnavailable
	}

	var record googlecred.SecretRecord
	record.Credential = credential

	if err := s.db.QueryRowContext(
		ctx,
		`SELECT secret_ciphertext, secret_nonce, secret_key_version
		 FROM google_client_credentials
		 WHERE id = ? AND project_id = ? AND provider = ?
		   AND secret_deleted_at IS NULL`,
		id, projectID, googleProvider,
	).Scan(&record.Ciphertext, &record.Nonce, &record.KeyVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return googlecred.SecretRecord{}, googlecred.ErrSecretUnavailable
		}
		return googlecred.SecretRecord{}, fmt.Errorf("get google credential secret: %w", err)
	}

	return record, nil
}

func (s *Store) TransitionCredential(
	ctx context.Context,
	projectID int64,
	id string,
	to domain.GoogleCredentialState,
	now string,
) (domain.GoogleCredential, error) {
	var set string
	switch to {
	case domain.GoogleCredentialRetiring:
		set = "state = 'retiring', retired_at = ?"
	case domain.GoogleCredentialDisabled:
		set = "state = 'disabled', disabled_at = ?"
	default:
		return domain.GoogleCredential{}, googlecred.ErrInvalidTransition
	}

	// The state guard is part of the UPDATE, so a concurrent transition
	// cannot be applied twice or out of order.
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE google_client_credentials
		 SET `+set+`, updated_at = ?
		 WHERE id = ? AND project_id = ? AND provider = ?
		   AND (
		     (? = 'retiring' AND state = 'active') OR
		     (? = 'disabled' AND state IN ('active', 'retiring'))
		   )`,
		now, now, id, projectID, googleProvider, string(to), string(to),
	)
	if err != nil {
		return domain.GoogleCredential{}, fmt.Errorf("transition google credential: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return domain.GoogleCredential{}, fmt.Errorf("transition google credential: %w", err)
	}
	if affected == 0 {
		// Distinguish "no such credential in this project" from "wrong state".
		if _, err := s.GetCredential(ctx, projectID, id); err != nil {
			return domain.GoogleCredential{}, err
		}
		return domain.GoogleCredential{}, googlecred.ErrInvalidTransition
	}

	return s.GetCredential(ctx, projectID, id)
}

func (s *Store) DeleteCredentialSecret(
	ctx context.Context,
	projectID int64,
	id string,
	now string,
) (domain.GoogleCredential, error) {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE google_client_credentials
		 SET secret_ciphertext = NULL,
		     secret_nonce = NULL,
		     secret_key_version = NULL,
		     secret_deleted_at = ?,
		     updated_at = ?
		 WHERE id = ? AND project_id = ? AND provider = ?
		   AND state = 'disabled'
		   AND secret_deleted_at IS NULL`,
		now, now, id, projectID, googleProvider,
	)
	if err != nil {
		return domain.GoogleCredential{}, fmt.Errorf("delete google credential secret: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return domain.GoogleCredential{}, fmt.Errorf("delete google credential secret: %w", err)
	}
	if affected == 0 {
		credential, err := s.GetCredential(ctx, projectID, id)
		if err != nil {
			return domain.GoogleCredential{}, err
		}
		if credential.State != domain.GoogleCredentialDisabled {
			return domain.GoogleCredential{}, googlecred.ErrInvalidTransition
		}
		// Already deleted: idempotent.
		return credential, nil
	}

	return s.GetCredential(ctx, projectID, id)
}

func (s *Store) CountPendingTransactions(
	ctx context.Context,
	projectID int64,
	id string,
	nowUnix int64,
) (int, error) {
	var count int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM oauth_transactions
		 WHERE project_id = ? AND provider = ? AND google_credential_id = ?
		   AND status IN ('pending', 'processing')
		   AND expires_at_unix > ?`,
		projectID, googleProvider, id, nowUnix,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count pending google credential transactions: %w", err)
	}
	return count, nil
}

func (s *Store) MarkAuthorized(ctx context.Context, projectID int64, id string, now string) error {
	return s.touchCredential(ctx, "last_authorized_at", projectID, id, now)
}

func (s *Store) MarkRefreshed(ctx context.Context, projectID int64, id string, now string) error {
	return s.touchCredential(ctx, "last_refreshed_at", projectID, id, now)
}

func (s *Store) touchCredential(
	ctx context.Context,
	column string,
	projectID int64,
	id string,
	now string,
) error {
	// column is one of two internal constants, never caller input.
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE google_client_credentials SET `+column+` = ?
		 WHERE id = ? AND project_id = ? AND provider = ?`,
		now, id, projectID, googleProvider,
	)
	if err != nil {
		return fmt.Errorf("update google credential usage: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update google credential usage: %w", err)
	}
	if affected == 0 {
		return googlecred.ErrNotFound
	}
	return nil
}

var _ googlecred.Store = (*Store)(nil)
