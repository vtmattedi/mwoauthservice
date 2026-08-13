package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

func (s *Store) GetProjectCallbackSecret(
	ctx context.Context,
	projectID int64,
) (project.CallbackSecretRecord, error) {
	var record project.CallbackSecretRecord

	err := s.db.QueryRowContext(
		ctx,
		`SELECT
            callback_secret_ciphertext,
            callback_secret_nonce,
            callback_secret_key_version
         FROM projects
         WHERE id = ?
         LIMIT 1`,
		projectID,
	).Scan(
		&record.Ciphertext,
		&record.Nonce,
		&record.KeyVersion,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return project.CallbackSecretRecord{},
				project.ErrNotFound
		}

		return project.CallbackSecretRecord{}, fmt.Errorf(
			"get project callback secret: %w",
			err,
		)
	}

	return record, nil
}
