package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
)

func (s *Store) ConsumeOAuthTransactionByStateHash(
	ctx context.Context,
	stateHash string,
	nowUnix int64,
) (domain.OAuthTransaction, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.OAuthTransaction{}, fmt.Errorf(
			"begin OAuth callback transaction: %w",
			err,
		)
	}

	rollback := func() {
		_ = tx.Rollback()
	}

	transaction, err := scanOAuthTransaction(
		tx.QueryRowContext(
			ctx,
			`SELECT
                id,
                project_id,
                provider,
                state_hash,
                pkce_verifier_ciphertext,
                pkce_verifier_nonce,
                client_reference,
                callback_url,
                return_url,
                requested_scopes_json,
                status,
                expires_at_unix,
                consumed_at_unix,
                created_at,
                created_at_unix,
                COALESCE(google_credential_id, '')
             FROM oauth_transactions
             WHERE state_hash = ?
             LIMIT 1`,
			stateHash,
		),
	)
	if err != nil {
		rollback()

		if errors.Is(err, sql.ErrNoRows) {
			return domain.OAuthTransaction{},
				oauth.ErrTransactionNotFound
		}

		return domain.OAuthTransaction{}, fmt.Errorf(
			"load OAuth transaction by state: %w",
			err,
		)
	}

	if transaction.Status != "pending" {
		rollback()
		return transaction, oauth.ErrTransactionConsumed
	}

	if transaction.ExpiresAtUnix <= nowUnix {
		result, updateErr := tx.ExecContext(
			ctx,
			`UPDATE oauth_transactions
             SET
                status = 'expired',
                consumed_at_unix = ?
             WHERE id = ?
               AND status = 'pending'`,
			nowUnix,
			transaction.ID,
		)
		if updateErr != nil {
			rollback()
			return transaction, fmt.Errorf(
				"expire OAuth transaction: %w",
				updateErr,
			)
		}

		affected, updateErr := result.RowsAffected()
		if updateErr != nil {
			rollback()
			return transaction, fmt.Errorf(
				"read OAuth expiration rows: %w",
				updateErr,
			)
		}
		if affected != 1 {
			rollback()
			return transaction, oauth.ErrTransactionConsumed
		}

		if err := tx.Commit(); err != nil {
			return transaction, fmt.Errorf(
				"commit OAuth expiration: %w",
				err,
			)
		}

		consumedAt := nowUnix
		transaction.Status = "expired"
		transaction.ConsumedAtUnix = &consumedAt

		return transaction, oauth.ErrTransactionExpired
	}

	result, err := tx.ExecContext(
		ctx,
		`UPDATE oauth_transactions
         SET
            status = 'processing',
            consumed_at_unix = ?
         WHERE id = ?
           AND status = 'pending'`,
		nowUnix,
		transaction.ID,
	)
	if err != nil {
		rollback()
		return transaction, fmt.Errorf(
			"consume OAuth transaction: %w",
			err,
		)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		rollback()
		return transaction, fmt.Errorf(
			"read OAuth consume rows: %w",
			err,
		)
	}
	if affected != 1 {
		rollback()
		return transaction, oauth.ErrTransactionConsumed
	}

	if err := tx.Commit(); err != nil {
		return transaction, fmt.Errorf(
			"commit OAuth transaction consumption: %w",
			err,
		)
	}

	consumedAt := nowUnix
	transaction.Status = "processing"
	transaction.ConsumedAtUnix = &consumedAt

	return transaction, nil
}

func (s *Store) TransitionOAuthTransactionStatus(
	ctx context.Context,
	transactionID string,
	fromStatus string,
	toStatus string,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE oauth_transactions
         SET status = ?
         WHERE id = ?
           AND status = ?`,
		toStatus,
		transactionID,
		fromStatus,
	)
	if err != nil {
		return fmt.Errorf(
			"transition OAuth transaction status: %w",
			err,
		)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf(
			"read OAuth transition rows: %w",
			err,
		)
	}
	if affected != 1 {
		return oauth.ErrTransactionConsumed
	}

	return nil
}

type oauthTransactionScanner interface {
	Scan(dest ...any) error
}

func scanOAuthTransaction(
	row oauthTransactionScanner,
) (domain.OAuthTransaction, error) {
	var transaction domain.OAuthTransaction
	var consumedAt sql.NullInt64

	err := row.Scan(
		&transaction.ID,
		&transaction.ProjectID,
		&transaction.Provider,
		&transaction.StateHash,
		&transaction.PKCEVerifierCiphertext,
		&transaction.PKCEVerifierNonce,
		&transaction.ClientReference,
		&transaction.CallbackURL,
		&transaction.ReturnURL,
		&transaction.RequestedScopesJSON,
		&transaction.Status,
		&transaction.ExpiresAtUnix,
		&consumedAt,
		&transaction.CreatedAt,
		&transaction.CreatedAtUnix,
		&transaction.GoogleCredentialID,
	)
	if err != nil {
		return domain.OAuthTransaction{}, err
	}

	if consumedAt.Valid {
		value := consumedAt.Int64
		transaction.ConsumedAtUnix = &value
	}

	return transaction, nil
}
