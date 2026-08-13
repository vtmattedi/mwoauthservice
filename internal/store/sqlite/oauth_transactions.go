package sqlite

import (
	"context"
	"fmt"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
)

func (s *Store) CreateOAuthTransaction(
	ctx context.Context,
	transaction domain.OAuthTransaction,
	limits domain.OAuthLimits,
	nowUnix int64,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf(
			"begin OAuth transaction creation: %w",
			err,
		)
	}

	rollback := func() {
		_ = tx.Rollback()
	}

	rateChecks := []struct {
		reason string
		query  string
		since  int64
		limit  int
	}{
		{
			reason: "per_minute",
			query: `SELECT COUNT(*)
                    FROM oauth_transactions
                    WHERE project_id = ?
                      AND provider = ?
                      AND created_at_unix >= ?`,
			since: nowUnix - 60,
			limit: limits.PerMinute,
		},
		{
			reason: "per_hour",
			query: `SELECT COUNT(*)
                    FROM oauth_transactions
                    WHERE project_id = ?
                      AND provider = ?
                      AND created_at_unix >= ?`,
			since: nowUnix - 3600,
			limit: limits.PerHour,
		},
	}

	for _, check := range rateChecks {
		var count int

		if err := tx.QueryRowContext(
			ctx,
			check.query,
			transaction.ProjectID,
			transaction.Provider,
			check.since,
		).Scan(&count); err != nil {
			rollback()
			return fmt.Errorf(
				"check OAuth rate limit %s: %w",
				check.reason,
				err,
			)
		}

		if count >= check.limit {
			rollback()
			return &oauth.RateLimitError{
				Reason: check.reason,
			}
		}
	}

	var pending int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
         FROM oauth_transactions
         WHERE project_id = ?
           AND provider = ?
           AND status IN ('pending', 'processing')
           AND expires_at_unix > ?`,
		transaction.ProjectID,
		transaction.Provider,
		nowUnix,
	).Scan(&pending); err != nil {
		rollback()
		return fmt.Errorf(
			"check pending OAuth transaction limit: %w",
			err,
		)
	}

	if pending >= limits.MaxPending {
		rollback()
		return &oauth.RateLimitError{
			Reason: "max_pending",
		}
	}

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO oauth_transactions(
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
            created_at_unix
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transaction.ID,
		transaction.ProjectID,
		transaction.Provider,
		transaction.StateHash,
		transaction.PKCEVerifierCiphertext,
		transaction.PKCEVerifierNonce,
		transaction.ClientReference,
		transaction.CallbackURL,
		transaction.ReturnURL,
		transaction.RequestedScopesJSON,
		transaction.Status,
		transaction.ExpiresAtUnix,
		transaction.CreatedAtUnix,
	)
	if err != nil {
		rollback()
		return fmt.Errorf(
			"insert OAuth transaction: %w",
			err,
		)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf(
			"commit OAuth transaction creation: %w",
			err,
		)
	}

	return nil
}
