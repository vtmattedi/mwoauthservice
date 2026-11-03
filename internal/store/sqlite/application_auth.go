package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
)

const appClientColumns = `
	c.id, c.project_id, c.client_id, c.display_name, c.enabled,
	c.allowed_scopes, c.created_at, c.updated_at`

func scanAppClient(row rowScanner) (appauth.Client, error) {
	var (
		c       appauth.Client
		enabled int
		scopes  string
	)
	if err := row.Scan(
		&c.PK, &c.ProjectID, &c.ClientID, &c.DisplayName, &enabled,
		&scopes, &c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return appauth.Client{}, err
	}
	c.Enabled = enabled != 0
	c.AllowedScopes = splitScopes(scopes)
	c.Secrets = []appauth.SecretInfo{}
	return c, nil
}

func splitScopes(s string) []string {
	fields := strings.Fields(s)
	if fields == nil {
		return []string{}
	}
	return fields
}

func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func loadSecrets(ctx context.Context, q queryer, clientPK int64) ([]appauth.SecretInfo, error) {
	rows, err := q.QueryContext(
		ctx,
		`SELECT id, state, created_at, revoked_at, last_used_at
		 FROM mw_application_client_secrets
		 WHERE client_pk = ?
		 ORDER BY id ASC`,
		clientPK,
	)
	if err != nil {
		return nil, fmt.Errorf("list application client secrets: %w", err)
	}
	defer rows.Close()

	secrets := []appauth.SecretInfo{}
	for rows.Next() {
		var (
			s                   appauth.SecretInfo
			revoked, lastUsedAt sql.NullString
		)
		if err := rows.Scan(&s.ID, &s.State, &s.CreatedAt, &revoked, &lastUsedAt); err != nil {
			return nil, fmt.Errorf("scan application client secret: %w", err)
		}
		s.RevokedAt = revoked.String
		s.LastUsedAt = lastUsedAt.String
		secrets = append(secrets, s)
	}
	return secrets, rows.Err()
}

func (s *Store) CreateClient(
	ctx context.Context,
	projectID int64,
	clientID string,
	displayName string,
	allowedScopes []string,
	secretHash string,
	now string,
) (appauth.Client, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return appauth.Client{}, fmt.Errorf("begin application client creation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var projectExists, clientExists int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT
			EXISTS(SELECT 1 FROM projects WHERE id = ?),
			EXISTS(SELECT 1 FROM mw_application_clients WHERE project_id = ?)`,
		projectID, projectID,
	).Scan(&projectExists, &clientExists); err != nil {
		return appauth.Client{}, fmt.Errorf("check application client preconditions: %w", err)
	}
	if projectExists == 0 {
		return appauth.Client{}, appauth.ErrNotFound
	}
	if clientExists != 0 {
		return appauth.Client{}, appauth.ErrConflict
	}

	result, err := tx.ExecContext(
		ctx,
		`INSERT INTO mw_application_clients(
			project_id, client_id, display_name, enabled, allowed_scopes,
			created_at, updated_at
		 ) VALUES (?, ?, ?, 1, ?, ?, ?)`,
		projectID, clientID, displayName, joinScopes(allowedScopes), now, now,
	)
	if err != nil {
		return appauth.Client{}, fmt.Errorf("insert application client: %w", err)
	}
	clientPK, err := result.LastInsertId()
	if err != nil {
		return appauth.Client{}, fmt.Errorf("application client id: %w", err)
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO mw_application_client_secrets(client_pk, secret_hash, state, created_at)
		 VALUES (?, ?, 'active', ?)`,
		clientPK, secretHash, now,
	); err != nil {
		return appauth.Client{}, fmt.Errorf("insert application client secret: %w", err)
	}

	client, err := scanAppClient(tx.QueryRowContext(
		ctx,
		`SELECT`+appClientColumns+` FROM mw_application_clients c WHERE c.id = ?`,
		clientPK,
	))
	if err != nil {
		return appauth.Client{}, fmt.Errorf("read application client: %w", err)
	}
	if client.Secrets, err = loadSecrets(ctx, tx, clientPK); err != nil {
		return appauth.Client{}, err
	}

	if err := tx.Commit(); err != nil {
		return appauth.Client{}, fmt.Errorf("commit application client creation: %w", err)
	}
	return client, nil
}

func (s *Store) GetClientByProject(
	ctx context.Context,
	projectID int64,
) (appauth.Client, error) {
	client, err := scanAppClient(s.db.QueryRowContext(
		ctx,
		`SELECT`+appClientColumns+` FROM mw_application_clients c WHERE c.project_id = ?`,
		projectID,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return appauth.Client{}, appauth.ErrNotFound
		}
		return appauth.Client{}, fmt.Errorf("get application client: %w", err)
	}
	if client.Secrets, err = loadSecrets(ctx, s.db, client.PK); err != nil {
		return appauth.Client{}, err
	}
	return client, nil
}

func (s *Store) GetAuthRecord(
	ctx context.Context,
	clientID string,
) (appauth.AuthRecord, error) {
	var (
		record         appauth.AuthRecord
		projectEnabled int
	)

	row := s.db.QueryRowContext(
		ctx,
		`SELECT`+appClientColumns+`, p.enabled
		 FROM mw_application_clients c
		 JOIN projects p ON p.id = c.project_id
		 WHERE c.client_id = ?`,
		clientID,
	)

	var (
		c       appauth.Client
		enabled int
		scopes  string
	)
	if err := row.Scan(
		&c.PK, &c.ProjectID, &c.ClientID, &c.DisplayName, &enabled,
		&scopes, &c.CreatedAt, &c.UpdatedAt, &projectEnabled,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return appauth.AuthRecord{}, appauth.ErrNotFound
		}
		return appauth.AuthRecord{}, fmt.Errorf("get application auth record: %w", err)
	}
	c.Enabled = enabled != 0
	c.AllowedScopes = splitScopes(scopes)
	c.Secrets = []appauth.SecretInfo{}
	record.Client = c
	record.ProjectEnabled = projectEnabled != 0

	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, secret_hash FROM mw_application_client_secrets
		 WHERE client_pk = ? AND state = 'active'`,
		c.PK,
	)
	if err != nil {
		return appauth.AuthRecord{}, fmt.Errorf("list active application secrets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var h appauth.SecretHash
		if err := rows.Scan(&h.ID, &h.Hash); err != nil {
			return appauth.AuthRecord{}, fmt.Errorf("scan application secret hash: %w", err)
		}
		record.ActiveSecrets = append(record.ActiveSecrets, h)
	}
	if err := rows.Err(); err != nil {
		return appauth.AuthRecord{}, err
	}

	return record, nil
}

func (s *Store) AddSecret(
	ctx context.Context,
	projectID int64,
	secretHash string,
	maxActive int,
	now string,
) (appauth.SecretInfo, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return appauth.SecretInfo{}, fmt.Errorf("begin application secret creation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var clientPK int64
	if err := tx.QueryRowContext(
		ctx,
		`SELECT id FROM mw_application_clients WHERE project_id = ?`, projectID,
	).Scan(&clientPK); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return appauth.SecretInfo{}, appauth.ErrNotFound
		}
		return appauth.SecretInfo{}, fmt.Errorf("find application client: %w", err)
	}

	var active int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM mw_application_client_secrets
		 WHERE client_pk = ? AND state = 'active'`, clientPK,
	).Scan(&active); err != nil {
		return appauth.SecretInfo{}, fmt.Errorf("count active application secrets: %w", err)
	}
	if active >= maxActive {
		return appauth.SecretInfo{}, appauth.ErrTooManySecrets
	}

	result, err := tx.ExecContext(
		ctx,
		`INSERT INTO mw_application_client_secrets(client_pk, secret_hash, state, created_at)
		 VALUES (?, ?, 'active', ?)`,
		clientPK, secretHash, now,
	)
	if err != nil {
		return appauth.SecretInfo{}, fmt.Errorf("insert application secret: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return appauth.SecretInfo{}, fmt.Errorf("application secret id: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return appauth.SecretInfo{}, fmt.Errorf("commit application secret creation: %w", err)
	}
	return appauth.SecretInfo{ID: id, State: appauth.SecretStateActive, CreatedAt: now}, nil
}

func (s *Store) RevokeSecret(
	ctx context.Context,
	projectID int64,
	secretID int64,
	now string,
) (appauth.SecretInfo, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return appauth.SecretInfo{}, fmt.Errorf("begin application secret revoke: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The project join keeps a secret ID from another project unreachable.
	var (
		info                appauth.SecretInfo
		revoked, lastUsedAt sql.NullString
	)
	if err := tx.QueryRowContext(
		ctx,
		`SELECT s.id, s.state, s.created_at, s.revoked_at, s.last_used_at
		 FROM mw_application_client_secrets s
		 JOIN mw_application_clients c ON c.id = s.client_pk
		 WHERE s.id = ? AND c.project_id = ?`,
		secretID, projectID,
	).Scan(&info.ID, &info.State, &info.CreatedAt, &revoked, &lastUsedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return appauth.SecretInfo{}, appauth.ErrNotFound
		}
		return appauth.SecretInfo{}, fmt.Errorf("find application secret: %w", err)
	}
	info.RevokedAt = revoked.String
	info.LastUsedAt = lastUsedAt.String

	if info.State == appauth.SecretStateRevoked {
		return info, nil
	}

	if _, err := tx.ExecContext(
		ctx,
		`UPDATE mw_application_client_secrets
		 SET state = 'revoked', revoked_at = ? WHERE id = ?`,
		now, secretID,
	); err != nil {
		return appauth.SecretInfo{}, fmt.Errorf("revoke application secret: %w", err)
	}

	nowUnix, err := unixFromTimestamp(now)
	if err != nil {
		return appauth.SecretInfo{}, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE mw_application_access_tokens
		 SET revoked_at_unix = ?
		 WHERE secret_id = ? AND revoked_at_unix IS NULL AND expires_at_unix > ?`,
		nowUnix, secretID, nowUnix,
	); err != nil {
		return appauth.SecretInfo{}, fmt.Errorf("revoke application tokens: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return appauth.SecretInfo{}, fmt.Errorf("commit application secret revoke: %w", err)
	}

	info.State = appauth.SecretStateRevoked
	info.RevokedAt = now
	return info, nil
}

func (s *Store) UpdateClient(
	ctx context.Context,
	projectID int64,
	displayName *string,
	enabled *bool,
	allowedScopes []string,
	now string,
) (appauth.Client, error) {
	sets := []string{"updated_at = ?"}
	args := []any{now}

	if displayName != nil {
		sets = append(sets, "display_name = ?")
		args = append(args, *displayName)
	}
	if enabled != nil {
		value := 0
		if *enabled {
			value = 1
		}
		sets = append(sets, "enabled = ?")
		args = append(args, value)
	}
	if len(allowedScopes) > 0 {
		sets = append(sets, "allowed_scopes = ?")
		args = append(args, joinScopes(allowedScopes))
	}
	args = append(args, projectID)

	result, err := s.db.ExecContext(
		ctx,
		`UPDATE mw_application_clients SET `+strings.Join(sets, ", ")+` WHERE project_id = ?`,
		args...,
	)
	if err != nil {
		return appauth.Client{}, fmt.Errorf("update application client: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil {
		return appauth.Client{}, fmt.Errorf("update application client: %w", err)
	} else if n == 0 {
		return appauth.Client{}, appauth.ErrNotFound
	}

	return s.GetClientByProject(ctx, projectID)
}

func (s *Store) TouchSecret(ctx context.Context, secretID int64, now string) error {
	if _, err := s.db.ExecContext(
		ctx,
		`UPDATE mw_application_client_secrets SET last_used_at = ? WHERE id = ?`,
		now, secretID,
	); err != nil {
		return fmt.Errorf("touch application secret: %w", err)
	}
	return nil
}

func (s *Store) InsertToken(ctx context.Context, record appauth.TokenRecord) error {
	if _, err := s.db.ExecContext(
		ctx,
		`INSERT INTO mw_application_access_tokens(
			token_hash, client_pk, secret_id, project_id, scopes,
			issued_at_unix, expires_at_unix
		 ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		record.TokenHash, record.ClientPK, record.SecretID, record.ProjectID,
		joinScopes(record.Scopes), record.IssuedAtUnix, record.ExpiresAtUnix,
	); err != nil {
		return fmt.Errorf("insert application access token: %w", err)
	}
	return nil
}

func (s *Store) LookupToken(
	ctx context.Context,
	tokenHash string,
	nowUnix int64,
) (appauth.TokenLookup, error) {
	var (
		lookup                                        appauth.TokenLookup
		tokenScopes                                   string
		expires                                       int64
		revoked                                       sql.NullInt64
		secretState                                   string
		clientEnabled, projectEnabled                 int
		clientScopes                                  string
		clientDisplay, clientCreated, clientUpdatedAt string
	)

	err := s.db.QueryRowContext(
		ctx,
		`SELECT
			t.scopes, t.expires_at_unix, t.revoked_at_unix, sec.state,
			c.id, c.project_id, c.client_id, c.display_name, c.enabled,
			c.allowed_scopes, c.created_at, c.updated_at, p.enabled
		 FROM mw_application_access_tokens t
		 JOIN mw_application_client_secrets sec ON sec.id = t.secret_id
		 JOIN mw_application_clients c ON c.id = t.client_pk
		 JOIN projects p ON p.id = t.project_id
		 WHERE t.token_hash = ?`,
		tokenHash,
	).Scan(
		&tokenScopes, &expires, &revoked, &secretState,
		&lookup.Client.PK, &lookup.Client.ProjectID, &lookup.Client.ClientID,
		&clientDisplay, &clientEnabled, &clientScopes, &clientCreated,
		&clientUpdatedAt, &projectEnabled,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return appauth.TokenLookup{}, appauth.ErrNotFound
		}
		return appauth.TokenLookup{}, fmt.Errorf("lookup application access token: %w", err)
	}

	lookup.Client.DisplayName = clientDisplay
	lookup.Client.Enabled = clientEnabled != 0
	lookup.Client.AllowedScopes = splitScopes(clientScopes)
	lookup.Client.CreatedAt = clientCreated
	lookup.Client.UpdatedAt = clientUpdatedAt
	lookup.Client.Secrets = []appauth.SecretInfo{}
	lookup.Scopes = splitScopes(tokenScopes)
	lookup.ProjectEnabled = projectEnabled != 0
	lookup.SecretActive = secretState == appauth.SecretStateActive
	lookup.Revoked = revoked.Valid
	lookup.Expired = expires <= nowUnix

	return lookup, nil
}

func (s *Store) RevokeTokens(
	ctx context.Context,
	projectID int64,
	secretID *int64,
	nowUnix int64,
) (int64, error) {
	query := `UPDATE mw_application_access_tokens
		SET revoked_at_unix = ?
		WHERE project_id = ? AND revoked_at_unix IS NULL AND expires_at_unix > ?`
	args := []any{nowUnix, projectID, nowUnix}
	if secretID != nil {
		query += ` AND secret_id = ?`
		args = append(args, *secretID)
	}

	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("revoke application tokens: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("revoke application tokens: %w", err)
	}
	return n, nil
}

func (s *Store) DeleteExpiredTokens(ctx context.Context, cutoffUnix int64) (int64, error) {
	result, err := s.db.ExecContext(
		ctx,
		`DELETE FROM mw_application_access_tokens WHERE expires_at_unix <= ?`,
		cutoffUnix,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired application tokens: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired application tokens: %w", err)
	}
	return n, nil
}

var _ appauth.Store = (*Store)(nil)
