package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/vtmattedi/mw-oauth-service/internal/adminwebauthn"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

func (s *Store) EnsureWebAuthnUser(
	ctx context.Context,
	adminUserID int64,
	rpid string,
	userHandle []byte,
) (adminwebauthn.UserRecord, error) {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO admin_webauthn_users(
            admin_user_id,
            rpid,
            user_handle
        ) VALUES (?, ?, ?)
        ON CONFLICT(admin_user_id, rpid) DO NOTHING`,
		adminUserID,
		rpid,
		userHandle,
	)
	if err != nil {
		return adminwebauthn.UserRecord{}, fmt.Errorf(
			"ensure WebAuthn user: %w",
			err,
		)
	}

	return s.GetWebAuthnUser(ctx, adminUserID, rpid)
}

func (s *Store) GetWebAuthnUser(
	ctx context.Context,
	adminUserID int64,
	rpid string,
) (adminwebauthn.UserRecord, error) {
	var record adminwebauthn.UserRecord

	err := s.db.QueryRowContext(
		ctx,
		`SELECT
            id,
            admin_user_id,
            rpid,
            user_handle,
            created_at
        FROM admin_webauthn_users
        WHERE admin_user_id = ?
          AND rpid = ?
        LIMIT 1`,
		adminUserID,
		rpid,
	).Scan(
		&record.ID,
		&record.AdminUserID,
		&record.RPID,
		&record.UserHandle,
		&record.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminwebauthn.UserRecord{},
				adminwebauthn.ErrNotFound
		}
		return adminwebauthn.UserRecord{}, fmt.Errorf(
			"get WebAuthn user: %w",
			err,
		)
	}

	return record, nil
}

func (s *Store) FindWebAuthnUserForCredential(
	ctx context.Context,
	rpid string,
	userHandle []byte,
	credentialID []byte,
) (
	domain.AdminUser,
	adminwebauthn.UserRecord,
	error,
) {
	var adminUser domain.AdminUser
	var userRecord adminwebauthn.UserRecord
	var enabled int

	err := s.db.QueryRowContext(
		ctx,
		`SELECT
            u.id,
            u.email,
            u.password_hash,
            u.enabled,
            u.created_at,
            u.updated_at,
            wu.id,
            wu.admin_user_id,
            wu.rpid,
            wu.user_handle,
            wu.created_at
        FROM admin_webauthn_users AS wu
        JOIN admin_users AS u
          ON u.id = wu.admin_user_id
        JOIN admin_webauthn_credentials AS c
          ON c.admin_user_id = u.id
         AND c.rpid = wu.rpid
        WHERE wu.rpid = ?
          AND wu.user_handle = ?
          AND c.credential_id = ?
          AND c.revoked_at IS NULL
        LIMIT 1`,
		rpid,
		userHandle,
		credentialID,
	).Scan(
		&adminUser.ID,
		&adminUser.Email,
		&adminUser.PasswordHash,
		&enabled,
		&adminUser.CreatedAt,
		&adminUser.UpdatedAt,
		&userRecord.ID,
		&userRecord.AdminUserID,
		&userRecord.RPID,
		&userRecord.UserHandle,
		&userRecord.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AdminUser{},
				adminwebauthn.UserRecord{},
				adminwebauthn.ErrNotFound
		}
		return domain.AdminUser{},
			adminwebauthn.UserRecord{},
			fmt.Errorf("find WebAuthn user: %w", err)
	}

	adminUser.Enabled = enabled != 0
	return adminUser, userRecord, nil
}

func (s *Store) ListWebAuthnCredentials(
	ctx context.Context,
	adminUserID int64,
	rpid string,
) ([]adminwebauthn.CredentialRecord, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT
            id,
            admin_user_id,
            rpid,
            credential_id,
            credential_ciphertext,
            credential_nonce,
            credential_key_version,
            label,
            transports_json,
            aaguid,
            sign_count,
            clone_warning,
            backup_eligible,
            backup_state,
            created_at,
            COALESCE(last_used_at, ''),
            COALESCE(revoked_at, '')
        FROM admin_webauthn_credentials
        WHERE admin_user_id = ?
          AND rpid = ?
          AND revoked_at IS NULL
        ORDER BY created_at ASC, id ASC`,
		adminUserID,
		rpid,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list WebAuthn credentials: %w",
			err,
		)
	}
	defer rows.Close()

	var records []adminwebauthn.CredentialRecord

	for rows.Next() {
		var record adminwebauthn.CredentialRecord
		var signCount int64
		var cloneWarning int
		var backupEligible int
		var backupState int

		if err := rows.Scan(
			&record.ID,
			&record.AdminUserID,
			&record.RPID,
			&record.CredentialID,
			&record.CredentialCiphertext,
			&record.CredentialNonce,
			&record.CredentialKeyVersion,
			&record.Label,
			&record.TransportsJSON,
			&record.AAGUID,
			&signCount,
			&cloneWarning,
			&backupEligible,
			&backupState,
			&record.CreatedAt,
			&record.LastUsedAt,
			&record.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf(
				"scan WebAuthn credential: %w",
				err,
			)
		}

		record.SignCount = uint32(signCount)
		record.CloneWarning = cloneWarning != 0
		record.BackupEligible = backupEligible != 0
		record.BackupState = backupState != 0
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate WebAuthn credentials: %w",
			err,
		)
	}

	return records, nil
}

func (s *Store) InsertWebAuthnCredential(
	ctx context.Context,
	record adminwebauthn.CredentialRecord,
) (adminwebauthn.CredentialRecord, error) {
	result, err := s.db.ExecContext(
		ctx,
		`INSERT INTO admin_webauthn_credentials(
            admin_user_id,
            rpid,
            credential_id,
            credential_ciphertext,
            credential_nonce,
            credential_key_version,
            label,
            transports_json,
            aaguid,
            sign_count,
            clone_warning,
            backup_eligible,
            backup_state
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.AdminUserID,
		record.RPID,
		record.CredentialID,
		record.CredentialCiphertext,
		record.CredentialNonce,
		record.CredentialKeyVersion,
		record.Label,
		record.TransportsJSON,
		record.AAGUID,
		record.SignCount,
		boolInt(record.CloneWarning),
		boolInt(record.BackupEligible),
		boolInt(record.BackupState),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return adminwebauthn.CredentialRecord{},
				adminwebauthn.ErrConflict
		}
		return adminwebauthn.CredentialRecord{}, fmt.Errorf(
			"insert WebAuthn credential: %w",
			err,
		)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return adminwebauthn.CredentialRecord{}, fmt.Errorf(
			"read WebAuthn credential id: %w",
			err,
		)
	}

	record.ID = id

	err = s.db.QueryRowContext(
		ctx,
		`SELECT created_at
         FROM admin_webauthn_credentials
         WHERE id = ?`,
		id,
	).Scan(&record.CreatedAt)
	if err != nil {
		return adminwebauthn.CredentialRecord{}, fmt.Errorf(
			"read WebAuthn credential created_at: %w",
			err,
		)
	}

	return record, nil
}

func (s *Store) UpdateWebAuthnCredential(
	ctx context.Context,
	record adminwebauthn.CredentialRecord,
	now string,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE admin_webauthn_credentials
         SET credential_ciphertext = ?,
             credential_nonce = ?,
             credential_key_version = ?,
             transports_json = ?,
             aaguid = ?,
             sign_count = ?,
             clone_warning = ?,
             backup_eligible = ?,
             backup_state = ?,
             last_used_at = ?
         WHERE admin_user_id = ?
           AND rpid = ?
           AND credential_id = ?
           AND revoked_at IS NULL`,
		record.CredentialCiphertext,
		record.CredentialNonce,
		record.CredentialKeyVersion,
		record.TransportsJSON,
		record.AAGUID,
		record.SignCount,
		boolInt(record.CloneWarning),
		boolInt(record.BackupEligible),
		boolInt(record.BackupState),
		now,
		record.AdminUserID,
		record.RPID,
		record.CredentialID,
	)
	if err != nil {
		return fmt.Errorf(
			"update WebAuthn credential: %w",
			err,
		)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf(
			"read WebAuthn credential update rows: %w",
			err,
		)
	}
	if affected == 0 {
		return adminwebauthn.ErrNotFound
	}

	return nil
}

func (s *Store) RevokeWebAuthnCredential(
	ctx context.Context,
	adminUserID int64,
	rpid string,
	credentialID []byte,
	now string,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE admin_webauthn_credentials
         SET revoked_at = ?
         WHERE admin_user_id = ?
           AND rpid = ?
           AND credential_id = ?
           AND revoked_at IS NULL`,
		now,
		adminUserID,
		rpid,
		credentialID,
	)
	if err != nil {
		return fmt.Errorf(
			"revoke WebAuthn credential: %w",
			err,
		)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf(
			"read WebAuthn revoke rows: %w",
			err,
		)
	}
	if affected == 0 {
		return adminwebauthn.ErrNotFound
	}

	return nil
}

func (s *Store) CreateWebAuthnCeremony(
	ctx context.Context,
	record adminwebauthn.CeremonyRecord,
) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO admin_webauthn_ceremonies(
            token_hash,
            admin_user_id,
            rpid,
            purpose,
            session_ciphertext,
            session_nonce,
            session_key_version,
            label,
            expires_at_unix
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.TokenHash,
		record.AdminUserID,
		record.RPID,
		record.Purpose,
		record.SessionCiphertext,
		record.SessionNonce,
		record.SessionKeyVersion,
		record.Label,
		record.ExpiresAtUnix,
	)
	if err != nil {
		return fmt.Errorf(
			"create WebAuthn ceremony: %w",
			err,
		)
	}

	return nil
}

func (s *Store) ConsumeWebAuthnCeremony(
	ctx context.Context,
	tokenHash string,
	nowUnix int64,
) (
	adminwebauthn.CeremonyRecord,
	error,
) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return adminwebauthn.CeremonyRecord{}, fmt.Errorf(
			"begin WebAuthn ceremony transaction: %w",
			err,
		)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var record adminwebauthn.CeremonyRecord
	var adminUserID sql.NullInt64
	var consumedAt sql.NullInt64

	err = tx.QueryRowContext(
		ctx,
		`SELECT
            id,
            token_hash,
            admin_user_id,
            rpid,
            purpose,
            session_ciphertext,
            session_nonce,
            session_key_version,
            label,
            expires_at_unix,
            consumed_at_unix,
            created_at
         FROM admin_webauthn_ceremonies
         WHERE token_hash = ?
         LIMIT 1`,
		tokenHash,
	).Scan(
		&record.ID,
		&record.TokenHash,
		&adminUserID,
		&record.RPID,
		&record.Purpose,
		&record.SessionCiphertext,
		&record.SessionNonce,
		&record.SessionKeyVersion,
		&record.Label,
		&record.ExpiresAtUnix,
		&consumedAt,
		&record.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminwebauthn.CeremonyRecord{},
				adminwebauthn.ErrNotFound
		}
		return adminwebauthn.CeremonyRecord{}, fmt.Errorf(
			"read WebAuthn ceremony: %w",
			err,
		)
	}

	if adminUserID.Valid {
		value := adminUserID.Int64
		record.AdminUserID = &value
	}
	if consumedAt.Valid {
		value := consumedAt.Int64
		record.ConsumedAtUnix = &value
		return adminwebauthn.CeremonyRecord{},
			adminwebauthn.ErrCeremonyUsed
	}
	if record.ExpiresAtUnix <= nowUnix {
		return adminwebauthn.CeremonyRecord{},
			adminwebauthn.ErrCeremonyExpired
	}

	result, err := tx.ExecContext(
		ctx,
		`UPDATE admin_webauthn_ceremonies
         SET consumed_at_unix = ?
         WHERE id = ?
           AND consumed_at_unix IS NULL`,
		nowUnix,
		record.ID,
	)
	if err != nil {
		return adminwebauthn.CeremonyRecord{}, fmt.Errorf(
			"consume WebAuthn ceremony: %w",
			err,
		)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return adminwebauthn.CeremonyRecord{}, fmt.Errorf(
			"read WebAuthn consume rows: %w",
			err,
		)
	}
	if affected != 1 {
		return adminwebauthn.CeremonyRecord{},
			adminwebauthn.ErrCeremonyUsed
	}

	if err := tx.Commit(); err != nil {
		return adminwebauthn.CeremonyRecord{}, fmt.Errorf(
			"commit WebAuthn ceremony: %w",
			err,
		)
	}

	value := nowUnix
	record.ConsumedAtUnix = &value
	return record, nil
}

func (s *Store) DeleteExpiredWebAuthnCeremonies(
	ctx context.Context,
	nowUnix int64,
) error {
	_, err := s.db.ExecContext(
		ctx,
		`DELETE FROM admin_webauthn_ceremonies
         WHERE expires_at_unix <= ?`,
		nowUnix,
	)
	if err != nil {
		return fmt.Errorf(
			"delete expired WebAuthn ceremonies: %w",
			err,
		)
	}

	return nil
}
