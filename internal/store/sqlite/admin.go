package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

func (s *Store) CreateAdminUser(
	ctx context.Context,
	email string,
	passwordHash string,
) (domain.AdminUser, error) {
	result, err := s.db.ExecContext(
		ctx,
		`INSERT INTO admin_users(email, password_hash)
         VALUES (?, ?)`,
		email,
		passwordHash,
	)
	if err != nil {
		return domain.AdminUser{}, fmt.Errorf(
			"create admin user: %w",
			err,
		)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return domain.AdminUser{}, fmt.Errorf(
			"read admin user id: %w",
			err,
		)
	}

	return s.getAdminUserByID(ctx, id)
}

func (s *Store) GetAdminUserByEmail(
	ctx context.Context,
	email string,
) (domain.AdminUser, error) {
	var user domain.AdminUser
	var enabled int

	err := s.db.QueryRowContext(
		ctx,
		`SELECT
            id,
            email,
            password_hash,
            enabled,
            created_at,
            updated_at
         FROM admin_users
         WHERE email = ?
         LIMIT 1`,
		email,
	).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&enabled,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AdminUser{}, admin.ErrNotFound
		}
		return domain.AdminUser{}, fmt.Errorf(
			"get admin user by email: %w",
			err,
		)
	}

	user.Enabled = enabled != 0
	return user, nil
}

func (s *Store) GetAdminUserByID(
	ctx context.Context,
	id int64,
) (domain.AdminUser, error) {
	return s.getAdminUserByID(ctx, id)
}

func (s *Store) getAdminUserByID(
	ctx context.Context,
	id int64,
) (domain.AdminUser, error) {
	var user domain.AdminUser
	var enabled int

	err := s.db.QueryRowContext(
		ctx,
		`SELECT
            id,
            email,
            password_hash,
            enabled,
            created_at,
            updated_at
         FROM admin_users
         WHERE id = ?
         LIMIT 1`,
		id,
	).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&enabled,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AdminUser{}, admin.ErrNotFound
		}
		return domain.AdminUser{}, fmt.Errorf(
			"get admin user by id: %w",
			err,
		)
	}

	user.Enabled = enabled != 0
	return user, nil
}

func (s *Store) CreateAdminSession(
	ctx context.Context,
	adminUserID int64,
	tokenHash string,
	csrfHash string,
	expiresAt int64,
) (domain.AdminSession, error) {
	result, err := s.db.ExecContext(
		ctx,
		`INSERT INTO admin_sessions(
            admin_user_id,
            token_hash,
            csrf_hash,
            expires_at
        ) VALUES (?, ?, ?, ?)`,
		adminUserID,
		tokenHash,
		csrfHash,
		expiresAt,
	)
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf(
			"create admin session: %w",
			err,
		)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return domain.AdminSession{}, fmt.Errorf(
			"read admin session id: %w",
			err,
		)
	}

	return domain.AdminSession{
		ID:        id,
		TokenHash: tokenHash,
		CSRFHash:  csrfHash,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Store) GetAdminSessionByTokenHash(
	ctx context.Context,
	tokenHash string,
) (domain.AdminSession, error) {
	var session domain.AdminSession
	var enabled int

	err := s.db.QueryRowContext(
		ctx,
		`SELECT
            s.id,
            s.token_hash,
            s.csrf_hash,
            s.expires_at,
            s.created_at,
            u.id,
            u.email,
            u.password_hash,
            u.enabled,
            u.created_at,
            u.updated_at
         FROM admin_sessions AS s
         JOIN admin_users AS u
           ON u.id = s.admin_user_id
         WHERE s.token_hash = ?
         LIMIT 1`,
		tokenHash,
	).Scan(
		&session.ID,
		&session.TokenHash,
		&session.CSRFHash,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.User.ID,
		&session.User.Email,
		&session.User.PasswordHash,
		&enabled,
		&session.User.CreatedAt,
		&session.User.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AdminSession{}, admin.ErrNotFound
		}
		return domain.AdminSession{}, fmt.Errorf(
			"get admin session: %w",
			err,
		)
	}

	session.User.Enabled = enabled != 0
	return session, nil
}

func (s *Store) UpdateAdminSessionCSRF(
	ctx context.Context,
	tokenHash string,
	csrfHash string,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE admin_sessions
         SET csrf_hash = ?
         WHERE token_hash = ?`,
		csrfHash,
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf("update admin csrf: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read csrf update rows: %w", err)
	}
	if affected == 0 {
		return admin.ErrNotFound
	}

	return nil
}

func (s *Store) DeleteAdminSession(
	ctx context.Context,
	tokenHash string,
) error {
	_, err := s.db.ExecContext(
		ctx,
		`DELETE FROM admin_sessions WHERE token_hash = ?`,
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf("delete admin session: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredAdminSessions(
	ctx context.Context,
	nowUnix int64,
) error {
	_, err := s.db.ExecContext(
		ctx,
		`DELETE FROM admin_sessions WHERE expires_at <= ?`,
		nowUnix,
	)
	if err != nil {
		return fmt.Errorf(
			"delete expired admin sessions: %w",
			err,
		)
	}
	return nil
}
