package admin

import (
	"context"
	"errors"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

var ErrNotFound = errors.New("admin resource not found")

type Store interface {
	CreateAdminUser(
		ctx context.Context,
		email string,
		passwordHash string,
	) (domain.AdminUser, error)

	GetAdminUserByEmail(
		ctx context.Context,
		email string,
	) (domain.AdminUser, error)

	GetAdminUserByID(
		ctx context.Context,
		id int64,
	) (domain.AdminUser, error)

	CreateAdminSession(
		ctx context.Context,
		adminUserID int64,
		tokenHash string,
		csrfHash string,
		expiresAt int64,
	) (domain.AdminSession, error)

	GetAdminSessionByTokenHash(
		ctx context.Context,
		tokenHash string,
	) (domain.AdminSession, error)

	UpdateAdminSessionCSRF(
		ctx context.Context,
		tokenHash string,
		csrfHash string,
	) error

	DeleteAdminSession(
		ctx context.Context,
		tokenHash string,
	) error

	DeleteExpiredAdminSessions(
		ctx context.Context,
		nowUnix int64,
	) error
}
