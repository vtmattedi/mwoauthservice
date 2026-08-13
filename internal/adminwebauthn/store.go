package adminwebauthn

import (
	"context"
	"errors"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

var (
	ErrNotFound        = errors.New("WebAuthn resource not found")
	ErrConflict        = errors.New("WebAuthn resource conflict")
	ErrCeremonyUsed    = errors.New("WebAuthn ceremony already consumed")
	ErrCeremonyExpired = errors.New("WebAuthn ceremony expired")
)

type Store interface {
	GetAdminUserByID(
		ctx context.Context,
		id int64,
	) (domain.AdminUser, error)

	EnsureWebAuthnUser(
		ctx context.Context,
		adminUserID int64,
		rpid string,
		userHandle []byte,
	) (UserRecord, error)

	GetWebAuthnUser(
		ctx context.Context,
		adminUserID int64,
		rpid string,
	) (UserRecord, error)

	FindWebAuthnUserForCredential(
		ctx context.Context,
		rpid string,
		userHandle []byte,
		credentialID []byte,
	) (domain.AdminUser, UserRecord, error)

	ListWebAuthnCredentials(
		ctx context.Context,
		adminUserID int64,
		rpid string,
	) ([]CredentialRecord, error)

	InsertWebAuthnCredential(
		ctx context.Context,
		record CredentialRecord,
	) (CredentialRecord, error)

	UpdateWebAuthnCredential(
		ctx context.Context,
		record CredentialRecord,
		now string,
	) error

	RevokeWebAuthnCredential(
		ctx context.Context,
		adminUserID int64,
		rpid string,
		credentialID []byte,
		now string,
	) error

	CreateWebAuthnCeremony(
		ctx context.Context,
		record CeremonyRecord,
	) error

	ConsumeWebAuthnCeremony(
		ctx context.Context,
		tokenHash string,
		nowUnix int64,
	) (CeremonyRecord, error)

	DeleteExpiredWebAuthnCeremonies(
		ctx context.Context,
		nowUnix int64,
	) error
}
