// Package googlecred manages per-project Google OAuth client credentials:
// storage contract, lifecycle and (in service.go) encryption.
package googlecred

import (
	"context"
	"errors"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

var (
	// ErrNotFound is returned when a credential does not exist inside the
	// requested project. A credential owned by another project is reported
	// identically, so references cannot be probed across projects.
	ErrNotFound = errors.New("google credential not found")

	// ErrProjectNotFound is returned when the owning project does not exist.
	ErrProjectNotFound = errors.New("project not found")

	// ErrInvalidTransition is returned for a lifecycle move that is not
	// allowed from the credential's current state.
	ErrInvalidTransition = errors.New("invalid google credential state transition")

	// ErrSecretUnavailable is returned when the credential exists but its
	// secret cannot be used: it was deleted (tombstone), the credential is
	// disabled, or its encryption key version is no longer configured.
	ErrSecretUnavailable = errors.New("google credential secret unavailable")

	// ErrValidation is returned for invalid input.
	ErrValidation = errors.New("google credential validation failed")
)

// NewRecord is an already-encrypted credential ready to be stored.
type NewRecord struct {
	ID         string
	ProjectID  int64
	ClientID   string
	Ciphertext string
	Nonce      string
	KeyVersion int
}

// SecretRecord is the encrypted secret of a credential. It is returned only
// by GetCredentialSecret, which exists for the server-side resolution path.
type SecretRecord struct {
	Credential domain.GoogleCredential
	Ciphertext string
	Nonce      string
	KeyVersion int
}

// Store persists credentials. Every method that takes a project ID scopes the
// lookup to that project.
type Store interface {
	// ActivateCredential atomically stores record as the project's new active
	// credential. A previously active credential becomes retiring in the same
	// transaction and is returned as retired.
	ActivateCredential(
		ctx context.Context,
		record NewRecord,
		now string,
	) (created domain.GoogleCredential, retired *domain.GoogleCredential, err error)

	GetCredential(
		ctx context.Context,
		projectID int64,
		id string,
	) (domain.GoogleCredential, error)

	// GetActiveCredential returns ErrNotFound when the project has none.
	GetActiveCredential(
		ctx context.Context,
		projectID int64,
	) (domain.GoogleCredential, error)

	ListCredentials(
		ctx context.Context,
		projectID int64,
	) ([]domain.GoogleCredential, error)

	// GetCredentialSecret returns encrypted secret material. It returns
	// ErrSecretUnavailable for tombstones.
	GetCredentialSecret(
		ctx context.Context,
		projectID int64,
		id string,
	) (SecretRecord, error)

	// TransitionCredential moves a credential to a new state if allowed.
	TransitionCredential(
		ctx context.Context,
		projectID int64,
		id string,
		to domain.GoogleCredentialState,
		now string,
	) (domain.GoogleCredential, error)

	// DeleteCredentialSecret clears the encrypted secret of a disabled
	// credential and keeps a tombstone row.
	DeleteCredentialSecret(
		ctx context.Context,
		projectID int64,
		id string,
		now string,
	) (domain.GoogleCredential, error)

	// CountPendingTransactions counts unexpired in-flight authorizations
	// pinned to the credential.
	CountPendingTransactions(
		ctx context.Context,
		projectID int64,
		id string,
		nowUnix int64,
	) (int, error)

	MarkAuthorized(ctx context.Context, projectID int64, id string, now string) error
	MarkRefreshed(ctx context.Context, projectID int64, id string, now string) error
}
