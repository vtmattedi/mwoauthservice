package project

import (
	"context"
	"errors"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

var (
	ErrNotFound   = errors.New("project not found")
	ErrConflict   = errors.New("project conflict")
	ErrValidation = errors.New("project validation failed")
)

type CreateRecord struct {
	Name                     string
	Enabled                  bool
	TokenHash                string
	CallbackSecretCiphertext string
	CallbackSecretNonce      string
	CallbackSecretKeyVersion int
}

type Store interface {
	ListProjects(
		ctx context.Context,
	) ([]domain.Project, error)

	CreateProject(
		ctx context.Context,
		record CreateRecord,
	) (domain.Project, error)

	GetProject(
		ctx context.Context,
		id int64,
	) (domain.Project, error)

	GetProjectByTokenHash(
		ctx context.Context,
		tokenHash string,
	) (domain.Project, error)

	UpdateProject(
		ctx context.Context,
		id int64,
		name string,
		enabled bool,
	) (domain.Project, error)

	UpdateProjectTokenHash(
		ctx context.Context,
		id int64,
		tokenHash string,
	) error

	UpdateProjectCallbackSecret(
		ctx context.Context,
		id int64,
		ciphertext string,
		nonce string,
		keyVersion int,
	) error

	GetGoogleOAuthConfig(
		ctx context.Context,
		projectID int64,
	) (domain.GoogleOAuthConfig, error)

	ReplaceGoogleOAuthConfig(
		ctx context.Context,
		projectID int64,
		config domain.GoogleOAuthConfig,
	) error
}

type SecretCipher interface {
	Encrypt(
		plaintext []byte,
	) (
		ciphertext string,
		nonce string,
		keyVersion int,
		err error,
	)

	Decrypt(
		ciphertext string,
		nonce string,
		keyVersion int,
	) ([]byte, error)
}
