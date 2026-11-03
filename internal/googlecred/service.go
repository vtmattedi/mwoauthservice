package googlecred

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
)

const (
	credentialIDRandomBytes = 18
	googleClientIDSuffix    = ".apps.googleusercontent.com"
	maxClientIDLength       = 256
	minClientSecretLength   = 8
	maxClientSecretLength   = 512
	timestampLayout         = "2006-01-02T15:04:05.000Z"
)

var (
	// ErrNotConfigured means the Google client secret keyring is not
	// configured, so per-project credentials cannot be stored or read.
	ErrNotConfigured = errors.New("google client secret keyring is not configured")

	// ErrBroken means a stored credential exists but cannot be decrypted
	// (missing key version, tampering, wrong context). It is reported
	// explicitly and never replaced by the legacy global client.
	ErrBroken = errors.New("google credential is broken")
)

// Purpose says what a resolved credential will be used for. It decides which
// states are acceptable.
type Purpose string

const (
	// PurposeAuthorize builds a new authorization URL: active only.
	PurposeAuthorize Purpose = "authorize"
	// PurposeExchange completes a pinned in-flight callback: active or
	// retiring.
	PurposeExchange Purpose = "exchange"
	// PurposeRefresh renews a previously issued token: active or retiring.
	PurposeRefresh Purpose = "refresh"
)

// Resolved holds a decrypted client credential. ClientSecret must only be
// passed to the Google token endpoint and never logged or returned.
type Resolved struct {
	Ref          string
	ProjectID    int64
	ClientID     string
	ClientSecret string
	State        domain.GoogleCredentialState
}

// Impact describes what retiring or disabling a credential would affect, so
// an operator can confirm.
type Impact struct {
	Credential            domain.GoogleCredential `json:"credential"`
	PendingAuthorizations int                     `json:"pending_authorizations"`
	// ExistingTokensMayDepend is true when the credential has authorized or
	// refreshed at least once: refresh tokens issued by it only work with
	// this Google client and cannot be moved to another one.
	ExistingTokensMayDepend bool `json:"existing_tokens_may_depend"`
}

// ConfigureResult is the outcome of creating or rotating the credential.
type ConfigureResult struct {
	Credential domain.GoogleCredential  `json:"credential"`
	Retired    *domain.GoogleCredential `json:"retired,omitempty"`
}

type Service struct {
	store Store
	keys  *secretbox.GoogleCredentialKeyring
	now   func() time.Time
}

// NewService builds the lifecycle service. keys may be nil when the keyring is
// not configured; write and resolve operations then return ErrNotConfigured
// while metadata reads keep working.
func NewService(store Store, keys *secretbox.GoogleCredentialKeyring) *Service {
	return &Service{store: store, keys: keys, now: time.Now}
}

func (s *Service) timestamp() string {
	return s.now().UTC().Format(timestampLayout)
}

// Configure stores a new Google client as the project's active credential.
// If one is already active it becomes retiring in the same transaction
// (rotation). The secret is encrypted before it reaches the store and is not
// part of the result.
func (s *Service) Configure(
	ctx context.Context,
	projectID int64,
	clientID string,
	clientSecret string,
) (ConfigureResult, error) {
	if s.keys == nil {
		return ConfigureResult{}, ErrNotConfigured
	}
	if projectID <= 0 {
		return ConfigureResult{}, ErrProjectNotFound
	}

	clientID, err := validateClientID(clientID)
	if err != nil {
		return ConfigureResult{}, err
	}
	if err := validateClientSecret(clientSecret); err != nil {
		return ConfigureResult{}, err
	}

	id, err := newCredentialID()
	if err != nil {
		return ConfigureResult{}, err
	}

	ciphertext, nonce, keyVersion, err := s.keys.Encrypt(
		secretbox.GoogleCredentialContext{CredentialID: id, ProjectID: projectID},
		[]byte(clientSecret),
	)
	if err != nil {
		return ConfigureResult{}, fmt.Errorf("encrypt google client secret: %w", err)
	}

	created, retired, err := s.store.ActivateCredential(
		ctx,
		NewRecord{
			ID:         id,
			ProjectID:  projectID,
			ClientID:   clientID,
			Ciphertext: ciphertext,
			Nonce:      nonce,
			KeyVersion: keyVersion,
		},
		s.timestamp(),
	)
	if err != nil {
		return ConfigureResult{}, err
	}

	return ConfigureResult{Credential: created, Retired: retired}, nil
}

// Retire stops a credential from issuing new authorizations while it can
// still finish pinned callbacks and refresh existing tokens. Only an active
// credential can be retired.
func (s *Service) Retire(
	ctx context.Context,
	projectID int64,
	ref string,
) (domain.GoogleCredential, error) {
	return s.store.TransitionCredential(
		ctx, projectID, ref, domain.GoogleCredentialRetiring, s.timestamp(),
	)
}

// Disable blocks authorize, callback exchange and refresh. A compromised
// active credential can be disabled directly without retiring it first.
func (s *Service) Disable(
	ctx context.Context,
	projectID int64,
	ref string,
) (domain.GoogleCredential, error) {
	return s.store.TransitionCredential(
		ctx, projectID, ref, domain.GoogleCredentialDisabled, s.timestamp(),
	)
}

// DeleteSecret removes the encrypted secret of a disabled credential and
// keeps a tombstone row, so references still resolve to "unavailable" and
// history needed for audit is preserved.
func (s *Service) DeleteSecret(
	ctx context.Context,
	projectID int64,
	ref string,
) (domain.GoogleCredential, error) {
	return s.store.DeleteCredentialSecret(ctx, projectID, ref, s.timestamp())
}

// Impact reports what retiring or disabling the credential would affect.
func (s *Service) Impact(
	ctx context.Context,
	projectID int64,
	ref string,
) (Impact, error) {
	credential, err := s.store.GetCredential(ctx, projectID, ref)
	if err != nil {
		return Impact{}, err
	}

	pending, err := s.store.CountPendingTransactions(
		ctx, projectID, ref, s.now().Unix(),
	)
	if err != nil {
		return Impact{}, err
	}

	return Impact{
		Credential:              credential,
		PendingAuthorizations:   pending,
		ExistingTokensMayDepend: credential.LastAuthorizedAt != "" || credential.LastRefreshedAt != "",
	}, nil
}

func (s *Service) Get(
	ctx context.Context,
	projectID int64,
	ref string,
) (domain.GoogleCredential, error) {
	return s.store.GetCredential(ctx, projectID, ref)
}

func (s *Service) List(
	ctx context.Context,
	projectID int64,
) ([]domain.GoogleCredential, error) {
	return s.store.ListCredentials(ctx, projectID)
}

// Active returns the credential used for new authorizations, or ErrNotFound.
func (s *Service) Active(
	ctx context.Context,
	projectID int64,
) (domain.GoogleCredential, error) {
	return s.store.GetActiveCredential(ctx, projectID)
}

// ResolveActive picks the project's active credential and decrypts it for a
// new authorization.
func (s *Service) ResolveActive(
	ctx context.Context,
	projectID int64,
) (Resolved, error) {
	active, err := s.store.GetActiveCredential(ctx, projectID)
	if err != nil {
		return Resolved{}, err
	}
	return s.Resolve(ctx, projectID, active.ID, PurposeAuthorize)
}

// Resolve returns the decrypted credential for ref inside projectID.
//
// Errors are distinct and never fall back to another credential:
//   - ErrNotFound: unknown ref, or it belongs to another project
//   - ErrSecretUnavailable: disabled, deleted, or state not allowed for purpose
//   - ErrBroken: stored but not decryptable (e.g. missing key version)
//   - ErrNotConfigured: keyring not configured
func (s *Service) Resolve(
	ctx context.Context,
	projectID int64,
	ref string,
	purpose Purpose,
) (Resolved, error) {
	record, err := s.store.GetCredentialSecret(ctx, projectID, ref)
	if err != nil {
		return Resolved{}, err
	}

	if !stateAllowed(record.Credential.State, purpose) {
		return Resolved{}, ErrSecretUnavailable
	}
	if s.keys == nil {
		return Resolved{}, ErrNotConfigured
	}
	if !s.keys.HasVersion(record.KeyVersion) {
		return Resolved{}, ErrBroken
	}

	plaintext, err := s.keys.Decrypt(
		secretbox.GoogleCredentialContext{
			CredentialID: record.Credential.ID,
			ProjectID:    record.Credential.ProjectID,
		},
		record.Ciphertext,
		record.Nonce,
		record.KeyVersion,
	)
	if err != nil {
		return Resolved{}, ErrBroken
	}

	return Resolved{
		Ref:          record.Credential.ID,
		ProjectID:    record.Credential.ProjectID,
		ClientID:     record.Credential.ClientID,
		ClientSecret: string(plaintext),
		State:        record.Credential.State,
	}, nil
}

// RecordAuthorized notes a successful real authorization (code exchange).
func (s *Service) RecordAuthorized(ctx context.Context, projectID int64, ref string) error {
	return s.store.MarkAuthorized(ctx, projectID, ref, s.timestamp())
}

// RecordRefreshed notes a successful refresh.
func (s *Service) RecordRefreshed(ctx context.Context, projectID int64, ref string) error {
	return s.store.MarkRefreshed(ctx, projectID, ref, s.timestamp())
}

func stateAllowed(state domain.GoogleCredentialState, purpose Purpose) bool {
	switch purpose {
	case PurposeAuthorize:
		return state == domain.GoogleCredentialActive
	case PurposeExchange, PurposeRefresh:
		return state == domain.GoogleCredentialActive ||
			state == domain.GoogleCredentialRetiring
	}
	return false
}

func newCredentialID() (string, error) {
	buf := make([]byte, credentialIDRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate google credential id: %w", err)
	}
	return domain.GoogleCredentialIDPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func validateClientID(raw string) (string, error) {
	clientID := strings.TrimSpace(raw)
	if clientID == "" || len(clientID) > maxClientIDLength {
		return "", fmt.Errorf("%w: client id has invalid length", ErrValidation)
	}
	if !strings.HasSuffix(clientID, googleClientIDSuffix) ||
		len(clientID) == len(googleClientIDSuffix) {
		return "", fmt.Errorf(
			"%w: client id must be a Google OAuth client ID ending in %s",
			ErrValidation, googleClientIDSuffix,
		)
	}
	for _, r := range clientID {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fmt.Errorf("%w: client id contains invalid characters", ErrValidation)
		}
	}
	return clientID, nil
}

// validateClientSecret checks structure only; Google accepts the secret when
// the first real authorization completes.
func validateClientSecret(secret string) error {
	if len(secret) < minClientSecretLength || len(secret) > maxClientSecretLength {
		return fmt.Errorf("%w: client secret has invalid length", ErrValidation)
	}
	for _, r := range secret {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%w: client secret contains invalid characters", ErrValidation)
		}
	}
	return nil
}
