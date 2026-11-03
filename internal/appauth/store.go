// Package appauth authenticates consuming application backends: an MW client
// ID and secret are exchanged for a short-lived, scoped, opaque access token.
// Secrets and tokens are only ever stored as hashes.
package appauth

import (
	"context"
	"errors"
)

const (
	ScopeGoogleAuthorize = "google.authorize"
	ScopeGoogleRefresh   = "google.refresh"

	ClientIDPrefix = "mwc_"
	SecretPrefix   = "mw_cs_"
	TokenPrefix    = "mw_at_"

	// MaxActiveSecrets bounds overlapping client secrets during rotation.
	MaxActiveSecrets = 2

	SecretStateActive  = "active"
	SecretStateRevoked = "revoked"
)

var (
	ErrNotFound = errors.New("application client not found")
	// ErrConflict means the project already has an application client.
	ErrConflict = errors.New("application client already exists")
	// ErrTooManySecrets means MaxActiveSecrets are already active; revoke one
	// before adding another.
	ErrTooManySecrets = errors.New("too many active client secrets")
	ErrValidation     = errors.New("application client validation failed")

	// ErrInvalidClient covers unknown client IDs and wrong secrets alike, so
	// callers cannot tell them apart.
	ErrInvalidClient = errors.New("invalid client credentials")
	ErrInvalidScope  = errors.New("requested scope is not allowed")
	// ErrInvalidToken covers unknown, expired and revoked tokens alike.
	ErrInvalidToken    = errors.New("invalid access token")
	ErrClientDisabled  = errors.New("application client is disabled")
	ErrProjectDisabled = errors.New("project is disabled")
)

// SecretInfo is secret metadata. The hash is never exposed.
type SecretInfo struct {
	ID         int64  `json:"id"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

// Client is application client metadata.
type Client struct {
	// PK is the internal row ID, used for joins only.
	PK            int64        `json:"-"`
	ProjectID     int64        `json:"project_id"`
	ClientID      string       `json:"client_id"`
	DisplayName   string       `json:"display_name"`
	Enabled       bool         `json:"enabled"`
	AllowedScopes []string     `json:"allowed_scopes"`
	CreatedAt     string       `json:"created_at"`
	UpdatedAt     string       `json:"updated_at"`
	Secrets       []SecretInfo `json:"secrets"`
}

// SecretHash is an active secret's ID and hash, for verification only.
type SecretHash struct {
	ID   int64
	Hash string
}

// AuthRecord is what token issuance needs to verify a client.
type AuthRecord struct {
	Client         Client
	ProjectEnabled bool
	ActiveSecrets  []SecretHash
}

// TokenRecord is a token ready to be stored.
type TokenRecord struct {
	TokenHash     string
	ClientPK      int64
	SecretID      int64
	ProjectID     int64
	Scopes        []string
	IssuedAtUnix  int64
	ExpiresAtUnix int64
}

// TokenLookup is a stored token joined with the state of everything it
// depends on, so every request re-validates client, project and secret.
type TokenLookup struct {
	Client         Client
	Scopes         []string
	ProjectEnabled bool
	SecretActive   bool
	Revoked        bool
	Expired        bool
}

type Store interface {
	// CreateClient atomically creates the project's client and first secret.
	CreateClient(
		ctx context.Context,
		projectID int64,
		clientID string,
		displayName string,
		allowedScopes []string,
		secretHash string,
		now string,
	) (Client, error)

	GetClientByProject(ctx context.Context, projectID int64) (Client, error)

	// GetAuthRecord returns ErrNotFound for an unknown client ID.
	GetAuthRecord(ctx context.Context, clientID string) (AuthRecord, error)

	// AddSecret adds an active secret unless maxActive are already active.
	AddSecret(
		ctx context.Context,
		projectID int64,
		secretHash string,
		maxActive int,
		now string,
	) (SecretInfo, error)

	// RevokeSecret revokes one secret and, in the same transaction, the
	// unexpired tokens it issued. Revoking an already revoked secret is a
	// no-op that returns its current state.
	RevokeSecret(
		ctx context.Context,
		projectID int64,
		secretID int64,
		now string,
	) (SecretInfo, error)

	UpdateClient(
		ctx context.Context,
		projectID int64,
		displayName *string,
		enabled *bool,
		allowedScopes []string,
		now string,
	) (Client, error)

	TouchSecret(ctx context.Context, secretID int64, now string) error

	InsertToken(ctx context.Context, record TokenRecord) error

	// LookupToken returns ErrInvalidToken-equivalent ErrNotFound when the
	// hash is unknown.
	LookupToken(ctx context.Context, tokenHash string, nowUnix int64) (TokenLookup, error)

	// RevokeTokens revokes unexpired tokens of a project's client; a nil
	// secretID covers all of its secrets. It returns how many were revoked.
	RevokeTokens(
		ctx context.Context,
		projectID int64,
		secretID *int64,
		nowUnix int64,
	) (int64, error)

	// DeleteExpiredTokens removes tokens that expired before the cutoff.
	DeleteExpiredTokens(ctx context.Context, cutoffUnix int64) (int64, error)
}
