package oauth

import "errors"

var (
	ErrInvalidRequest = errors.New("invalid OAuth request")
	// ErrNoGoogleClient means the project has no active Google OAuth client.
	ErrNoGoogleClient = errors.New(
		"no Google OAuth client is configured for this project",
	)
	// ErrGoogleClientUnavailable means a per-project Google client exists
	// but cannot be used (for example its encryption key is missing). There is
	// no other client to substitute.
	ErrGoogleClientUnavailable = errors.New(
		"the project's Google OAuth client is unavailable",
	)
	ErrProviderDisabled    = errors.New("OAuth provider is disabled")
	ErrScopeNotAllowed     = errors.New("OAuth scope is not allowed")
	ErrCallbackNotAllowed  = errors.New("OAuth callback URL is not allowed")
	ErrReturnURLNotAllowed = errors.New(
		"OAuth return URL is not allowed",
	)
)
