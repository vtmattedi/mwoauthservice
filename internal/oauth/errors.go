package oauth

import "errors"

var (
	ErrInvalidAPIKey       = errors.New("invalid API key")
	ErrDisabledProject     = errors.New("project is disabled")
	ErrInvalidRequest      = errors.New("invalid OAuth request")
	ErrProviderDisabled    = errors.New("OAuth provider is disabled")
	ErrScopeNotAllowed     = errors.New("OAuth scope is not allowed")
	ErrCallbackNotAllowed  = errors.New("OAuth callback URL is not allowed")
	ErrReturnURLNotAllowed = errors.New(
		"OAuth return URL is not allowed",
	)
)
