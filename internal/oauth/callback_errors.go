package oauth

import "errors"

var (
	ErrInvalidCallback = errors.New("invalid OAuth provider callback")

	ErrTransactionNotFound = errors.New(
		"OAuth transaction not found",
	)
	ErrTransactionExpired = errors.New(
		"OAuth transaction expired",
	)
	ErrTransactionConsumed = errors.New(
		"OAuth transaction already consumed",
	)

	ErrProviderDenied = errors.New(
		"OAuth authorization denied by user",
	)
	ErrProviderExchangeFailed = errors.New(
		"OAuth provider code exchange failed",
	)
	// ErrCredentialUnavailable means the Google client pinned to the
	// authorization can no longer be used (disabled, deleted or not
	// decryptable). The code is not exchanged with any other client.
	ErrCredentialUnavailable = errors.New(
		"OAuth Google client credential is unavailable",
	)
	// ErrTemporaryFailure means the callback could not be completed because of
	// a transient server-side problem. The authorization is left pending, so
	// the same callback URL can be retried.
	ErrTemporaryFailure = errors.New(
		"OAuth callback temporarily failed",
	)
	ErrDeliveryFailed = errors.New(
		"OAuth result delivery failed",
	)
	ErrDeliveryUnavailable = errors.New(
		"OAuth result delivery is not implemented",
	)
)
