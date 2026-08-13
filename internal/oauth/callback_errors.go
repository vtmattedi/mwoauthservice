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
	ErrDeliveryFailed = errors.New(
		"OAuth result delivery failed",
	)
	ErrDeliveryUnavailable = errors.New(
		"OAuth result delivery is not implemented",
	)
)
