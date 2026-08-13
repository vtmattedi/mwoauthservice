package oauth

import (
	"context"
	"fmt"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

type TransactionStore interface {
	CreateOAuthTransaction(
		ctx context.Context,
		transaction domain.OAuthTransaction,
		limits domain.OAuthLimits,
		nowUnix int64,
	) error
}

type PKCECipher interface {
	Encrypt(
		plaintext []byte,
	) (
		ciphertext string,
		nonce string,
		err error,
	)
}

type RateLimitError struct {
	Reason string
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf(
		"OAuth transaction rate limit exceeded: %s",
		e.Reason,
	)
}
