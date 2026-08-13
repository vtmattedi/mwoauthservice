package oauth

import (
	"context"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

type CallbackStore interface {
	ConsumeOAuthTransactionByStateHash(
		ctx context.Context,
		stateHash string,
		nowUnix int64,
	) (domain.OAuthTransaction, error)

	TransitionOAuthTransactionStatus(
		ctx context.Context,
		transactionID string,
		fromStatus string,
		toStatus string,
	) error
}

type PKCEDecrypter interface {
	Decrypt(
		ciphertext string,
		nonce string,
	) ([]byte, error)
}

type GoogleCodeExchanger interface {
	ExchangeCode(
		ctx context.Context,
		code string,
		verifier string,
	) (TokenSet, error)
}

type ResultDeliverer interface {
	Deliver(
		ctx context.Context,
		transaction domain.OAuthTransaction,
		tokens TokenSet,
	) error
}
