package oauth

import (
	"context"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

type UnavailableDeliverer struct{}

func (UnavailableDeliverer) Deliver(
	ctx context.Context,
	transaction domain.OAuthTransaction,
	tokens TokenSet,
) error {
	return ErrDeliveryUnavailable
}
