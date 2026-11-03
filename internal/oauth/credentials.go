package oauth

import (
	"context"

	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
)

// GoogleClient is the OAuth client ID and secret used for one call to Google.
type GoogleClient struct {
	ClientID     string
	ClientSecret string
}

// CredentialSource resolves per-project Google OAuth clients. It is satisfied
// by *googlecred.Service.
type CredentialSource interface {
	ResolveActive(
		ctx context.Context,
		projectID int64,
	) (googlecred.Resolved, error)

	Resolve(
		ctx context.Context,
		projectID int64,
		ref string,
		purpose googlecred.Purpose,
	) (googlecred.Resolved, error)

	RecordAuthorized(ctx context.Context, projectID int64, ref string) error
	RecordRefreshed(ctx context.Context, projectID int64, ref string) error
}
