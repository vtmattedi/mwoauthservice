package federation

import (
	"context"
	"time"
)

const (
	SourceLocal     = "local"
	SourceFederated = "federated"
)

// Principal is the trusted, unified identity exposed to admin handlers.
type Principal struct {
	Source          string
	LocalAdminID    *int64
	IdentitySubject *string
	Audience        string
	Scopes          []string
	AuthTime        *time.Time
	AMR             []string
}

type principalContextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func Current(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}
