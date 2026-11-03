// Package refresh renews Google access tokens on behalf of consuming
// applications. The broker never stores user tokens: the consumer sends its
// Google refresh token with the credential_ref returned when the user
// authorized, and receives the renewed access token.
package refresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/providers/google"
)

const (
	maxCredentialRefLength = 64
	maxRefreshTokenLength  = 2048

	// invalidGrantMemory is how long a refresh token that Google rejected as
	// invalid_grant is remembered (as a hash) so a consumer stuck in a retry
	// loop does not hammer Google or burn its own rate limit.
	invalidGrantMemory = 5 * time.Minute
	// rejectedClientMemory is how long a credential that Google rejects
	// (invalid_client and similar) is remembered, so a wrong stored secret is
	// not sent to Google again on every retry.
	rejectedClientMemory = time.Minute
	maxRemembered        = 10000
)

var (
	ErrInvalidRequest = errors.New("invalid refresh request")
	// ErrCredentialNotFound is returned for an unknown credential_ref and for
	// one that belongs to another project; the two are indistinguishable.
	ErrCredentialNotFound = errors.New("Google credential not found")
	// ErrCredentialUnavailable: the credential exists but cannot be used
	// (disabled, secret deleted, key lost, or Google rejects the client).
	ErrCredentialUnavailable = errors.New("Google credential is unavailable")
	// ErrReauthorizationRequired: Google says the refresh token is no longer
	// valid; the user must consent again.
	ErrReauthorizationRequired = errors.New("reauthorization required")
	ErrProviderUnavailable     = errors.New("Google is unavailable")
	ErrProviderRateLimited     = errors.New("Google rate limited the request")
	ErrRateLimited             = errors.New("refresh rate limit exceeded")
)

// Error is a refresh failure with a stable sentinel (Kind), a short reason code
// for auditing, and an optional retry hint. It never contains tokens, secrets
// or provider response bodies.
type Error struct {
	Kind       error
	Reason     string
	RetryAfter time.Duration
}

func (e *Error) Error() string { return e.Kind.Error() }
func (e *Error) Unwrap() error { return e.Kind }

func fail(kind error, reason string) *Error {
	return &Error{Kind: kind, Reason: reason}
}

// Request is what a consumer sends.
type Request struct {
	CredentialRef string
	RefreshToken  string
}

// Result is the renewed Google access token. RefreshToken is set only when
// Google issued a replacement; otherwise the consumer keeps its current one.
type Result struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	Scopes       []string
	RefreshToken string
}

// Google is the provider client used for the refresh grant.
type Google interface {
	Refresh(
		ctx context.Context,
		client oauth.GoogleClient,
		refreshToken string,
	) (oauth.TokenSet, error)
}

// Limits are the refresh-specific rate limits, separate from authorize.
type Limits struct {
	// PerProject bounds all refreshes of one project.
	PerProject *appauth.Limiter
	// PerCredential bounds refreshes through one Google client.
	PerCredential *ScopedLimiter
	// PerToken bounds refreshes of a single refresh token.
	PerToken *ScopedLimiter
}

// DefaultLimits returns conservative per-minute defaults.
func DefaultLimits() Limits {
	return Limits{
		PerProject:    appauth.NewLimiter(300, time.Minute, 10000),
		PerCredential: NewScopedLimiter(120, time.Minute, 1000),
		PerToken:      NewScopedLimiter(10, time.Minute, 10000),
	}
}

type Service struct {
	credentials oauth.CredentialSource
	projects    *project.Service
	google      Google
	limits      Limits
	now         func() time.Time

	mu       sync.Mutex
	invalid  map[string]time.Time
	rejected map[string]time.Time
}

// Options configures the service.
type Options struct {
	// Credentials resolves per-project Google clients. Required.
	Credentials oauth.CredentialSource
	// Projects provides project policy (provider enabled, legacy mode).
	Projects *project.Service
	Google   Google
	Limits   Limits
}

func NewService(options Options) (*Service, error) {
	if options.Credentials == nil {
		return nil, fmt.Errorf("credential source is required")
	}
	if options.Projects == nil {
		return nil, fmt.Errorf("project service is required")
	}
	if options.Google == nil {
		return nil, fmt.Errorf("Google refresher is required")
	}

	return &Service{
		credentials: options.Credentials,
		projects:    options.Projects,
		google:      options.Google,
		limits:      options.Limits,
		now:         time.Now,
		invalid:     make(map[string]time.Time),
		rejected:    make(map[string]time.Time),
	}, nil
}

// WithClock replaces the time source (for tests) and returns the service.
func (s *Service) WithClock(now func() time.Time) *Service {
	s.now = now
	return s
}

// Refresh renews a Google access token for projectID. projectID comes from
// the authenticated MW access token; nothing the consumer sends can select a
// different project, a different Google client or a different endpoint.
func (s *Service) Refresh(
	ctx context.Context,
	projectID int64,
	request Request,
) (Result, error) {
	if projectID <= 0 {
		return Result{}, fail(ErrCredentialNotFound, "invalid_project")
	}
	if err := validate(request); err != nil {
		return Result{}, err
	}

	config, err := s.projects.GoogleConfig(ctx, projectID)
	if err != nil {
		return Result{}, fmt.Errorf("load Google OAuth project policy: %w", err)
	}
	if !config.Enabled {
		return Result{}, oauth.ErrProviderDisabled
	}

	projectKey := strconv.FormatInt(projectID, 10)
	credentialKey := projectKey + "|" + request.CredentialRef
	tokenKey := fingerprint(projectID, request.CredentialRef, request.RefreshToken)

	// 1. The project limit comes first, without recording anything, so a
	// caller who is over it creates no further limiter state.
	if exceeded, retry := peek(s.limits.PerProject, projectKey); exceeded {
		return Result{}, rateLimited("project_rate_limited", retry)
	}

	// 2. Only a credential that exists in this project gets to create
	// per-credential and per-token limiter entries; random credential_refs
	// and random refresh tokens cannot fill the limiter maps.
	client, err := s.resolve(ctx, projectID, request.CredentialRef)
	if err != nil {
		return Result{}, err
	}

	// 3. Narrowest limit first, so a request refused for hammering one token
	// does not also use up the credential's or project's allowance.
	if s.limits.PerToken != nil {
		if ok, retry := s.limits.PerToken.Allow(projectID, tokenKey); !ok {
			return Result{}, rateLimited("token_rate_limited", retry)
		}
	}
	if s.limits.PerCredential != nil {
		if ok, retry := s.limits.PerCredential.Allow(projectID, request.CredentialRef); !ok {
			return Result{}, rateLimited("credential_rate_limited", retry)
		}
	}
	if s.limits.PerProject != nil {
		if ok, retry := s.limits.PerProject.Allow(projectKey); !ok {
			return Result{}, rateLimited("project_rate_limited", retry)
		}
	}
	// 4. Answer known-bad cases locally instead of calling Google again.
	if s.remembered(s.rejected, credentialKey) {
		return Result{}, fail(ErrCredentialUnavailable, "google_client_rejected_cached")
	}
	if s.remembered(s.invalid, tokenKey) {
		return Result{}, fail(ErrReauthorizationRequired, "invalid_grant_cached")
	}

	tokens, err := s.google.Refresh(ctx, client, request.RefreshToken)
	client = oauth.GoogleClient{}
	if err != nil {
		return Result{}, s.mapProviderError(credentialKey, tokenKey, err)
	}

	// Informational; never fails the refresh, but a failure is visible.
	if markErr := s.credentials.RecordRefreshed(
		ctx, projectID, request.CredentialRef,
	); markErr != nil {
		slog.WarnContext(
			ctx,
			"could not record Google credential refresh",
			"project_id", projectID,
			"credential_ref", request.CredentialRef,
			"error", markErr,
		)
	}

	return Result{
		AccessToken:  tokens.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokens.ExpiresIn,
		Scopes:       append([]string(nil), tokens.Scopes...),
		RefreshToken: tokens.RefreshToken,
	}, nil
}

// resolve returns the Google client for ref inside the caller's project. A ref
// that does not exist in this project, whatever the reason, is "not found".
func (s *Service) resolve(
	ctx context.Context,
	projectID int64,
	ref string,
) (oauth.GoogleClient, error) {
	resolved, err := s.credentials.Resolve(ctx, projectID, ref, googlecred.PurposeRefresh)
	switch {
	case err == nil:
		return oauth.GoogleClient{
			ClientID:     resolved.ClientID,
			ClientSecret: resolved.ClientSecret,
		}, nil
	case errors.Is(err, googlecred.ErrNotFound):
		return oauth.GoogleClient{}, fail(ErrCredentialNotFound, "credential_not_found")
	case errors.Is(err, googlecred.ErrSecretUnavailable):
		return oauth.GoogleClient{}, fail(ErrCredentialUnavailable, "credential_disabled")
	case errors.Is(err, googlecred.ErrBroken), errors.Is(err, googlecred.ErrNotConfigured):
		return oauth.GoogleClient{}, fail(ErrCredentialUnavailable, "credential_broken")
	default:
		return oauth.GoogleClient{}, fmt.Errorf("resolve Google credential: %w", err)
	}
}

func (s *Service) mapProviderError(credentialKey, tokenKey string, err error) error {
	var providerError *google.ProviderError
	if !errors.As(err, &providerError) {
		return fail(ErrProviderUnavailable, "provider_error")
	}

	switch providerError.Kind {
	case google.KindInvalidGrant:
		s.remember(s.invalid, tokenKey, invalidGrantMemory)
		return fail(ErrReauthorizationRequired, "invalid_grant")

	case google.KindRateLimited:
		e := fail(ErrProviderRateLimited, "provider_rate_limited")
		e.RetryAfter = providerError.RetryAfter
		return e

	case google.KindRejected:
		// Google refuses the client itself (invalid_client and similar): the
		// stored credential is wrong, which an operator must fix. Remember it
		// briefly so retries do not keep sending the secret to Google.
		s.remember(s.rejected, credentialKey, rejectedClientMemory)
		return fail(ErrCredentialUnavailable, "google_client_rejected")

	default:
		return fail(ErrProviderUnavailable, "provider_unavailable")
	}
}

func rateLimited(reason string, retry time.Duration) *Error {
	e := fail(ErrRateLimited, reason)
	e.RetryAfter = retry
	return e
}

// peek reports whether key is already over its limit, recording nothing.
func peek(limiter *appauth.Limiter, key string) (bool, time.Duration) {
	if limiter == nil {
		return false, 0
	}
	return limiter.Exceeded(key)
}

func (s *Service) remembered(memory map[string]time.Time, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	until, ok := memory[key]
	if !ok {
		return false
	}
	if !s.now().Before(until) {
		delete(memory, key)
		return false
	}
	return true
}

// remember keeps key for the given duration. The memory is bounded: when it
// is full, expired entries are dropped, and if it is still full the entry is
// skipped rather than growing without limit.
func (s *Service) remember(memory map[string]time.Time, key string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if len(memory) >= maxRemembered {
		for k, until := range memory {
			if !now.Before(until) {
				delete(memory, k)
			}
		}
		if len(memory) >= maxRemembered {
			return
		}
	}
	memory[key] = now.Add(ttl)
}

func validate(request Request) error {
	ref := request.CredentialRef
	if ref == "" || len(ref) > maxCredentialRefLength {
		return fail(ErrInvalidRequest, "invalid_credential_ref")
	}
	for _, r := range ref {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
			!(r >= '0' && r <= '9') && r != '_' && r != '-' {
			return fail(ErrInvalidRequest, "invalid_credential_ref")
		}
	}

	token := request.RefreshToken
	if token == "" || len(token) > maxRefreshTokenLength {
		return fail(ErrInvalidRequest, "invalid_refresh_token")
	}
	for _, r := range token {
		if r <= ' ' || r == 0x7f {
			return fail(ErrInvalidRequest, "invalid_refresh_token")
		}
	}
	return nil
}

// fingerprint identifies a refresh token without keeping it: a hash scoped to
// the project and credential.
func fingerprint(projectID int64, ref string, token string) string {
	sum := sha256.Sum256([]byte(
		strconv.FormatInt(projectID, 10) + "\x00" + ref + "\x00" + token,
	))
	return hex.EncodeToString(sum[:])
}
