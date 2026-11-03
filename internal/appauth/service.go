package appauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	secretRandomBytes   = 32
	tokenRandomBytes    = 32
	clientIDRandomBytes = 12
	maxDisplayName      = 160
	timestampLayout     = "2006-01-02T15:04:05.000Z"

	// DefaultTokenTTL is the MW access token lifetime (plan D07).
	DefaultTokenTTL = 900 * time.Second
)

// KnownScopes are the MW scopes a client can be granted.
var KnownScopes = []string{ScopeGoogleAuthorize, ScopeGoogleRefresh}

// Token is an issued access token. AccessToken is shown to the caller once.
type Token struct {
	AccessToken string
	ExpiresIn   int
	Scopes      []string
	// ProjectID and ClientID identify who the token was issued to, for
	// auditing. They are not part of the token response.
	ProjectID int64
	ClientID  string
}

// Principal is an authenticated application: the project and the scopes that
// are valid right now (token scopes limited to what the client may still be
// granted).
type Principal struct {
	ProjectID int64
	ClientID  string
	Scopes    []string
}

func (p Principal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// CreatedClient is returned once; ClientSecret cannot be shown again.
type CreatedClient struct {
	Client       Client
	ClientSecret string
}

// NewSecret is a freshly generated secret, shown once.
type NewSecret struct {
	Secret       SecretInfo
	ClientSecret string
}

type Service struct {
	store    Store
	tokenTTL time.Duration
	now      func() time.Time
}

// NewService builds the service. A zero tokenTTL means DefaultTokenTTL.
func NewService(store Store, tokenTTL time.Duration) *Service {
	if tokenTTL <= 0 {
		tokenTTL = DefaultTokenTTL
	}
	return &Service{store: store, tokenTTL: tokenTTL, now: time.Now}
}

// WithClock replaces the time source (for tests) and returns the service.
func (s *Service) WithClock(now func() time.Time) *Service {
	s.now = now
	return s
}

func (s *Service) timestamp() string {
	return s.now().UTC().Format(timestampLayout)
}

// CreateClient creates the project's application client with its first
// secret. allowedScopes defaults to every known scope.
func (s *Service) CreateClient(
	ctx context.Context,
	projectID int64,
	displayName string,
	allowedScopes []string,
) (CreatedClient, error) {
	if projectID <= 0 {
		return CreatedClient{}, ErrNotFound
	}
	displayName, err := validateDisplayName(displayName)
	if err != nil {
		return CreatedClient{}, err
	}
	scopes, err := normalizeScopes(allowedScopes, true)
	if err != nil {
		return CreatedClient{}, err
	}

	clientID, err := randomID(ClientIDPrefix, clientIDRandomBytes)
	if err != nil {
		return CreatedClient{}, err
	}
	secret, err := randomID(SecretPrefix, secretRandomBytes)
	if err != nil {
		return CreatedClient{}, err
	}

	client, err := s.store.CreateClient(
		ctx, projectID, clientID, displayName, scopes, HashSecret(secret), s.timestamp(),
	)
	if err != nil {
		return CreatedClient{}, err
	}

	return CreatedClient{Client: client, ClientSecret: secret}, nil
}

// Get returns client metadata, including secret versions, never hashes.
func (s *Service) Get(ctx context.Context, projectID int64) (Client, error) {
	if projectID <= 0 {
		return Client{}, ErrNotFound
	}
	return s.store.GetClientByProject(ctx, projectID)
}

// AddSecret starts a rotation: a second secret becomes valid while the old one
// keeps working, until the old one is revoked.
func (s *Service) AddSecret(ctx context.Context, projectID int64) (NewSecret, error) {
	if projectID <= 0 {
		return NewSecret{}, ErrNotFound
	}
	secret, err := randomID(SecretPrefix, secretRandomBytes)
	if err != nil {
		return NewSecret{}, err
	}

	info, err := s.store.AddSecret(
		ctx, projectID, HashSecret(secret), MaxActiveSecrets, s.timestamp(),
	)
	if err != nil {
		return NewSecret{}, err
	}
	return NewSecret{Secret: info, ClientSecret: secret}, nil
}

// RevokeSecret immediately invalidates one secret and the tokens it issued.
func (s *Service) RevokeSecret(
	ctx context.Context,
	projectID int64,
	secretID int64,
) (SecretInfo, error) {
	if projectID <= 0 || secretID <= 0 {
		return SecretInfo{}, ErrNotFound
	}
	return s.store.RevokeSecret(ctx, projectID, secretID, s.timestamp())
}

// UpdateClient changes display name, enabled flag and/or allowed scopes.
// A nil/empty argument leaves that field unchanged.
func (s *Service) UpdateClient(
	ctx context.Context,
	projectID int64,
	displayName *string,
	enabled *bool,
	allowedScopes []string,
) (Client, error) {
	if projectID <= 0 {
		return Client{}, ErrNotFound
	}
	if displayName == nil && enabled == nil && len(allowedScopes) == 0 {
		return Client{}, fmt.Errorf("%w: at least one field is required", ErrValidation)
	}

	if displayName != nil {
		name, err := validateDisplayName(*displayName)
		if err != nil {
			return Client{}, err
		}
		displayName = &name
	}

	var scopes []string
	if len(allowedScopes) > 0 {
		var err error
		scopes, err = normalizeScopes(allowedScopes, false)
		if err != nil {
			return Client{}, err
		}
	}

	return s.store.UpdateClient(ctx, projectID, displayName, enabled, scopes, s.timestamp())
}

// RevokeTokens revokes every unexpired token of the project's client, or only
// those issued by one secret.
func (s *Service) RevokeTokens(
	ctx context.Context,
	projectID int64,
	secretID *int64,
) (int64, error) {
	if projectID <= 0 {
		return 0, ErrNotFound
	}
	return s.store.RevokeTokens(ctx, projectID, secretID, s.now().Unix())
}

// CleanupExpired deletes tokens that expired more than retention ago.
func (s *Service) CleanupExpired(ctx context.Context, retention time.Duration) (int64, error) {
	if retention < 0 {
		retention = 0
	}
	return s.store.DeleteExpiredTokens(ctx, s.now().Add(-retention).Unix())
}

// IssueToken verifies client credentials and returns a new access token.
//
// requestedScopes may be empty (grant everything the client is allowed) or a
// subset of the client's allowed scopes. Unknown client and wrong secret both
// return ErrInvalidClient; a disabled client or project is only reported after
// the secret has been verified.
func (s *Service) IssueToken(
	ctx context.Context,
	clientID string,
	clientSecret string,
	requestedScopes []string,
) (Token, error) {
	record, err := s.store.GetAuthRecord(ctx, clientID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Burn comparable work so unknown IDs are not faster to reject.
			_, _ = verifySecret(clientSecret, nil)
			return Token{}, ErrInvalidClient
		}
		return Token{}, err
	}

	secretID, ok := verifySecret(clientSecret, record.ActiveSecrets)
	if !ok {
		return Token{}, ErrInvalidClient
	}

	if !record.Client.Enabled {
		return Token{}, ErrClientDisabled
	}
	if !record.ProjectEnabled {
		return Token{}, ErrProjectDisabled
	}

	scopes, err := grantScopes(requestedScopes, record.Client.AllowedScopes)
	if err != nil {
		return Token{}, err
	}

	raw, err := randomID(TokenPrefix, tokenRandomBytes)
	if err != nil {
		return Token{}, err
	}

	now := s.now()
	if err := s.store.InsertToken(ctx, TokenRecord{
		TokenHash:     HashToken(raw),
		ClientPK:      record.Client.PK,
		SecretID:      secretID,
		ProjectID:     record.Client.ProjectID,
		Scopes:        scopes,
		IssuedAtUnix:  now.Unix(),
		ExpiresAtUnix: now.Add(s.tokenTTL).Unix(),
	}); err != nil {
		return Token{}, err
	}

	// Best effort: last-used is informational.
	_ = s.store.TouchSecret(ctx, secretID, s.timestamp())

	return Token{
		AccessToken: raw,
		ExpiresIn:   int(s.tokenTTL / time.Second),
		Scopes:      scopes,
		ProjectID:   record.Client.ProjectID,
		ClientID:    record.Client.ClientID,
	}, nil
}

// Authenticate validates a bearer token on every protected request: it must be
// known, unexpired and unrevoked, its issuing secret must still be active, and
// the client and project must still be enabled. The returned scopes are the
// token's scopes limited to what the client may currently be granted.
func (s *Service) Authenticate(ctx context.Context, rawToken string) (Principal, error) {
	rawToken = strings.TrimSpace(rawToken)
	if !strings.HasPrefix(rawToken, TokenPrefix) {
		return Principal{}, ErrInvalidToken
	}

	lookup, err := s.store.LookupToken(ctx, HashToken(rawToken), s.now().Unix())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Principal{}, ErrInvalidToken
		}
		return Principal{}, err
	}

	if lookup.Expired || lookup.Revoked || !lookup.SecretActive {
		return Principal{}, ErrInvalidToken
	}
	if !lookup.Client.Enabled {
		return Principal{}, ErrClientDisabled
	}
	if !lookup.ProjectEnabled {
		return Principal{}, ErrProjectDisabled
	}

	return Principal{
		ProjectID: lookup.Client.ProjectID,
		ClientID:  lookup.Client.ClientID,
		Scopes:    intersect(lookup.Scopes, lookup.Client.AllowedScopes),
	}, nil
}

// HashSecret hashes a client secret for storage (and comparison).
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// HashToken hashes an access token for storage and lookup.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// verifySecret compares in constant time against every active secret and
// returns the matching secret's ID. It always inspects all candidates.
func verifySecret(secret string, candidates []SecretHash) (int64, bool) {
	given := []byte(HashSecret(secret))

	var matched int64
	found := 0
	for _, c := range candidates {
		if subtle.ConstantTimeCompare(given, []byte(c.Hash)) == 1 {
			matched = c.ID
			found = 1
		}
	}

	if len(candidates) == 0 {
		// Same cost as one comparison for an unknown client.
		_ = subtle.ConstantTimeCompare(given, given)
	}

	return matched, found == 1
}

func grantScopes(requested []string, allowed []string) ([]string, error) {
	if len(requested) == 0 {
		granted := append([]string(nil), allowed...)
		sort.Strings(granted)
		return granted, nil
	}

	allowedSet := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = struct{}{}
	}

	seen := make(map[string]struct{}, len(requested))
	granted := make([]string, 0, len(requested))
	for _, s := range requested {
		if _, ok := allowedSet[s]; !ok {
			return nil, ErrInvalidScope
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		granted = append(granted, s)
	}
	sort.Strings(granted)
	return granted, nil
}

func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// normalizeScopes validates scope names, removes duplicates and sorts. With
// defaultAll an empty list means every known scope.
func normalizeScopes(scopes []string, defaultAll bool) ([]string, error) {
	if len(scopes) == 0 {
		if defaultAll {
			out := append([]string(nil), KnownScopes...)
			sort.Strings(out)
			return out, nil
		}
		return nil, fmt.Errorf("%w: at least one scope is required", ErrValidation)
	}

	known := make(map[string]struct{}, len(KnownScopes))
	for _, s := range KnownScopes {
		known[s] = struct{}{}
	}

	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if _, ok := known[s]; !ok {
			return nil, fmt.Errorf("%w: unknown scope %q", ErrValidation, s)
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

func validateDisplayName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if len(name) > maxDisplayName {
		return "", fmt.Errorf("%w: display name is too long", ErrValidation)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: display name contains control characters", ErrValidation)
		}
	}
	return name, nil
}

func randomID(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random credential: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}
