package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

const (
	googleProvider = "google"

	transactionTTL = 10 * time.Minute

	stateRandomBytes         = 32
	pkceVerifierRandomBytes  = 32
	transactionIDRandomBytes = 18

	maxClientReferenceLength = 256
	maxRequestedScopes       = 50
	maxRequestedScopeLength  = 512
)

type Service struct {
	store             TransactionStore
	projects          *project.Service
	cipher            PKCECipher
	credentials       CredentialSource
	googleRedirectURI string
}

type Options struct {
	GoogleRedirectURI string
	// Credentials resolves each project's own Google OAuth client. Required:
	// there is no shared global client.
	Credentials CredentialSource
}

type GoogleAuthorizationRequest struct {
	Scopes          []string `json:"scopes"`
	CallbackURL     string   `json:"callback_url"`
	ReturnURL       string   `json:"return_url"`
	ClientReference string   `json:"client_reference"`
}

type AuthorizationResult struct {
	ProjectID        int64  `json:"-"`
	TransactionID    string `json:"transaction_id"`
	AuthorizationURL string `json:"authorization_url"`
	ExpiresIn        int    `json:"expires_in"`
}

func NewService(
	store TransactionStore,
	projects *project.Service,
	cipher PKCECipher,
	options Options,
) (*Service, error) {
	if options.Credentials == nil {
		return nil, fmt.Errorf("Google credential source is required")
	}

	redirectURI := strings.TrimSpace(options.GoogleRedirectURI)
	if redirectURI == "" {
		return nil, fmt.Errorf("GOOGLE_REDIRECT_URI is required")
	}

	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil ||
		!parsedRedirect.IsAbs() ||
		parsedRedirect.Host == "" {
		return nil, fmt.Errorf(
			"GOOGLE_REDIRECT_URI must be an absolute URL",
		)
	}

	if store == nil {
		return nil, fmt.Errorf("OAuth transaction store is required")
	}
	if projects == nil {
		return nil, fmt.Errorf("project service is required")
	}
	if cipher == nil {
		return nil, fmt.Errorf("PKCE cipher is required")
	}

	return &Service{
		store:             store,
		projects:          projects,
		cipher:            cipher,
		credentials:       options.Credentials,
		googleRedirectURI: redirectURI,
	}, nil
}

func (s *Service) AuthorizeGoogle(
	ctx context.Context,
	authenticatedProject domain.Project,
	request GoogleAuthorizationRequest,
) (AuthorizationResult, error) {
	if authenticatedProject.ID <= 0 {
		return AuthorizationResult{}, fmt.Errorf(
			"%w: invalid authenticated project",
			ErrInvalidRequest,
		)
	}

	config, err := s.projects.GoogleConfig(
		ctx,
		authenticatedProject.ID,
	)
	if err != nil {
		return AuthorizationResult{}, fmt.Errorf(
			"load Google OAuth project policy: %w",
			err,
		)
	}

	if !config.Enabled {
		return AuthorizationResult{}, ErrProviderDisabled
	}

	normalized, err := validateAuthorizationRequest(
		request,
		config,
	)
	if err != nil {
		return AuthorizationResult{}, err
	}

	// Choose the Google client now and pin it on the transaction. The callback
	// uses the pinned client, never whichever is active later.
	choice, err := s.selectGoogleClient(ctx, authenticatedProject.ID)
	if err != nil {
		return AuthorizationResult{}, err
	}

	state, err := randomURLToken(stateRandomBytes)
	if err != nil {
		return AuthorizationResult{}, err
	}

	verifier, err := randomURLToken(pkceVerifierRandomBytes)
	if err != nil {
		return AuthorizationResult{}, err
	}

	transactionIDToken, err := randomURLToken(
		transactionIDRandomBytes,
	)
	if err != nil {
		return AuthorizationResult{}, err
	}
	transactionID := "oauth_txn_" + transactionIDToken

	ciphertext, nonce, err := s.cipher.Encrypt(
		[]byte(verifier),
	)
	if err != nil {
		return AuthorizationResult{}, fmt.Errorf(
			"encrypt PKCE verifier: %w",
			err,
		)
	}

	requestedScopesJSON, err := json.Marshal(normalized.Scopes)
	if err != nil {
		return AuthorizationResult{}, fmt.Errorf(
			"encode requested scopes: %w",
			err,
		)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(transactionTTL)

	transaction := domain.OAuthTransaction{
		ID:                     transactionID,
		ProjectID:              authenticatedProject.ID,
		Provider:               googleProvider,
		StateHash:              hashOpaqueValue(state),
		PKCEVerifierCiphertext: ciphertext,
		PKCEVerifierNonce:      nonce,
		ClientReference:        normalized.ClientReference,
		CallbackURL:            normalized.CallbackURL,
		ReturnURL:              normalized.ReturnURL,
		RequestedScopesJSON:    string(requestedScopesJSON),
		GoogleCredentialID:     choice.CredentialID,
		Status:                 "pending",
		ExpiresAtUnix:          expiresAt.Unix(),
		CreatedAtUnix:          now.Unix(),
	}

	if err := s.store.CreateOAuthTransaction(
		ctx,
		transaction,
		config.Limits,
		now.Unix(),
	); err != nil {
		return AuthorizationResult{}, err
	}

	authorizationURL, err := s.googleAuthorizationURL(
		choice.ClientID,
		state,
		verifier,
		normalized.Scopes,
	)
	if err != nil {
		return AuthorizationResult{}, err
	}

	return AuthorizationResult{
		ProjectID:        authenticatedProject.ID,
		TransactionID:    transactionID,
		AuthorizationURL: authorizationURL,
		ExpiresIn:        int(transactionTTL.Seconds()),
	}, nil
}

// googleClientChoice is the Google client picked for one authorization.
type googleClientChoice struct {
	ClientID     string
	CredentialID string
}

// selectGoogleClient returns the project's active Google client. A project
// with no active credential has no way to authorize, and a credential that
// exists but cannot be used (missing key, undecryptable) is an error: there is
// no other client to fall back to.
func (s *Service) selectGoogleClient(
	ctx context.Context,
	projectID int64,
) (googleClientChoice, error) {
	resolved, err := s.credentials.ResolveActive(ctx, projectID)
	switch {
	case err == nil:
		return googleClientChoice{
			ClientID:     resolved.ClientID,
			CredentialID: resolved.Ref,
		}, nil

	case errors.Is(err, googlecred.ErrNotFound):
		return googleClientChoice{}, ErrNoGoogleClient

	case isPermanentCredentialError(err):
		return googleClientChoice{}, fmt.Errorf(
			"%w: %v", ErrGoogleClientUnavailable, err,
		)

	default:
		// A store failure is not the project's fault; report it as an
		// internal error so the caller can retry.
		return googleClientChoice{}, fmt.Errorf(
			"resolve project Google client: %w", err,
		)
	}
}

// isPermanentCredentialError reports whether err says the credential itself
// is unusable (as opposed to a transient failure reading it).
func isPermanentCredentialError(err error) bool {
	return errors.Is(err, googlecred.ErrNotFound) ||
		errors.Is(err, googlecred.ErrSecretUnavailable) ||
		errors.Is(err, googlecred.ErrBroken) ||
		errors.Is(err, googlecred.ErrNotConfigured)
}

func (s *Service) googleAuthorizationURL(
	clientID string,
	state string,
	verifier string,
	scopes []string,
) (string, error) {
	endpoint := url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/v2/auth",
	}

	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(
		challengeSum[:],
	)

	query := endpoint.Query()
	query.Set("client_id", clientID)
	query.Set("redirect_uri", s.googleRedirectURI)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	query.Set("access_type", "offline")
	query.Set("include_granted_scopes", "true")
	query.Set("prompt", "consent")

	endpoint.RawQuery = query.Encode()

	return endpoint.String(), nil
}

func validateAuthorizationRequest(
	request GoogleAuthorizationRequest,
	config domain.GoogleOAuthConfig,
) (GoogleAuthorizationRequest, error) {
	request.CallbackURL = strings.TrimSpace(request.CallbackURL)
	request.ReturnURL = strings.TrimSpace(request.ReturnURL)
	request.ClientReference = strings.TrimSpace(
		request.ClientReference,
	)

	if request.ClientReference == "" ||
		len(request.ClientReference) > maxClientReferenceLength ||
		hasControlCharacters(request.ClientReference) {
		return GoogleAuthorizationRequest{}, fmt.Errorf(
			"%w: invalid client_reference",
			ErrInvalidRequest,
		)
	}

	scopes, err := normalizeRequestedScopes(request.Scopes)
	if err != nil {
		return GoogleAuthorizationRequest{}, err
	}
	request.Scopes = scopes

	if !allScopesAllowed(
		request.Scopes,
		config.AllowedScopes,
	) {
		return GoogleAuthorizationRequest{}, ErrScopeNotAllowed
	}

	if !containsExact(
		config.AllowedCallbackURLs,
		request.CallbackURL,
	) {
		return GoogleAuthorizationRequest{}, ErrCallbackNotAllowed
	}

	if !containsExact(
		config.AllowedReturnURLs,
		request.ReturnURL,
	) {
		return GoogleAuthorizationRequest{}, ErrReturnURLNotAllowed
	}

	return request, nil
}

func normalizeRequestedScopes(
	scopes []string,
) ([]string, error) {
	if len(scopes) == 0 || len(scopes) > maxRequestedScopes {
		return nil, fmt.Errorf(
			"%w: scopes must contain between 1 and %d entries",
			ErrInvalidRequest,
			maxRequestedScopes,
		)
	}

	normalized := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))

	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" ||
			len(scope) > maxRequestedScopeLength ||
			hasControlCharacters(scope) {
			return nil, fmt.Errorf(
				"%w: invalid scope",
				ErrInvalidRequest,
			)
		}

		if _, exists := seen[scope]; exists {
			continue
		}

		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}

	if len(normalized) == 0 {
		return nil, fmt.Errorf(
			"%w: at least one scope is required",
			ErrInvalidRequest,
		)
	}

	sort.Strings(normalized)
	return normalized, nil
}

func allScopesAllowed(
	requested []string,
	allowed []string,
) bool {
	allowset := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		allowset[scope] = struct{}{}
	}

	for _, scope := range requested {
		if _, ok := allowset[scope]; !ok {
			return false
		}
	}

	return true
}

func containsExact(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func hasControlCharacters(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func randomURLToken(byteCount int) (string, error) {
	raw := make([]byte, byteCount)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf(
			"generate OAuth random value: %w",
			err,
		)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashOpaqueValue(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
