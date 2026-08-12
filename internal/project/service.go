package project

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

const (
	apiKeyPrefix          = "mw_live_"
	callbackSecretPrefix  = "mw_whsec_"
	credentialRandomBytes = 32

	defaultRatePerMinute = 10
	defaultRatePerHour   = 100
	defaultMaxPending    = 50

	maxProjectNameLength = 160
	maxPolicyItems       = 50
	maxScopeLength       = 512
	maxURLLength         = 2048
)

type Service struct {
	store  Store
	cipher SecretCipher
}

type Credentials struct {
	Project        domain.Project
	APIKey         string
	CallbackSecret string
}

type UpdateInput struct {
	Name    *string
	Enabled *bool
}

func NewService(store Store, cipher SecretCipher) *Service {
	return &Service{
		store:  store,
		cipher: cipher,
	}
}

func (s *Service) List(
	ctx context.Context,
) ([]domain.Project, error) {
	return s.store.ListProjects(ctx)
}

func (s *Service) Get(
	ctx context.Context,
	id int64,
) (domain.Project, error) {
	if id <= 0 {
		return domain.Project{}, ErrNotFound
	}
	return s.store.GetProject(ctx, id)
}

func (s *Service) Create(
	ctx context.Context,
	name string,
	enabled bool,
) (Credentials, error) {
	name, err := validateProjectName(name)
	if err != nil {
		return Credentials{}, err
	}

	apiKey, err := randomCredential(apiKeyPrefix)
	if err != nil {
		return Credentials{}, err
	}

	callbackSecret, err := randomCredential(callbackSecretPrefix)
	if err != nil {
		return Credentials{}, err
	}

	ciphertext, nonce, keyVersion, err := s.cipher.Encrypt(
		[]byte(callbackSecret),
	)
	if err != nil {
		return Credentials{}, fmt.Errorf(
			"encrypt callback signing secret: %w",
			err,
		)
	}

	created, err := s.store.CreateProject(
		ctx,
		CreateRecord{
			Name:                     name,
			Enabled:                  enabled,
			TokenHash:                HashAPIKey(apiKey),
			CallbackSecretCiphertext: ciphertext,
			CallbackSecretNonce:      nonce,
			CallbackSecretKeyVersion: keyVersion,
		},
	)
	if err != nil {
		return Credentials{}, err
	}

	return Credentials{
		Project:        created,
		APIKey:         apiKey,
		CallbackSecret: callbackSecret,
	}, nil
}

func (s *Service) Update(
	ctx context.Context,
	id int64,
	input UpdateInput,
) (domain.Project, error) {
	current, err := s.Get(ctx, id)
	if err != nil {
		return domain.Project{}, err
	}

	if input.Name == nil && input.Enabled == nil {
		return domain.Project{}, fmt.Errorf(
			"%w: at least one field is required",
			ErrValidation,
		)
	}

	name := current.Name
	enabled := current.Enabled

	if input.Name != nil {
		name, err = validateProjectName(*input.Name)
		if err != nil {
			return domain.Project{}, err
		}
	}

	if input.Enabled != nil {
		enabled = *input.Enabled
	}

	return s.store.UpdateProject(
		ctx,
		id,
		name,
		enabled,
	)
}

func (s *Service) RotateAPIKey(
	ctx context.Context,
	id int64,
) (string, error) {
	if _, err := s.Get(ctx, id); err != nil {
		return "", err
	}

	apiKey, err := randomCredential(apiKeyPrefix)
	if err != nil {
		return "", err
	}

	if err := s.store.UpdateProjectTokenHash(
		ctx,
		id,
		HashAPIKey(apiKey),
	); err != nil {
		return "", err
	}

	return apiKey, nil
}

func (s *Service) RotateCallbackSecret(
	ctx context.Context,
	id int64,
) (string, error) {
	if _, err := s.Get(ctx, id); err != nil {
		return "", err
	}

	secret, err := randomCredential(callbackSecretPrefix)
	if err != nil {
		return "", err
	}

	ciphertext, nonce, keyVersion, err := s.cipher.Encrypt(
		[]byte(secret),
	)
	if err != nil {
		return "", fmt.Errorf(
			"encrypt callback signing secret: %w",
			err,
		)
	}

	if err := s.store.UpdateProjectCallbackSecret(
		ctx,
		id,
		ciphertext,
		nonce,
		keyVersion,
	); err != nil {
		return "", err
	}

	return secret, nil
}

func (s *Service) LookupByAPIKey(
	ctx context.Context,
	rawAPIKey string,
) (domain.Project, error) {
	rawAPIKey = strings.TrimSpace(rawAPIKey)
	if !strings.HasPrefix(rawAPIKey, apiKeyPrefix) {
		return domain.Project{}, ErrNotFound
	}

	return s.store.GetProjectByTokenHash(
		ctx,
		HashAPIKey(rawAPIKey),
	)
}

func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Service) GoogleConfig(
	ctx context.Context,
	projectID int64,
) (domain.GoogleOAuthConfig, error) {
	if _, err := s.Get(ctx, projectID); err != nil {
		return domain.GoogleOAuthConfig{}, err
	}

	config, err := s.store.GetGoogleOAuthConfig(
		ctx,
		projectID,
	)
	if err == nil {
		return config, nil
	}
	if err != ErrNotFound {
		return domain.GoogleOAuthConfig{}, err
	}

	return DefaultGoogleConfig(), nil
}

func (s *Service) ConfigureGoogle(
	ctx context.Context,
	projectID int64,
	config domain.GoogleOAuthConfig,
) (domain.GoogleOAuthConfig, error) {
	if _, err := s.Get(ctx, projectID); err != nil {
		return domain.GoogleOAuthConfig{}, err
	}

	normalized, err := validateGoogleConfig(config)
	if err != nil {
		return domain.GoogleOAuthConfig{}, err
	}

	if err := s.store.ReplaceGoogleOAuthConfig(
		ctx,
		projectID,
		normalized,
	); err != nil {
		return domain.GoogleOAuthConfig{}, err
	}

	return normalized, nil
}

func DefaultGoogleConfig() domain.GoogleOAuthConfig {
	return domain.GoogleOAuthConfig{
		Enabled:             false,
		AllowedScopes:       []string{},
		AllowedCallbackURLs: []string{},
		AllowedReturnURLs:   []string{},
		Limits: domain.OAuthLimits{
			PerMinute:  defaultRatePerMinute,
			PerHour:    defaultRatePerHour,
			MaxPending: defaultMaxPending,
		},
	}
}

func validateGoogleConfig(
	config domain.GoogleOAuthConfig,
) (domain.GoogleOAuthConfig, error) {
	scopes, err := normalizeValues(
		"allowed_scopes",
		config.AllowedScopes,
		maxScopeLength,
	)
	if err != nil {
		return domain.GoogleOAuthConfig{}, err
	}

	callbacks, err := normalizeURLs(
		"allowed_callback_urls",
		config.AllowedCallbackURLs,
	)
	if err != nil {
		return domain.GoogleOAuthConfig{}, err
	}

	returns, err := normalizeURLs(
		"allowed_return_urls",
		config.AllowedReturnURLs,
	)
	if err != nil {
		return domain.GoogleOAuthConfig{}, err
	}

	limits := config.Limits
	if limits.PerMinute == 0 {
		limits.PerMinute = defaultRatePerMinute
	}
	if limits.PerHour == 0 {
		limits.PerHour = defaultRatePerHour
	}
	if limits.MaxPending == 0 {
		limits.MaxPending = defaultMaxPending
	}

	if limits.PerMinute < 1 ||
		limits.PerHour < 1 ||
		limits.MaxPending < 1 {
		return domain.GoogleOAuthConfig{}, fmt.Errorf(
			"%w: rate limits must be positive",
			ErrValidation,
		)
	}

	if config.Enabled {
		if len(scopes) == 0 {
			return domain.GoogleOAuthConfig{}, fmt.Errorf(
				"%w: enabled Google OAuth requires at least one scope",
				ErrValidation,
			)
		}
		if len(callbacks) == 0 {
			return domain.GoogleOAuthConfig{}, fmt.Errorf(
				"%w: enabled Google OAuth requires a callback URL",
				ErrValidation,
			)
		}
		if len(returns) == 0 {
			return domain.GoogleOAuthConfig{}, fmt.Errorf(
				"%w: enabled Google OAuth requires a return URL",
				ErrValidation,
			)
		}
	}

	return domain.GoogleOAuthConfig{
		Enabled:             config.Enabled,
		AllowedScopes:       scopes,
		AllowedCallbackURLs: callbacks,
		AllowedReturnURLs:   returns,
		Limits:              limits,
	}, nil
}

func validateProjectName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf(
			"%w: project name is required",
			ErrValidation,
		)
	}
	if len(name) > maxProjectNameLength {
		return "", fmt.Errorf(
			"%w: project name is too long",
			ErrValidation,
		)
	}
	return name, nil
}

func normalizeValues(
	field string,
	values []string,
	maxLength int,
) ([]string, error) {
	if len(values) > maxPolicyItems {
		return nil, fmt.Errorf(
			"%w: %s has too many entries",
			ErrValidation,
			field,
		)
	}

	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf(
				"%w: %s contains an empty value",
				ErrValidation,
				field,
			)
		}
		if len(value) > maxLength {
			return nil, fmt.Errorf(
				"%w: %s contains a value that is too long",
				ErrValidation,
				field,
			)
		}
		if _, exists := seen[value]; exists {
			continue
		}

		seen[value] = struct{}{}
		result = append(result, value)
	}

	sort.Strings(result)
	return result, nil
}

func normalizeURLs(
	field string,
	values []string,
) ([]string, error) {
	normalized, err := normalizeValues(
		field,
		values,
		maxURLLength,
	)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(normalized))

	for _, raw := range normalized {
		parsed, err := url.Parse(raw)
		if err != nil ||
			!parsed.IsAbs() ||
			parsed.Host == "" ||
			parsed.User != nil {
			return nil, fmt.Errorf(
				"%w: %s contains an invalid absolute URL",
				ErrValidation,
				field,
			)
		}

		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf(
				"%w: %s URLs may not contain query strings or fragments",
				ErrValidation,
				field,
			)
		}

		hostname := strings.ToLower(parsed.Hostname())
		if hostname == "" || strings.Contains(hostname, "*") {
			return nil, fmt.Errorf(
				"%w: %s URLs may not contain wildcard hosts",
				ErrValidation,
				field,
			)
		}

		switch strings.ToLower(parsed.Scheme) {
		case "https":
		case "http":
			if !isLoopbackHost(hostname) {
				return nil, fmt.Errorf(
					"%w: non-local %s URLs must use https",
					ErrValidation,
					field,
				)
			}
		default:
			return nil, fmt.Errorf(
				"%w: %s URLs must use http or https",
				ErrValidation,
				field,
			)
		}

		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = strings.ToLower(parsed.Host)
		result = append(result, parsed.String())
	}

	sort.Strings(result)
	return result, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func randomCredential(prefix string) (string, error) {
	raw := make([]byte, credentialRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate credential: %w", err)
	}

	return prefix +
			base64.RawURLEncoding.EncodeToString(raw),
		nil
}
