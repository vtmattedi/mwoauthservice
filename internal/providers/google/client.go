package google

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
)

const defaultTokenEndpoint = "https://oauth2.googleapis.com/token"

type Options struct {
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	TokenEndpoint string
	HTTPClient    *http.Client
}

type Client struct {
	clientID      string
	clientSecret  string
	redirectURI   string
	tokenEndpoint string
	httpClient    *http.Client
}

type ExchangeError struct {
	StatusCode   int
	ProviderCode string
}

func (e *ExchangeError) Error() string {
	if e.ProviderCode != "" {
		return fmt.Sprintf(
			"Google token exchange failed: status=%d code=%s",
			e.StatusCode,
			e.ProviderCode,
		)
	}

	return fmt.Sprintf(
		"Google token exchange failed: status=%d",
		e.StatusCode,
	)
}

func NewClient(options Options) (*Client, error) {
	clientID := strings.TrimSpace(options.ClientID)
	clientSecret := strings.TrimSpace(options.ClientSecret)
	redirectURI := strings.TrimSpace(options.RedirectURI)

	if clientID == "" {
		return nil, fmt.Errorf("Google OAuth client ID is required")
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("Google OAuth client secret is required")
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("Google OAuth redirect URI is required")
	}

	endpoint := strings.TrimSpace(options.TokenEndpoint)
	if endpoint == "" {
		endpoint = defaultTokenEndpoint
	}

	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil ||
		!parsedEndpoint.IsAbs() ||
		parsedEndpoint.Host == "" {
		return nil, fmt.Errorf(
			"Google token endpoint must be an absolute URL",
		)
	}

	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 15 * time.Second,
		}
	}

	return &Client{
		clientID:      clientID,
		clientSecret:  clientSecret,
		redirectURI:   redirectURI,
		tokenEndpoint: endpoint,
		httpClient:    httpClient,
	}, nil
}

func (c *Client) ExchangeCode(
	ctx context.Context,
	code string,
	verifier string,
) (oauth.TokenSet, error) {
	code = strings.TrimSpace(code)
	verifier = strings.TrimSpace(verifier)

	if code == "" {
		return oauth.TokenSet{}, fmt.Errorf(
			"authorization code is required",
		)
	}
	if verifier == "" {
		return oauth.TokenSet{}, fmt.Errorf(
			"PKCE verifier is required",
		)
	}

	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", c.redirectURI)

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.tokenEndpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return oauth.TokenSet{}, fmt.Errorf(
			"create Google token request: %w",
			err,
		)
	}

	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	request.Header.Set("Accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return oauth.TokenSet{}, fmt.Errorf(
			"execute Google token exchange: %w",
			err,
		)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(
		io.LimitReader(response.Body, 1<<20),
	)
	if err != nil {
		return oauth.TokenSet{}, fmt.Errorf(
			"read Google token response: %w",
			err,
		)
	}

	if response.StatusCode < 200 ||
		response.StatusCode >= 300 {
		var providerError struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &providerError)

		return oauth.TokenSet{}, &ExchangeError{
			StatusCode: response.StatusCode,
			ProviderCode: sanitizeProviderCode(
				providerError.Error,
			),
		}
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    any    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return oauth.TokenSet{}, fmt.Errorf(
			"decode Google token response: %w",
			err,
		)
	}

	payload.AccessToken = strings.TrimSpace(payload.AccessToken)
	payload.RefreshToken = strings.TrimSpace(payload.RefreshToken)
	payload.TokenType = strings.TrimSpace(payload.TokenType)
	payload.Scope = strings.TrimSpace(payload.Scope)

	if payload.AccessToken == "" {
		return oauth.TokenSet{}, fmt.Errorf(
			"Google token response omitted access_token",
		)
	}

	expiresIn, err := parseExpiresIn(payload.ExpiresIn)
	if err != nil {
		return oauth.TokenSet{}, err
	}

	return oauth.TokenSet{
		AccessToken:  payload.AccessToken,
		RefreshToken: payload.RefreshToken,
		TokenType:    payload.TokenType,
		ExpiresIn:    expiresIn,
		Scopes:       strings.Fields(payload.Scope),
	}, nil
}

func parseExpiresIn(value any) (int64, error) {
	switch typed := value.(type) {
	case float64:
		if typed < 0 {
			return 0, fmt.Errorf("invalid Google expires_in")
		}
		return int64(typed), nil

	case string:
		parsed, err := strconv.ParseInt(
			strings.TrimSpace(typed),
			10,
			64,
		)
		if err != nil || parsed < 0 {
			return 0, fmt.Errorf("invalid Google expires_in")
		}
		return parsed, nil

	case nil:
		return 0, nil

	default:
		return 0, fmt.Errorf("invalid Google expires_in")
	}
}

func sanitizeProviderCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if len(value) > 80 {
		value = value[:80]
	}

	for _, r := range value {
		if !(r >= 'a' && r <= 'z') &&
			!(r >= 'A' && r <= 'Z') &&
			!(r >= '0' && r <= '9') &&
			r != '_' &&
			r != '-' {
			return ""
		}
	}

	return value
}
