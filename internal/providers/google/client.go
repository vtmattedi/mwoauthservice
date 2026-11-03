package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
)

// officialTokenEndpoint is Google's token endpoint. It is fixed in code:
// nothing a consumer sends can change where client secrets or refresh tokens
// are posted.
const officialTokenEndpoint = "https://oauth2.googleapis.com/token"

const (
	defaultTimeout   = 15 * time.Second
	maxResponseBytes = 256 << 10
	maxRetryAfter    = 5 * time.Minute
)

// Options configures the client. The OAuth client ID and secret are not part
// of it: each call receives the credentials of the project it acts for.
type Options struct {
	// RedirectURI is the central Google-facing callback URL.
	RedirectURI string
	// TokenEndpoint overrides the official endpoint. It exists for tests and
	// must not be set from request data.
	TokenEndpoint string
	HTTPClient    *http.Client
}

// Credentials identify one Google OAuth client.
type Credentials = oauth.GoogleClient

func validateCredentials(c Credentials) error {
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("Google OAuth client ID is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return errors.New("Google OAuth client secret is required")
	}
	return nil
}

type Client struct {
	redirectURI   string
	tokenEndpoint string
	httpClient    *http.Client
}

// ErrorKind classifies a provider failure so callers can decide whether to
// ask for reauthorization, retry later, or fix configuration.
type ErrorKind string

const (
	// KindInvalidGrant: the code or refresh token is no longer valid.
	KindInvalidGrant ErrorKind = "invalid_grant"
	// KindRateLimited: Google throttled the request (HTTP 429).
	KindRateLimited ErrorKind = "rate_limited"
	// KindUnavailable: outage, timeout, network failure or an unusable
	// response. Retrying later may succeed.
	KindUnavailable ErrorKind = "unavailable"
	// KindRejected: Google refused the request for another reason, such as
	// an invalid client or secret.
	KindRejected ErrorKind = "rejected"
)

// ProviderError describes a failed call to Google. It never carries Google's
// response body or error description, only a sanitized provider code.
type ProviderError struct {
	Operation    string
	StatusCode   int
	ProviderCode string
	Kind         ErrorKind
	// RetryAfter is Google's Retry-After (bounded), when it sent one.
	RetryAfter time.Duration

	cause error
}

// ExchangeError is the previous name of ProviderError.
type ExchangeError = ProviderError

func (e *ProviderError) Error() string {
	switch {
	case e.StatusCode != 0 && e.ProviderCode != "":
		return fmt.Sprintf(
			"Google %s failed: status=%d code=%s",
			e.Operation, e.StatusCode, e.ProviderCode,
		)
	case e.StatusCode != 0:
		return fmt.Sprintf(
			"Google %s failed: status=%d",
			e.Operation, e.StatusCode,
		)
	case e.cause != nil:
		// Causes are fixed, sanitized phrases ("request timed out").
		return fmt.Sprintf(
			"Google %s failed: %s (%v)",
			e.Operation, e.Kind, e.cause,
		)
	default:
		return fmt.Sprintf("Google %s failed: %s", e.Operation, e.Kind)
	}
}

func (e *ProviderError) Unwrap() error { return e.cause }

func NewClient(options Options) (*Client, error) {
	redirectURI := strings.TrimSpace(options.RedirectURI)
	if redirectURI == "" {
		return nil, fmt.Errorf("Google OAuth redirect URI is required")
	}

	endpoint := strings.TrimSpace(options.TokenEndpoint)
	if endpoint == "" {
		endpoint = officialTokenEndpoint
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
		httpClient = &http.Client{Timeout: defaultTimeout}
	}

	// Never follow redirects: a redirect would resend the client secret and
	// refresh token to whatever host it points at.
	guarded := *httpClient
	guarded.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Client{
		redirectURI:   redirectURI,
		tokenEndpoint: endpoint,
		httpClient:    &guarded,
	}, nil
}

// ExchangeCode trades an authorization code for tokens using the given Google
// client credentials.
func (c *Client) ExchangeCode(
	ctx context.Context,
	credentials Credentials,
	code string,
	verifier string,
) (oauth.TokenSet, error) {
	if err := validateCredentials(credentials); err != nil {
		return oauth.TokenSet{}, err
	}

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
	form.Set("client_id", credentials.ClientID)
	form.Set("client_secret", credentials.ClientSecret)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", c.redirectURI)

	tokens, err := c.postToken(ctx, "token exchange", form)
	if err != nil {
		return oauth.TokenSet{}, err
	}
	return tokens, nil
}

// Refresh renews a Google access token using the same OAuth client that issued
// the refresh token. The returned RefreshToken is set only when Google sent a
// replacement; otherwise the caller keeps the one it has.
func (c *Client) Refresh(
	ctx context.Context,
	credentials Credentials,
	refreshToken string,
) (oauth.TokenSet, error) {
	if err := validateCredentials(credentials); err != nil {
		return oauth.TokenSet{}, err
	}

	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return oauth.TokenSet{}, fmt.Errorf("refresh token is required")
	}

	form := url.Values{}
	form.Set("client_id", credentials.ClientID)
	form.Set("client_secret", credentials.ClientSecret)
	form.Set("refresh_token", refreshToken)
	form.Set("grant_type", "refresh_token")

	tokens, err := c.postToken(ctx, "token refresh", form)
	if err != nil {
		return oauth.TokenSet{}, err
	}

	// A refresh must yield a usable, bounded access token.
	if tokens.ExpiresIn <= 0 {
		return oauth.TokenSet{}, &ProviderError{
			Operation: "token refresh",
			Kind:      KindUnavailable,
			cause:     errors.New("response omitted expires_in"),
		}
	}
	return tokens, nil
}

func (c *Client) postToken(
	ctx context.Context,
	operation string,
	form url.Values,
) (oauth.TokenSet, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.tokenEndpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return oauth.TokenSet{}, fmt.Errorf(
			"create Google %s request: %w", operation, err,
		)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return oauth.TokenSet{}, &ProviderError{
			Operation: operation,
			Kind:      KindUnavailable,
			cause:     sanitizeTransportError(err),
		}
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return oauth.TokenSet{}, &ProviderError{
			Operation:  operation,
			StatusCode: response.StatusCode,
			Kind:       KindUnavailable,
			cause:      errors.New("could not read response"),
		}
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var providerError struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &providerError)
		code := sanitizeProviderCode(providerError.Error)

		return oauth.TokenSet{}, &ProviderError{
			Operation:    operation,
			StatusCode:   response.StatusCode,
			ProviderCode: code,
			Kind:         classify(response.StatusCode, code),
			RetryAfter: parseRetryAfter(
				response.Header.Get("Retry-After"),
				time.Now(),
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
		return oauth.TokenSet{}, &ProviderError{
			Operation:  operation,
			StatusCode: response.StatusCode,
			Kind:       KindUnavailable,
			cause:      errors.New("response is not valid JSON"),
		}
	}

	payload.AccessToken = strings.TrimSpace(payload.AccessToken)
	payload.RefreshToken = strings.TrimSpace(payload.RefreshToken)
	payload.TokenType = strings.TrimSpace(payload.TokenType)
	payload.Scope = strings.TrimSpace(payload.Scope)

	if payload.AccessToken == "" {
		return oauth.TokenSet{}, &ProviderError{
			Operation:  operation,
			StatusCode: response.StatusCode,
			Kind:       KindUnavailable,
			cause:      errors.New("response omitted access_token"),
		}
	}
	// token_type is passed through as Google sent it. Rejecting an unexpected
	// value here would fail an exchange after Google already consumed the
	// one-time code, which no retry can recover.

	expiresIn, err := parseExpiresIn(payload.ExpiresIn)
	if err != nil {
		return oauth.TokenSet{}, &ProviderError{
			Operation:  operation,
			StatusCode: response.StatusCode,
			Kind:       KindUnavailable,
			cause:      err,
		}
	}

	return oauth.TokenSet{
		AccessToken:  payload.AccessToken,
		RefreshToken: payload.RefreshToken,
		TokenType:    payload.TokenType,
		ExpiresIn:    expiresIn,
		Scopes:       strings.Fields(payload.Scope),
	}, nil
}

func classify(status int, providerCode string) ErrorKind {
	switch {
	case providerCode == "invalid_grant":
		return KindInvalidGrant
	case status == http.StatusTooManyRequests:
		return KindRateLimited
	case status >= 500:
		return KindUnavailable
	default:
		return KindRejected
	}
}

// sanitizeTransportError keeps the failure category but drops details such as
// URLs, which are not needed by callers.
func sanitizeTransportError(err error) error {
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New("request timed out")
	case errors.Is(err, context.Canceled):
		return errors.New("request canceled")
	case errors.As(err, &netErr) && netErr.Timeout():
		return errors.New("request timed out")
	default:
		return errors.New("network error")
	}
}

// parseRetryAfter reads a Retry-After header, which is either a number of
// seconds or an HTTP date, and bounds the result. Anything unusable is 0.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	var delay time.Duration
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		delay = time.Duration(seconds) * time.Second
	} else if when, err := http.ParseTime(value); err == nil {
		delay = when.Sub(now)
		if delay <= 0 {
			return 0
		}
	} else {
		return 0
	}

	if delay > maxRetryAfter {
		return maxRetryAfter
	}
	return delay
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
