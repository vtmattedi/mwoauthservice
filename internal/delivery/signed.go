package delivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

const (
	webhookIDRandomBytes  = 18
	maxResponseDrainBytes = 4096
)

var retryDelays = []time.Duration{
	0,
	250 * time.Millisecond,
	750 * time.Millisecond,
}

type Options struct {
	HTTPClient *http.Client
	Now        func() time.Time
	Sleep      func(context.Context, time.Duration) error
}

type SignedDeliverer struct {
	projects   *project.Service
	httpClient *http.Client
	now        func() time.Time
	sleep      func(context.Context, time.Duration) error
}

type DeliveryError struct {
	Attempts   int
	LastStatus int
	Reason     string
}

func (e *DeliveryError) Error() string {
	return fmt.Sprintf(
		"signed callback delivery failed: reason=%s attempts=%d status=%d",
		e.Reason,
		e.Attempts,
		e.LastStatus,
	)
}

type successPayload struct {
	Event           string `json:"event"`
	TransactionID   string `json:"transaction_id"`
	ClientReference string `json:"client_reference"`
	Provider        string `json:"provider"`
	// CredentialRef identifies the per-project Google client that issued the
	// token. The consumer stores it next to the refresh token and sends it
	// back to refresh with the exact same client.
	CredentialRef string       `json:"credential_ref"`
	Token         tokenPayload `json:"token"`
}

type tokenPayload struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int64    `json:"expires_in"`
	Scope        []string `json:"scope"`
}

func NewSignedDeliverer(
	projects *project.Service,
	options Options,
) (*SignedDeliverer, error) {
	if projects == nil {
		return nil, fmt.Errorf("project service is required")
	}

	var client http.Client
	if options.HTTPClient != nil {
		client = *options.HTTPClient
	} else {
		client.Timeout = 8 * time.Second
	}

	if client.Timeout <= 0 {
		client.Timeout = 8 * time.Second
	}

	// Never follow a project callback redirect. Following a redirect could
	// forward the signed body, including OAuth tokens, to a different host.
	client.CheckRedirect = func(
		req *http.Request,
		via []*http.Request,
	) error {
		return http.ErrUseLastResponse
	}

	now := options.Now
	if now == nil {
		now = func() time.Time {
			return time.Now().UTC()
		}
	}

	sleep := options.Sleep
	if sleep == nil {
		sleep = sleepContext
	}

	return &SignedDeliverer{
		projects:   projects,
		httpClient: &client,
		now:        now,
		sleep:      sleep,
	}, nil
}

func (d *SignedDeliverer) Deliver(
	ctx context.Context,
	transaction domain.OAuthTransaction,
	tokens oauth.TokenSet,
) error {
	if err := validateCallbackURL(transaction.CallbackURL); err != nil {
		return &DeliveryError{
			Reason: "invalid_callback_url",
		}
	}

	signingSecret, err := d.projects.CallbackSigningSecret(
		ctx,
		transaction.ProjectID,
	)
	if err != nil {
		return &DeliveryError{
			Reason: "signing_secret_unavailable",
		}
	}
	defer clearBytes(signingSecret)

	scopes := append([]string(nil), tokens.Scopes...)
	if len(scopes) == 0 {
		scopes = requestedScopes(transaction.RequestedScopesJSON)
	}

	payload := successPayload{
		Event:           "oauth.authorization.completed",
		TransactionID:   transaction.ID,
		ClientReference: transaction.ClientReference,
		Provider:        transaction.Provider,
		CredentialRef:   transaction.GoogleCredentialID,
		Token: tokenPayload{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			TokenType:    tokens.TokenType,
			ExpiresIn:    tokens.ExpiresIn,
			Scope:        scopes,
		},
	}

	rawBody, err := json.Marshal(payload)
	if err != nil {
		return &DeliveryError{
			Reason: "encode_payload",
		}
	}

	webhookID, err := newWebhookID()
	if err != nil {
		return &DeliveryError{
			Reason: "generate_webhook_id",
		}
	}

	timestamp := d.now().UTC().Unix()
	timestampText := strconv.FormatInt(timestamp, 10)

	signature := signatureHex(
		signingSecret,
		webhookID,
		timestampText,
		rawBody,
	)

	attempts := 0
	lastStatus := 0
	lastReason := "unknown"

	for _, delay := range retryDelays {
		if delay > 0 {
			if err := d.sleep(ctx, delay); err != nil {
				return &DeliveryError{
					Attempts:   attempts,
					LastStatus: lastStatus,
					Reason:     "context_cancelled",
				}
			}
		}

		attempts++

		request, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			transaction.CallbackURL,
			bytes.NewReader(rawBody),
		)
		if err != nil {
			return &DeliveryError{
				Attempts:   attempts,
				LastStatus: lastStatus,
				Reason:     "build_request",
			}
		}

		request.Header.Set(
			"Content-Type",
			"application/json",
		)
		request.Header.Set(
			"Accept",
			"application/json",
		)
		request.Header.Set(
			"User-Agent",
			"mw-oauth-service/1",
		)
		request.Header.Set(
			"X-MW-Webhook-Id",
			webhookID,
		)
		request.Header.Set(
			"X-MW-Timestamp",
			timestampText,
		)
		request.Header.Set(
			"X-MW-Signature",
			"v1="+signature,
		)

		response, err := d.httpClient.Do(request)
		if err != nil {
			lastReason = "transport_error"
			lastStatus = 0
			continue
		}

		lastStatus = response.StatusCode

		// Do not inspect, return, or log project response bodies. Drain only
		// a small bounded amount so keep-alive can be reused where possible.
		_, _ = io.Copy(
			io.Discard,
			io.LimitReader(
				response.Body,
				maxResponseDrainBytes,
			),
		)
		_ = response.Body.Close()

		if response.StatusCode >= 200 &&
			response.StatusCode < 300 {
			return nil
		}

		lastReason = "non_2xx"
	}

	return &DeliveryError{
		Attempts:   attempts,
		LastStatus: lastStatus,
		Reason:     lastReason,
	}
}

func signatureHex(
	secret []byte,
	webhookID string,
	timestamp string,
	rawBody []byte,
) string {
	mac := hmac.New(sha256.New, secret)

	_, _ = mac.Write([]byte(webhookID))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(rawBody)

	return hex.EncodeToString(mac.Sum(nil))
}

func newWebhookID() (string, error) {
	raw := make([]byte, webhookIDRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return "oauth_delivery_" +
			base64.RawURLEncoding.EncodeToString(raw),
		nil
}

func requestedScopes(raw string) []string {
	var scopes []string
	if err := json.Unmarshal([]byte(raw), &scopes); err != nil {
		return []string{}
	}

	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			result = append(result, scope)
		}
	}

	return result
}

func validateCallbackURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil ||
		!parsed.IsAbs() ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return fmt.Errorf("invalid callback URL")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf(
			"non-local callback URL must use https",
		)
	default:
		return fmt.Errorf(
			"callback URL must use http or https",
		)
	}
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sleepContext(
	ctx context.Context,
	delay time.Duration,
) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
