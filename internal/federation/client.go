package federation

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
)

const maxIntrospectionBody = 64 << 10

type IntrospectionClient interface {
	Introspect(context.Context, string) (Token, error)
}

type Token struct {
	Active   bool
	Subject  string
	Audience []string
	Scopes   []string
	AuthTime *time.Time
	AMR      []string
}

type Client struct {
	endpoint     string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

type ClientOptions struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	Timeout      time.Duration
	HTTPClient   *http.Client
}

func NewClient(opts ClientOptions) (*Client, error) {
	base, err := url.Parse(strings.TrimSpace(opts.BaseURL))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") ||
		base.Host == "" || base.User != nil {
		return nil, fmt.Errorf("invalid Identity base URL")
	}
	if strings.TrimSpace(opts.ClientID) == "" || opts.ClientSecret == "" {
		return nil, fmt.Errorf("Identity introspection credentials are required")
	}

	base.Path = strings.TrimRight(base.Path, "/") + "/oauth/introspect"
	base.RawQuery = ""
	base.Fragment = ""

	var httpClient *http.Client
	if opts.HTTPClient == nil {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		httpClient = &http.Client{Timeout: timeout}
	} else {
		clone := *opts.HTTPClient
		httpClient = &clone
		if opts.Timeout > 0 {
			httpClient.Timeout = opts.Timeout
		}
	}
	previousRedirectPolicy := httpClient.CheckRedirect
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
			return http.ErrUseLastResponse
		}
		if previousRedirectPolicy != nil {
			return previousRedirectPolicy(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}

	return &Client{
		endpoint: base.String(), clientID: strings.TrimSpace(opts.ClientID),
		clientSecret: opts.ClientSecret, httpClient: httpClient,
	}, nil
}

func (c *Client) Introspect(ctx context.Context, rawToken string) (Token, error) {
	form := url.Values{"token": []string{rawToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, fmt.Errorf("%w: create request", ErrIntrospectionFailed)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	response, err := c.httpClient.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("%w: transport", ErrIntrospectionFailed)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxIntrospectionBody+1))
		return Token{}, fmt.Errorf("%w: status %d", ErrIntrospectionFailed, response.StatusCode)
	}

	limited := io.LimitReader(response.Body, maxIntrospectionBody+1)
	body, err := io.ReadAll(limited)
	if err != nil || len(body) > maxIntrospectionBody {
		return Token{}, fmt.Errorf("%w: invalid response body", ErrIntrospectionFailed)
	}

	var payload introspectionResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return Token{}, fmt.Errorf("%w: invalid response JSON", ErrIntrospectionFailed)
	}

	authTime, err := payload.authTime()
	if err != nil {
		return Token{}, fmt.Errorf("%w: invalid auth_time", ErrIntrospectionFailed)
	}
	return Token{
		Active: payload.Active, Subject: strings.TrimSpace(payload.Subject),
		Audience: payload.Audience.values(), Scopes: strings.Fields(payload.Scope),
		AuthTime: authTime, AMR: payload.AMR,
	}, nil
}

type stringOrStrings []string

func (s *stringOrStrings) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

func (s stringOrStrings) values() []string {
	result := make([]string, 0, len(s))
	for _, value := range s {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

type introspectionResponse struct {
	Active   bool            `json:"active"`
	Subject  string          `json:"sub"`
	Audience stringOrStrings `json:"aud"`
	Scope    string          `json:"scope"`
	AuthTime json.RawMessage `json:"auth_time"`
	AMR      []string        `json:"amr"`
}

func (r introspectionResponse) authTime() (*time.Time, error) {
	if len(r.AuthTime) == 0 || string(r.AuthTime) == "null" {
		return nil, nil
	}
	var unix int64
	if err := json.Unmarshal(r.AuthTime, &unix); err != nil {
		var raw string
		if json.Unmarshal(r.AuthTime, &raw) != nil {
			return nil, err
		}
		unix, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	value := time.Unix(unix, 0).UTC()
	return &value, nil
}
