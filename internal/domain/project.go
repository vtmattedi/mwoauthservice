package domain

type Project struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	// AppCredentialsConfigured says whether the project has an MW application
	// client (client ID and secret). Without one, no application can
	// authenticate for the project.
	AppCredentialsConfigured bool `json:"app_credentials_configured"`
}

type OAuthLimits struct {
	PerMinute  int `json:"per_minute"`
	PerHour    int `json:"per_hour"`
	MaxPending int `json:"max_pending"`
}

type GoogleOAuthConfig struct {
	Enabled             bool        `json:"enabled"`
	AllowedScopes       []string    `json:"allowed_scopes"`
	AllowedCallbackURLs []string    `json:"allowed_callback_urls"`
	AllowedReturnURLs   []string    `json:"allowed_return_urls"`
	Limits              OAuthLimits `json:"limits"`
}
