package domain

// Integration modes describe how a project's consumer authenticates.
const (
	// IntegrationLegacy: only the mw_live_ API key exists.
	IntegrationLegacy = "legacy"
	// IntegrationMigrating: MW client credentials exist and the legacy API
	// key is still accepted.
	IntegrationMigrating = "migrating"
	// IntegrationAppCredentials: MW client credentials only.
	IntegrationAppCredentials = "app_credentials"
	// IntegrationUnconfigured: no MW client credentials and legacy disabled,
	// so nothing can authenticate.
	IntegrationUnconfigured = "unconfigured"
)

type Project struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	// LegacyEnabled says whether the mw_live_ API key (and, in later phases,
	// the global Google client) is still accepted for this project.
	LegacyEnabled bool `json:"legacy_enabled"`
	// AppCredentialsConfigured says whether an MW application client exists.
	AppCredentialsConfigured bool `json:"app_credentials_configured"`
	// IntegrationMode is derived from the two flags above.
	IntegrationMode string `json:"integration_mode"`
}

// ResolveIntegrationMode derives IntegrationMode from the stored flags.
func (p *Project) ResolveIntegrationMode() {
	switch {
	case p.AppCredentialsConfigured && p.LegacyEnabled:
		p.IntegrationMode = IntegrationMigrating
	case p.AppCredentialsConfigured:
		p.IntegrationMode = IntegrationAppCredentials
	case p.LegacyEnabled:
		p.IntegrationMode = IntegrationLegacy
	default:
		p.IntegrationMode = IntegrationUnconfigured
	}
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
