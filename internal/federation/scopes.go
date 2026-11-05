package federation

const (
	ScopeProjectsRead      = "oauth.projects.read"
	ScopeProjectsWrite     = "oauth.projects.write"
	ScopeProjectsDelete    = "oauth.projects.delete"
	ScopeCredentialsRead   = "oauth.credentials.read"
	ScopeCredentialsRotate = "oauth.credentials.rotate"
	// Google client credentials are separate from policy: editing the
	// authorization policy must never allow changing Google client secrets.
	ScopeProviderCredentialsRead   = "oauth.provider_credentials.read"
	ScopeProviderCredentialsManage = "oauth.provider_credentials.manage"
	ScopePolicyRead                = "oauth.policy.read"
	ScopePolicyWrite               = "oauth.policy.write"
	ScopeAuditRead                 = "oauth.audit.read"
	ScopeMetricsRead               = "oauth.metrics.read"
	ScopeServerRead                = "oauth.server.read"
)

func hasScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}
