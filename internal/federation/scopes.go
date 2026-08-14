package federation

const (
	ScopeProjectsRead      = "oauth.projects.read"
	ScopeProjectsWrite     = "oauth.projects.write"
	ScopeProjectsDelete    = "oauth.projects.delete"
	ScopeCredentialsRotate = "oauth.credentials.rotate"
	ScopePolicyRead        = "oauth.policy.read"
	ScopePolicyWrite       = "oauth.policy.write"
	ScopeAuditRead         = "oauth.audit.read"
	ScopeMetricsRead       = "oauth.metrics.read"
	ScopeServerRead        = "oauth.server.read"
)

func hasScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}
