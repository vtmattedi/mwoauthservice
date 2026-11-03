package domain

// GoogleCredentialIDPrefix is the prefix of every stored credential ID. The
// ID is the opaque credential_ref handed to consumers.
const GoogleCredentialIDPrefix = "gcred_"

type GoogleCredentialState string

const (
	GoogleCredentialActive   GoogleCredentialState = "active"
	GoogleCredentialRetiring GoogleCredentialState = "retiring"
	GoogleCredentialDisabled GoogleCredentialState = "disabled"
)

func (s GoogleCredentialState) Valid() bool {
	switch s {
	case GoogleCredentialActive,
		GoogleCredentialRetiring,
		GoogleCredentialDisabled:
		return true
	}
	return false
}

// CanTransitionTo reports whether a lifecycle move is allowed:
// active -> retiring | disabled, retiring -> disabled. Disabled is final;
// a credential is never reactivated (create a new one instead).
func (s GoogleCredentialState) CanTransitionTo(next GoogleCredentialState) bool {
	switch s {
	case GoogleCredentialActive:
		return next == GoogleCredentialRetiring ||
			next == GoogleCredentialDisabled
	case GoogleCredentialRetiring:
		return next == GoogleCredentialDisabled
	}
	return false
}

type GoogleCredentialSource string

const (
	GoogleCredentialSourceProject GoogleCredentialSource = "project"
)

// GoogleCredential is credential metadata only. It never carries the client
// secret or its ciphertext, so it is safe to return from admin read paths.
type GoogleCredential struct {
	ID               string                 `json:"credential_ref"`
	ProjectID        int64                  `json:"project_id"`
	ClientID         string                 `json:"client_id"`
	State            GoogleCredentialState  `json:"state"`
	Source           GoogleCredentialSource `json:"source"`
	SecretAvailable  bool                   `json:"secret_available"`
	KeyVersion       int                    `json:"key_version,omitempty"`
	CreatedAt        string                 `json:"created_at"`
	UpdatedAt        string                 `json:"updated_at"`
	RetiredAt        string                 `json:"retired_at,omitempty"`
	DisabledAt       string                 `json:"disabled_at,omitempty"`
	SecretDeletedAt  string                 `json:"secret_deleted_at,omitempty"`
	LastAuthorizedAt string                 `json:"last_authorized_at,omitempty"`
	LastRefreshedAt  string                 `json:"last_refreshed_at,omitempty"`
}
