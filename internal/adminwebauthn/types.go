package adminwebauthn

import (
	"encoding/base64"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

type UserRecord struct {
	ID          int64
	AdminUserID int64
	RPID        string
	UserHandle  []byte
	CreatedAt   string
}

type CredentialRecord struct {
	ID                   int64
	AdminUserID          int64
	RPID                 string
	CredentialID         []byte
	CredentialCiphertext string
	CredentialNonce      string
	CredentialKeyVersion int
	Label                string
	TransportsJSON       string
	AAGUID               []byte
	SignCount            uint32
	CloneWarning         bool
	BackupEligible       bool
	BackupState          bool
	CreatedAt            string
	LastUsedAt           string
	RevokedAt            string
}

type CeremonyRecord struct {
	ID                int64
	TokenHash         string
	AdminUserID       *int64
	RPID              string
	Purpose           string
	SessionCiphertext string
	SessionNonce      string
	SessionKeyVersion int
	Label             string
	ExpiresAtUnix     int64
	ConsumedAtUnix    *int64
	CreatedAt         string
}

type CredentialSummary struct {
	CredentialID   string   `json:"credential_id"`
	Label          string   `json:"label"`
	Transports     []string `json:"transports"`
	SignCount      uint32   `json:"sign_count"`
	CloneWarning   bool     `json:"clone_warning"`
	BackupEligible bool     `json:"backup_eligible"`
	BackupState    bool     `json:"backup_state"`
	CreatedAt      string   `json:"created_at"`
	LastUsedAt     string   `json:"last_used_at,omitempty"`
}

type webAuthnUser struct {
	admin       domain.AdminUser
	handle      []byte
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return append([]byte(nil), u.handle...)
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.admin.Email
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	return u.admin.Email
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return append(
		[]webauthn.Credential(nil),
		u.credentials...,
	)
}

func encodeCredentialID(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCredentialID(raw string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(raw)
}
