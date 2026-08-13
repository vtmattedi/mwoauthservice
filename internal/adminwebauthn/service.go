package adminwebauthn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

const (
	ceremonyTTL        = 5 * time.Minute
	ceremonyTokenBytes = 32
	userHandleBytes    = 64
	maxCredentialLabel = 80

	purposeRegistration   = "registration"
	purposeAuthentication = "authentication"
)

var (
	ErrInvalidCeremony = errors.New("invalid WebAuthn ceremony")
	ErrVerification    = errors.New("WebAuthn verification failed")
	ErrDisabledAdmin   = errors.New("admin is disabled")
	ErrInvalidLabel    = errors.New("invalid WebAuthn credential label")
)

type Options struct {
	RPID                       string
	RPName                     string
	Origins                    []string
	CredentialKeys             string
	CredentialActiveKeyVersion int
}

type Service struct {
	store   Store
	keyring *Keyring
	web     *webauthn.WebAuthn
	rpid    string
}

func NewService(
	store Store,
	opts Options,
) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("WebAuthn store is required")
	}

	rpid := strings.TrimSpace(opts.RPID)
	if rpid == "" {
		return nil, fmt.Errorf("WEBAUTHN_RP_ID is required")
	}

	rpName := strings.TrimSpace(opts.RPName)
	if rpName == "" {
		rpName = "MW OAuth"
	}

	origins := compactOrigins(opts.Origins)
	if len(origins) == 0 {
		return nil, fmt.Errorf("WEBAUTHN_ORIGINS is required")
	}

	keyring, err := NewKeyring(
		opts.CredentialKeys,
		opts.CredentialActiveKeyVersion,
	)
	if err != nil {
		return nil, err
	}

	timeout := webauthn.TimeoutConfig{
		Enforce:    true,
		Timeout:    ceremonyTTL,
		TimeoutUVD: ceremonyTTL,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPID:                  rpid,
		RPDisplayName:         rpName,
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        timeout,
			Registration: timeout,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure WebAuthn: %w", err)
	}

	return &Service{
		store:   store,
		keyring: keyring,
		web:     web,
		rpid:    rpid,
	}, nil
}

func (s *Service) BeginRegistration(
	ctx context.Context,
	adminUser domain.AdminUser,
	label string,
) (
	*protocol.CredentialCreation,
	string,
	error,
) {
	if !adminUser.Enabled {
		return nil, "", ErrDisabledAdmin
	}

	label = strings.TrimSpace(label)
	if len(label) > maxCredentialLabel {
		return nil, "", ErrInvalidLabel
	}

	userRecord, err := s.ensureUser(
		ctx,
		adminUser.ID,
	)
	if err != nil {
		return nil, "", err
	}

	credentials, err := s.loadCredentials(
		ctx,
		adminUser.ID,
	)
	if err != nil {
		return nil, "", err
	}

	user := &webAuthnUser{
		admin:       adminUser,
		handle:      userRecord.UserHandle,
		credentials: credentials,
	}

	creation, session, err := s.web.BeginRegistration(
		user,
		webauthn.WithResidentKeyRequirement(
			protocol.ResidentKeyRequirementRequired,
		),
		webauthn.WithExclusions(
			webauthn.Credentials(
				user.WebAuthnCredentials(),
			).CredentialDescriptors(),
		),
		webauthn.WithExtensions(
			map[string]any{"credProps": true},
		),
	)
	if err != nil {
		return nil, "", fmt.Errorf(
			"begin WebAuthn registration: %w",
			err,
		)
	}

	token, err := s.saveCeremony(
		ctx,
		&adminUser.ID,
		purposeRegistration,
		label,
		session,
	)
	if err != nil {
		return nil, "", err
	}

	return creation, token, nil
}

func (s *Service) FinishRegistration(
	ctx context.Context,
	adminUserID int64,
	ceremonyToken string,
	request *http.Request,
) (CredentialSummary, error) {
	ceremony, session, err := s.consumeCeremony(
		ctx,
		ceremonyToken,
		purposeRegistration,
	)
	if err != nil {
		return CredentialSummary{}, err
	}
	if ceremony.AdminUserID == nil ||
		*ceremony.AdminUserID != adminUserID {
		return CredentialSummary{}, ErrInvalidCeremony
	}

	adminUser, err := s.store.GetAdminUserByID(
		ctx,
		adminUserID,
	)
	if err != nil {
		return CredentialSummary{}, ErrInvalidCeremony
	}
	if !adminUser.Enabled {
		return CredentialSummary{}, ErrDisabledAdmin
	}

	userRecord, err := s.store.GetWebAuthnUser(
		ctx,
		adminUserID,
		s.rpid,
	)
	if err != nil {
		return CredentialSummary{}, ErrInvalidCeremony
	}

	credentials, err := s.loadCredentials(
		ctx,
		adminUserID,
	)
	if err != nil {
		return CredentialSummary{}, err
	}

	user := &webAuthnUser{
		admin:       adminUser,
		handle:      userRecord.UserHandle,
		credentials: credentials,
	}

	credential, err := s.web.FinishRegistration(
		user,
		*session,
		request,
	)
	if err != nil {
		return CredentialSummary{}, ErrVerification
	}

	record, err := s.encryptCredential(
		adminUserID,
		ceremony.Label,
		*credential,
	)
	if err != nil {
		return CredentialSummary{}, err
	}

	stored, err := s.store.InsertWebAuthnCredential(
		ctx,
		record,
	)
	if err != nil {
		return CredentialSummary{}, err
	}

	return summaryFromRecord(stored), nil
}

func (s *Service) BeginLogin(
	ctx context.Context,
) (
	*protocol.CredentialAssertion,
	string,
	error,
) {
	assertion, session, err := s.web.BeginDiscoverableLogin(
		webauthn.WithUserVerification(
			protocol.VerificationRequired,
		),
	)
	if err != nil {
		return nil, "", fmt.Errorf(
			"begin WebAuthn login: %w",
			err,
		)
	}

	token, err := s.saveCeremony(
		ctx,
		nil,
		purposeAuthentication,
		"",
		session,
	)
	if err != nil {
		return nil, "", err
	}

	return assertion, token, nil
}

func (s *Service) FinishLogin(
	ctx context.Context,
	ceremonyToken string,
	request *http.Request,
) (domain.AdminUser, error) {
	_, session, err := s.consumeCeremony(
		ctx,
		ceremonyToken,
		purposeAuthentication,
	)
	if err != nil {
		return domain.AdminUser{}, err
	}

	var resolved *webAuthnUser

	handler := func(
		rawID []byte,
		userHandle []byte,
	) (webauthn.User, error) {
		adminUser, userRecord, err :=
			s.store.FindWebAuthnUserForCredential(
				ctx,
				s.rpid,
				userHandle,
				rawID,
			)
		if err != nil {
			return nil, ErrVerification
		}
		if !adminUser.Enabled {
			return nil, ErrDisabledAdmin
		}

		credentials, err := s.loadCredentials(
			ctx,
			adminUser.ID,
		)
		if err != nil {
			return nil, err
		}

		resolved = &webAuthnUser{
			admin:       adminUser,
			handle:      userRecord.UserHandle,
			credentials: credentials,
		}
		return resolved, nil
	}

	user, credential, err := s.web.FinishPasskeyLogin(
		handler,
		*session,
		request,
	)
	if err != nil {
		return domain.AdminUser{}, ErrVerification
	}

	verified, ok := user.(*webAuthnUser)
	if !ok || resolved == nil ||
		verified.admin.ID != resolved.admin.ID {
		return domain.AdminUser{}, ErrVerification
	}

	record, err := s.encryptCredential(
		verified.admin.ID,
		findCredentialLabel(
			credential.ID,
			s.mustCredentialRecords(
				ctx,
				verified.admin.ID,
			),
		),
		*credential,
	)
	if err != nil {
		return domain.AdminUser{}, err
	}

	if err := s.store.UpdateWebAuthnCredential(
		ctx,
		record,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return domain.AdminUser{}, err
	}

	verified.admin.PasswordHash = ""
	return verified.admin, nil
}

func (s *Service) ListCredentials(
	ctx context.Context,
	adminUserID int64,
) ([]CredentialSummary, error) {
	records, err := s.store.ListWebAuthnCredentials(
		ctx,
		adminUserID,
		s.rpid,
	)
	if err != nil {
		return nil, err
	}

	items := make([]CredentialSummary, 0, len(records))
	for _, record := range records {
		items = append(items, summaryFromRecord(record))
	}

	return items, nil
}

func (s *Service) RevokeCredential(
	ctx context.Context,
	adminUserID int64,
	encodedCredentialID string,
) error {
	credentialID, err := decodeCredentialID(
		strings.TrimSpace(encodedCredentialID),
	)
	if err != nil || len(credentialID) == 0 {
		return ErrNotFound
	}

	return s.store.RevokeWebAuthnCredential(
		ctx,
		adminUserID,
		s.rpid,
		credentialID,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
}

func (s *Service) ensureUser(
	ctx context.Context,
	adminUserID int64,
) (UserRecord, error) {
	record, err := s.store.GetWebAuthnUser(
		ctx,
		adminUserID,
		s.rpid,
	)
	if err == nil {
		return record, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return UserRecord{}, err
	}

	handle := make([]byte, userHandleBytes)
	if _, err := rand.Read(handle); err != nil {
		return UserRecord{}, fmt.Errorf(
			"generate WebAuthn user handle: %w",
			err,
		)
	}

	return s.store.EnsureWebAuthnUser(
		ctx,
		adminUserID,
		s.rpid,
		handle,
	)
}

func (s *Service) loadCredentials(
	ctx context.Context,
	adminUserID int64,
) ([]webauthn.Credential, error) {
	records, err := s.store.ListWebAuthnCredentials(
		ctx,
		adminUserID,
		s.rpid,
	)
	if err != nil {
		return nil, err
	}

	credentials := make(
		[]webauthn.Credential,
		0,
		len(records),
	)

	for _, record := range records {
		credential, err := s.decryptCredential(record)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}

	return credentials, nil
}

func (s *Service) encryptCredential(
	adminUserID int64,
	label string,
	credential webauthn.Credential,
) (CredentialRecord, error) {
	encoded, err := json.Marshal(credential)
	if err != nil {
		return CredentialRecord{}, fmt.Errorf(
			"encode WebAuthn credential: %w",
			err,
		)
	}

	aad := credentialAAD(
		adminUserID,
		s.rpid,
		credential.ID,
	)

	ciphertext, nonce, version, err :=
		s.keyring.Encrypt(encoded, aad)
	if err != nil {
		return CredentialRecord{}, err
	}

	transports, err := json.Marshal(credential.Transport)
	if err != nil {
		return CredentialRecord{}, fmt.Errorf(
			"encode WebAuthn transports: %w",
			err,
		)
	}

	return CredentialRecord{
		AdminUserID:          adminUserID,
		RPID:                 s.rpid,
		CredentialID:         append([]byte(nil), credential.ID...),
		CredentialCiphertext: ciphertext,
		CredentialNonce:      nonce,
		CredentialKeyVersion: version,
		Label:                strings.TrimSpace(label),
		TransportsJSON:       string(transports),
		AAGUID: append(
			[]byte(nil),
			credential.Authenticator.AAGUID...,
		),
		SignCount:      credential.Authenticator.SignCount,
		CloneWarning:   credential.Authenticator.CloneWarning,
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
	}, nil
}

func (s *Service) decryptCredential(
	record CredentialRecord,
) (webauthn.Credential, error) {
	aad := credentialAAD(
		record.AdminUserID,
		record.RPID,
		record.CredentialID,
	)

	plaintext, err := s.keyring.Decrypt(
		record.CredentialCiphertext,
		record.CredentialNonce,
		record.CredentialKeyVersion,
		aad,
	)
	if err != nil {
		return webauthn.Credential{}, err
	}
	defer clear(plaintext)

	var credential webauthn.Credential
	if err := json.Unmarshal(
		plaintext,
		&credential,
	); err != nil {
		return webauthn.Credential{}, fmt.Errorf(
			"decode WebAuthn credential: %w",
			err,
		)
	}

	return credential, nil
}

func (s *Service) saveCeremony(
	ctx context.Context,
	adminUserID *int64,
	purpose string,
	label string,
	session *webauthn.SessionData,
) (string, error) {
	if session == nil {
		return "", fmt.Errorf("WebAuthn session is nil")
	}

	rawToken, tokenHash, err := newCeremonyToken()
	if err != nil {
		return "", err
	}

	encoded, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf(
			"encode WebAuthn session: %w",
			err,
		)
	}

	aad := ceremonyAAD(
		tokenHash,
		s.rpid,
		purpose,
	)
	ciphertext, nonce, version, err :=
		s.keyring.Encrypt(encoded, aad)
	if err != nil {
		return "", err
	}
	clear(encoded)

	expiresAt := session.Expires.UTC()
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(ceremonyTTL)
	}

	_ = s.store.DeleteExpiredWebAuthnCeremonies(
		ctx,
		time.Now().UTC().Unix(),
	)

	if err := s.store.CreateWebAuthnCeremony(
		ctx,
		CeremonyRecord{
			TokenHash:         tokenHash,
			AdminUserID:       adminUserID,
			RPID:              s.rpid,
			Purpose:           purpose,
			SessionCiphertext: ciphertext,
			SessionNonce:      nonce,
			SessionKeyVersion: version,
			Label:             label,
			ExpiresAtUnix:     expiresAt.Unix(),
		},
	); err != nil {
		return "", err
	}

	return rawToken, nil
}

func (s *Service) consumeCeremony(
	ctx context.Context,
	rawToken string,
	expectedPurpose string,
) (
	CeremonyRecord,
	*webauthn.SessionData,
	error,
) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" ||
		!strings.HasPrefix(rawToken, "wac_") {
		return CeremonyRecord{}, nil, ErrInvalidCeremony
	}

	tokenHash := hashCeremonyToken(rawToken)
	record, err := s.store.ConsumeWebAuthnCeremony(
		ctx,
		tokenHash,
		time.Now().UTC().Unix(),
	)
	if err != nil {
		if errors.Is(err, ErrCeremonyExpired) {
			return CeremonyRecord{}, nil, ErrCeremonyExpired
		}
		if errors.Is(err, ErrCeremonyUsed) {
			return CeremonyRecord{}, nil, ErrCeremonyUsed
		}
		if errors.Is(err, ErrNotFound) {
			return CeremonyRecord{}, nil, ErrInvalidCeremony
		}
		return CeremonyRecord{}, nil, err
	}

	if record.RPID != s.rpid ||
		record.Purpose != expectedPurpose {
		return CeremonyRecord{}, nil, ErrInvalidCeremony
	}

	aad := ceremonyAAD(
		record.TokenHash,
		record.RPID,
		record.Purpose,
	)
	plaintext, err := s.keyring.Decrypt(
		record.SessionCiphertext,
		record.SessionNonce,
		record.SessionKeyVersion,
		aad,
	)
	if err != nil {
		return CeremonyRecord{}, nil, ErrInvalidCeremony
	}
	defer clear(plaintext)

	var session webauthn.SessionData
	if err := json.Unmarshal(
		plaintext,
		&session,
	); err != nil {
		return CeremonyRecord{}, nil, ErrInvalidCeremony
	}

	return record, &session, nil
}

func (s *Service) mustCredentialRecords(
	ctx context.Context,
	adminUserID int64,
) []CredentialRecord {
	records, err := s.store.ListWebAuthnCredentials(
		ctx,
		adminUserID,
		s.rpid,
	)
	if err != nil {
		return nil
	}
	return records
}

func findCredentialLabel(
	credentialID []byte,
	records []CredentialRecord,
) string {
	for _, record := range records {
		if string(record.CredentialID) == string(credentialID) {
			return record.Label
		}
	}
	return ""
}

func summaryFromRecord(
	record CredentialRecord,
) CredentialSummary {
	var transports []string
	_ = json.Unmarshal(
		[]byte(record.TransportsJSON),
		&transports,
	)

	return CredentialSummary{
		CredentialID:   encodeCredentialID(record.CredentialID),
		Label:          record.Label,
		Transports:     transports,
		SignCount:      record.SignCount,
		CloneWarning:   record.CloneWarning,
		BackupEligible: record.BackupEligible,
		BackupState:    record.BackupState,
		CreatedAt:      record.CreatedAt,
		LastUsedAt:     record.LastUsedAt,
	}
}

func credentialAAD(
	adminUserID int64,
	rpid string,
	credentialID []byte,
) []byte {
	return []byte(fmt.Sprintf(
		"mw-oauth-service:admin-webauthn:credential:v1:%d:%s:%s",
		adminUserID,
		rpid,
		base64.RawURLEncoding.EncodeToString(credentialID),
	))
}

func ceremonyAAD(
	tokenHash string,
	rpid string,
	purpose string,
) []byte {
	return []byte(
		"mw-oauth-service:admin-webauthn:ceremony:v1:" +
			tokenHash + ":" + rpid + ":" + purpose,
	)
}

func newCeremonyToken() (
	rawToken string,
	tokenHash string,
	err error,
) {
	raw := make([]byte, ceremonyTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf(
			"generate WebAuthn ceremony token: %w",
			err,
		)
	}

	rawToken = "wac_" +
		base64.RawURLEncoding.EncodeToString(raw)

	return rawToken, hashCeremonyToken(rawToken), nil
}

func hashCeremonyToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func compactOrigins(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, raw := range values {
		for _, value := range strings.Split(raw, ",") {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}

	return result
}
