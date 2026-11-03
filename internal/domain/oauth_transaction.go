package domain

type OAuthTransaction struct {
	ID                     string
	ProjectID              int64
	Provider               string
	StateHash              string
	PKCEVerifierCiphertext string
	PKCEVerifierNonce      string
	ClientReference        string
	CallbackURL            string
	ReturnURL              string
	RequestedScopesJSON    string
	// GoogleCredentialID pins the per-project Google client used when the
	// authorization started, so a rotation during consent cannot change which
	// client exchanges the code. Empty means the legacy global client.
	GoogleCredentialID string
	Status             string
	ExpiresAtUnix      int64
	ConsumedAtUnix     *int64
	CreatedAt          string
	CreatedAtUnix      int64
}
