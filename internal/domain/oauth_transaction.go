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
	Status                 string
	ExpiresAtUnix          int64
	ConsumedAtUnix         *int64
	CreatedAt              string
	CreatedAtUnix          int64
}
