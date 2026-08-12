package domain

type AdminUser struct {
	ID           int64  `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

type AdminSession struct {
	ID        int64
	User      AdminUser
	TokenHash string
	CSRFHash  string
	ExpiresAt int64
	CreatedAt string
}
