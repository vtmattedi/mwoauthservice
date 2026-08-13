package oauth

type TokenSet struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
	Scopes       []string
}

func clearTokenSet(tokens *TokenSet) {
	if tokens == nil {
		return
	}

	tokens.AccessToken = ""
	tokens.RefreshToken = ""
	tokens.TokenType = ""
	tokens.ExpiresIn = 0

	for i := range tokens.Scopes {
		tokens.Scopes[i] = ""
	}
	tokens.Scopes = nil
}
