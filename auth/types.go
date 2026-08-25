package auth

import "time"

// Transaction is the short-lived browser authorization state.
type Transaction struct {
	Verifier     string
	Challenge    string
	State        string
	RedirectPath string
	Provider     string
	CallbackURI  string
	ExpiresAt    time.Time
}

// Tokens is one access/refresh token pair.
type Tokens struct {
	AccessToken  string
	RefreshToken string
}

// Principal is a verified OpenAuth user.
type Principal struct {
	Subject   string
	UserID    string
	Email     string
	Name      string
	Image     string
	Roles     []string
	Audiences []string
}
