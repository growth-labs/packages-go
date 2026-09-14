package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

// Authorize constructs an authorization URL and transaction.
func (c *Client) Authorize(origin *url.URL, provider, redirectPath string) (*url.URL, Transaction, error) {
	if origin == nil || origin.Host == "" || (origin.Scheme != "https" && origin.Scheme != "http") {
		return nil, Transaction{}, errorf(CodeInvalidConfig, "origin must be an absolute HTTP URL")
	}
	// An empty provider is "let the issuer ask". The issuer renders its own
	// chooser over the providers it has configured, which is the only way a
	// consumer offers a choice without rebuilding that page — and a consumer
	// that pre-picks one, as every consumer did by defaulting to Google, hides
	// the others from anyone who cannot complete it.
	if provider != "" && !contains(c.config.Providers, provider) {
		return nil, Transaction{}, errorf(CodeInvalidProvider, "provider is not configured")
	}
	verifier, err := randomBase64URL()
	if err != nil {
		return nil, Transaction{}, errorf(CodeInvalidConfig, "generate PKCE verifier: %v", err)
	}
	state, err := randomBase64URL()
	if err != nil {
		return nil, Transaction{}, errorf(CodeInvalidConfig, "generate state: %v", err)
	}
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if !validAbsolutePath(redirectPath) {
		redirectPath = "/"
	}
	callbackURI := (&url.URL{Scheme: origin.Scheme, Host: origin.Host, Path: c.config.CallbackPath}).String()
	transaction := Transaction{
		Verifier:     verifier,
		Challenge:    challenge,
		State:        state,
		RedirectPath: redirectPath,
		Provider:     provider,
		CallbackURI:  callbackURI,
		ExpiresAt:    c.config.Now().Add(c.config.TransactionMaxAge),
	}
	issuerProvider := provider
	if issuerProvider == "email-code" {
		issuerProvider = "code"
	}
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.config.ClientID},
		"redirect_uri":          {callbackURI},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {c.config.Resource},
	}
	if issuerProvider != "" {
		query.Set("provider", issuerProvider)
	}
	authorizationURL, _ := url.Parse(c.config.Issuer + "/authorize")
	authorizationURL.RawQuery = query.Encode()
	return authorizationURL, transaction, nil
}

func randomBase64URL() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
