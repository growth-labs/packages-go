package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxTokenResponseBytes = 1 << 20

// ExchangeRequest is an authorization-code callback exchange.
type ExchangeRequest struct {
	Code        string
	State       string
	Transaction Transaction
}

// OAuthError is a bounded issuer refusal.
type OAuthError struct {
	Status      int
	OAuthCode   string
	Description string
}

func (e *OAuthError) Error() string { return e.OAuthCode }

// Exchange exchanges an authorization code for verified tokens.
func (c *Client) Exchange(ctx context.Context, request ExchangeRequest) (Tokens, Principal, error) {
	if request.Code == "" || request.Transaction.Verifier == "" {
		return Tokens{}, Principal{}, errorf(CodeMissingPKCE, "authorization code and PKCE verifier are required")
	}
	if request.Transaction.State == "" || !constantTimeEqual(request.State, request.Transaction.State) {
		return Tokens{}, Principal{}, errorf(CodeInvalidState, "callback state does not match")
	}
	if request.Transaction.ExpiresAt.IsZero() || c.config.Now().After(request.Transaction.ExpiresAt) {
		return Tokens{}, Principal{}, errorf(CodeInvalidState, "authorization transaction is expired")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {request.Code},
		"code_verifier": {request.Transaction.Verifier},
		"redirect_uri":  {request.Transaction.CallbackURI},
		"client_id":     {c.config.ClientID},
		"resource":      {c.config.Resource},
	}
	return c.requestTokens(ctx, form)
}

// Refresh rotates a refresh token and verifies the new access token.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (Tokens, Principal, error) {
	if refreshToken == "" {
		return Tokens{}, Principal{}, errorf(CodeInvalidToken, "refresh token is required")
	}
	return c.requestTokens(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.config.ClientID},
		"resource":      {c.config.Resource},
	})
}

// Revoke revokes a refresh token.
func (c *Client) Revoke(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	secret, confidential, err := c.resolveSecret(ctx)
	if err != nil {
		return err
	}
	return c.revokeWithSecret(ctx, refreshToken, secret, confidential)
}

func (c *Client) revokeWithSecret(ctx context.Context, refreshToken, secret string, confidential bool) error {
	response, err := c.postFormResolved(ctx, "/revoke", url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {c.config.ClientID},
	}, secret, confidential)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decodeOAuthError(response)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return nil
}

func (c *Client) requestTokens(ctx context.Context, form url.Values) (Tokens, Principal, error) {
	secret, confidential, err := c.resolveSecret(ctx)
	if err != nil {
		return Tokens{}, Principal{}, err
	}
	return c.requestTokensResolved(ctx, form, secret, confidential)
}

func (c *Client) requestTokensResolved(ctx context.Context, form url.Values, secret string, confidential bool) (Tokens, Principal, error) {
	response, err := c.postFormResolved(ctx, "/token", form, secret, confidential)
	if err != nil {
		return Tokens{}, Principal{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Tokens{}, Principal{}, decodeOAuthError(response)
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxTokenResponseBytes)).Decode(&body); err != nil {
		return Tokens{}, Principal{}, errorf(CodeInvalidResponse, "decode token response: %v", err)
	}
	if body.AccessToken == "" || body.RefreshToken == "" {
		return Tokens{}, Principal{}, errorf(CodeInvalidResponse, "token response is missing tokens")
	}
	principal, err := c.Verify(ctx, body.AccessToken)
	if err != nil {
		return Tokens{}, Principal{}, err
	}
	return Tokens{AccessToken: body.AccessToken, RefreshToken: body.RefreshToken}, principal, nil
}

func (c *Client) postForm(ctx context.Context, path string, form url.Values) (*http.Response, error) {
	secret, confidential, err := c.resolveSecret(ctx)
	if err != nil {
		return nil, err
	}
	return c.postFormResolved(ctx, path, form, secret, confidential)
}

func (c *Client) postFormResolved(ctx context.Context, path string, form url.Values, secret string, confidential bool) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.IssuerInternal+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errorf(CodeIssuerUnavailable, "build issuer request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if confidential {
		credentials := url.QueryEscape(c.config.ClientID) + ":" + url.QueryEscape(secret)
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	response, err := c.config.HTTPClient.Do(request)
	if err != nil {
		return nil, errorf(CodeIssuerUnavailable, "issuer request failed: %v", err)
	}
	return response, nil
}

func (c *Client) refreshWithSecret(ctx context.Context, refreshToken, secret string, confidential bool) (Tokens, Principal, error) {
	return c.requestTokensResolved(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.config.ClientID},
		"resource":      {c.config.Resource},
	}, secret, confidential)
}

func (c *Client) resolveSecret(ctx context.Context) (string, bool, error) {
	if c.config.ClientSecret == nil {
		return "", false, nil
	}
	secret, err := c.config.ClientSecret.Resolve(ctx)
	if err != nil || secret == "" {
		return "", true, errorf(CodeSecretUnavailable, "confidential client secret is unavailable")
	}
	return secret, true, nil
}

func decodeOAuthError(response *http.Response) error {
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxTokenResponseBytes)).Decode(&body); err != nil || body.Error == "" {
		return errorf(CodeInvalidResponse, "issuer returned HTTP %d", response.StatusCode)
	}
	return &OAuthError{
		Status:      response.StatusCode,
		OAuthCode:   bounded(body.Error, 128),
		Description: bounded(body.Description, 512),
	}
}

func bounded(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
