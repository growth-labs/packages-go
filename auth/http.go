package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

type principalContextKey struct{}

// Callback handles an OAuth authorization-code callback.
func (c *Client) Callback(response http.ResponseWriter, request *http.Request) {
	transaction, err := c.TransactionFromRequest(request)
	if err != nil {
		if IsCode(err, CodeInvalidState) {
			http.Error(response, "Invalid state parameter", http.StatusForbidden)
			return
		}
		http.Error(response, "Missing PKCE verifier", http.StatusBadRequest)
		return
	}
	if request.URL.Query().Get("error") != "" {
		c.redirectLoginFailure(response, request)
		return
	}
	code := request.URL.Query().Get("code")
	if code == "" {
		c.redirectLoginFailure(response, request)
		return
	}
	tokens, _, err := c.Exchange(request.Context(), ExchangeRequest{
		Code:        code,
		State:       request.URL.Query().Get("state"),
		Transaction: transaction,
	})
	if err != nil {
		if IsCode(err, CodeInvalidState) {
			http.Error(response, "Invalid state parameter", http.StatusForbidden)
			return
		}
		if IsCode(err, CodeSecretUnavailable) {
			writeServiceUnavailable(response, request)
			return
		}
		c.redirectLoginFailure(response, request)
		return
	}
	c.SetSessionCookies(response, tokens)
	c.ClearTransactionCookies(response)
	http.Redirect(response, request, safeRedirect(transaction.RedirectPath), http.StatusFound)
}

// Logout clears the local session and revokes its refresh token.
func (c *Client) Logout(response http.ResponseWriter, request *http.Request) {
	_, refreshToken := c.SessionTokens(request)
	c.ClearSessionCookies(response)
	c.ClearTransactionCookies(response)
	if refreshToken != "" {
		secret, confidential, err := c.resolveSecret(request.Context())
		if err != nil {
			writeServiceUnavailable(response, request)
			return
		}
		_ = c.revokeWithSecret(request.Context(), refreshToken, secret, confidential)
	}
	http.Redirect(response, request, safeRedirect(c.config.LogoutRedirect), http.StatusFound)
}

// Middleware resolves an optional principal and gates configured paths.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		accessToken, refreshToken := c.SessionTokens(request)
		var principal Principal
		authenticated := false
		var secret string
		confidential := false

		if refreshToken != "" && c.config.ClientSecret != nil {
			var err error
			secret, confidential, err = c.resolveSecret(request.Context())
			if err != nil {
				writeServiceUnavailable(response, request)
				return
			}
		}
		if accessToken != "" {
			verified, err := c.Verify(request.Context(), accessToken)
			if err == nil {
				principal = verified
				authenticated = true
			}
		}
		if !authenticated && refreshToken != "" {
			tokens, refreshed, err := c.refreshWithSecret(request.Context(), refreshToken, secret, confidential)
			if err == nil {
				c.SetSessionCookies(response, tokens)
				principal = refreshed
				authenticated = true
			} else if IsCode(err, CodeSecretUnavailable) {
				writeServiceUnavailable(response, request)
				return
			}
		}
		if !authenticated && c.isGated(request.URL.Path) {
			query := url.Values{"redirect": {request.URL.Path}}
			http.Redirect(response, request, c.config.LoginPath+"?"+query.Encode(), http.StatusFound)
			return
		}
		if authenticated {
			request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal))
		}
		next.ServeHTTP(response, request)
	})
}

// PrincipalFromContext reads a verified principal from a request context.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

func (c *Client) isGated(path string) bool {
	for _, pattern := range c.config.GatedPaths {
		if strings.HasSuffix(pattern, "/*") {
			if strings.HasPrefix(path, strings.TrimSuffix(pattern, "*")) {
				return true
			}
		} else if path == pattern {
			return true
		}
	}
	return false
}

func (c *Client) redirectLoginFailure(response http.ResponseWriter, request *http.Request) {
	query := url.Values{"error": {"auth_failed"}}
	http.Redirect(response, request, c.config.LoginPath+"?"+query.Encode(), http.StatusFound)
}

func writeServiceUnavailable(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("Pragma", "no-cache")
	response.Header().Set("Expires", "0")
	if acceptsJSON(request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusServiceUnavailable)
		_, _ = response.Write([]byte(`{"error":"auth_service_unavailable"}`))
		return
	}
	http.Error(response, "Service unavailable", http.StatusServiceUnavailable)
}

func acceptsJSON(request *http.Request) bool {
	for _, part := range strings.Split(request.Header.Get("Accept"), ",") {
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]), "application/json") {
			return true
		}
	}
	return false
}
