package auth

import (
	"net/http"
	"time"
)

// SetTransactionCookies persists a browser transaction.
func (c *Client) SetTransactionCookies(response http.ResponseWriter, transaction Transaction) {
	c.setCookie(response, c.cookieName("pkce"), transaction.Verifier, c.config.CallbackPath, c.config.TransactionMaxAge)
	c.setCookie(response, c.cookieName("state"), transaction.State, "/", c.config.TransactionMaxAge)
	c.setCookie(response, c.cookieName("redirect"), transaction.RedirectPath, "/", c.config.TransactionMaxAge)
	c.setCookie(response, c.cookieName("provider"), transaction.Provider, "/", c.config.TransactionMaxAge)
}

// TransactionFromRequest reads a browser transaction.
func (c *Client) TransactionFromRequest(request *http.Request) (Transaction, error) {
	verifier := readCookie(request, c.cookieName("pkce"))
	if verifier == "" {
		return Transaction{}, errorf(CodeMissingPKCE, "PKCE verifier cookie is missing")
	}
	state := readCookie(request, c.cookieName("state"))
	if state == "" {
		return Transaction{}, errorf(CodeInvalidState, "state cookie is missing")
	}
	callbackURI := (&urlForRequest{request: request}).callback(c.config.CallbackPath)
	return Transaction{
		Verifier:     verifier,
		State:        state,
		RedirectPath: safeRedirect(readCookie(request, c.cookieName("redirect"))),
		Provider:     readCookie(request, c.cookieName("provider")),
		CallbackURI:  callbackURI,
		ExpiresAt:    c.config.Now().Add(c.config.TransactionMaxAge),
	}, nil
}

// SetSessionCookies writes access and refresh session cookies.
func (c *Client) SetSessionCookies(response http.ResponseWriter, tokens Tokens) {
	c.setCookie(response, c.cookieName("at"), tokens.AccessToken, "/", c.config.AccessTokenMaxAge)
	c.setCookie(response, c.cookieName("rt"), tokens.RefreshToken, "/", c.config.RefreshTokenMaxAge)
}

// SessionTokens reads access and refresh session cookies.
func (c *Client) SessionTokens(request *http.Request) (string, string) {
	return readCookie(request, c.cookieName("at")), readCookie(request, c.cookieName("rt"))
}

// ClearSessionCookies clears access and refresh session cookies.
func (c *Client) ClearSessionCookies(response http.ResponseWriter) {
	c.clearCookie(response, c.cookieName("at"), "/")
	c.clearCookie(response, c.cookieName("rt"), "/")
}

// ClearTransactionCookies clears all authorization transaction cookies.
func (c *Client) ClearTransactionCookies(response http.ResponseWriter) {
	c.clearCookie(response, c.cookieName("pkce"), c.config.CallbackPath)
	c.clearCookie(response, c.cookieName("state"), "/")
	c.clearCookie(response, c.cookieName("redirect"), "/")
	c.clearCookie(response, c.cookieName("provider"), "/")
}

func (c *Client) cookieName(suffix string) string { return c.config.CookiePrefix + "_" + suffix }

func (c *Client) setCookie(response http.ResponseWriter, name, value, path string, maxAge time.Duration) {
	http.SetCookie(response, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Domain:   c.config.SessionCookieDomain,
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c *Client) clearCookie(response http.ResponseWriter, name, path string) {
	http.SetCookie(response, &http.Cookie{
		Name:     name,
		Path:     path,
		Domain:   c.config.SessionCookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func readCookie(request *http.Request, name string) string {
	cookie, err := request.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func safeRedirect(path string) string {
	if !validAbsolutePath(path) {
		return "/"
	}
	return path
}

type urlForRequest struct{ request *http.Request }

func (u *urlForRequest) callback(path string) string {
	scheme := "https"
	if u.request.TLS == nil && u.request.URL.Scheme == "http" {
		scheme = "http"
	}
	if u.request.URL.Scheme != "" {
		scheme = u.request.URL.Scheme
	}
	return scheme + "://" + u.request.Host + path
}
