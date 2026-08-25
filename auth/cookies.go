package auth

import (
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// SetTransactionCookies persists a browser transaction.
func (c *Client) SetTransactionCookies(response http.ResponseWriter, transaction Transaction) {
	c.setCookie(response, c.cookieName("pkce"), transaction.Verifier, c.config.CallbackPath, c.config.TransactionMaxAge, "")
	c.setCookie(response, c.cookieName("callback"), transaction.CallbackURI, c.config.CallbackPath, c.config.TransactionMaxAge, "")
	c.setCookie(response, c.cookieName("expires"), strconv.FormatInt(transaction.ExpiresAt.Unix(), 10), c.config.CallbackPath, c.config.TransactionMaxAge, "")
	c.setCookie(response, c.cookieName("state"), transaction.State, "/", c.config.TransactionMaxAge, "")
	c.setCookie(response, c.cookieName("redirect"), transaction.RedirectPath, "/", c.config.TransactionMaxAge, "")
	c.setCookie(response, c.cookieName("provider"), transaction.Provider, "/", c.config.TransactionMaxAge, "")
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
	callbackURI := readCookie(request, c.cookieName("callback"))
	parsedCallback, err := url.Parse(callbackURI)
	if err != nil || parsedCallback.Host == "" || (parsedCallback.Scheme != "https" && parsedCallback.Scheme != "http") || parsedCallback.Path != c.config.CallbackPath || parsedCallback.RawQuery != "" || parsedCallback.Fragment != "" || parsedCallback.User != nil {
		return Transaction{}, errorf(CodeInvalidState, "callback transaction is missing or invalid")
	}
	expiresUnix, err := strconv.ParseInt(readCookie(request, c.cookieName("expires")), 10, 64)
	if err != nil {
		return Transaction{}, errorf(CodeInvalidState, "authorization transaction expiry is missing")
	}
	expiresAt := time.Unix(expiresUnix, 0)
	if c.config.Now().After(expiresAt) {
		return Transaction{}, errorf(CodeInvalidState, "authorization transaction is expired")
	}
	return Transaction{
		Verifier:     verifier,
		State:        state,
		RedirectPath: safeRedirect(readCookie(request, c.cookieName("redirect"))),
		Provider:     readCookie(request, c.cookieName("provider")),
		CallbackURI:  callbackURI,
		ExpiresAt:    expiresAt,
	}, nil
}

// SetSessionCookies writes access and refresh session cookies.
func (c *Client) SetSessionCookies(response http.ResponseWriter, tokens Tokens) {
	c.setCookie(response, c.cookieName("at"), tokens.AccessToken, "/", c.config.AccessTokenMaxAge, c.config.SessionCookieDomain)
	c.setCookie(response, c.cookieName("rt"), tokens.RefreshToken, "/", c.config.RefreshTokenMaxAge, c.config.SessionCookieDomain)
}

// SessionTokens reads access and refresh session cookies.
func (c *Client) SessionTokens(request *http.Request) (string, string) {
	return readCookie(request, c.cookieName("at")), readCookie(request, c.cookieName("rt"))
}

// ClearSessionCookies clears access and refresh session cookies.
func (c *Client) ClearSessionCookies(response http.ResponseWriter) {
	c.clearCookie(response, c.cookieName("at"), "/", c.config.SessionCookieDomain)
	c.clearCookie(response, c.cookieName("rt"), "/", c.config.SessionCookieDomain)
}

// ClearTransactionCookies clears all authorization transaction cookies.
func (c *Client) ClearTransactionCookies(response http.ResponseWriter) {
	c.clearCookie(response, c.cookieName("pkce"), c.config.CallbackPath, "")
	c.clearCookie(response, c.cookieName("callback"), c.config.CallbackPath, "")
	c.clearCookie(response, c.cookieName("expires"), c.config.CallbackPath, "")
	c.clearCookie(response, c.cookieName("state"), "/", "")
	c.clearCookie(response, c.cookieName("redirect"), "/", "")
	c.clearCookie(response, c.cookieName("provider"), "/", "")
}

func (c *Client) cookieName(suffix string) string { return c.config.CookiePrefix + "_" + suffix }

func (c *Client) setCookie(response http.ResponseWriter, name, value, path string, maxAge time.Duration, domain string) {
	http.SetCookie(response, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Domain:   domain,
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c *Client) clearCookie(response http.ResponseWriter, name, path, domain string) {
	http.SetCookie(response, &http.Cookie{
		Name:     name,
		Path:     path,
		Domain:   domain,
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
