package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(Config{
		Issuer:             "https://auth.fulcrum-labs.com",
		ClientID:           "conformance-public-client",
		Resource:           "https://consumer.example.test",
		CallbackPath:       "/api/auth/callback",
		CookiePrefix:       "consumer",
		Providers:          []string{"google", "password", "email-code"},
		AccessTokenMaxAge:  15 * time.Minute,
		RefreshTokenMaxAge: 30 * 24 * time.Hour,
		TransactionMaxAge:  10 * time.Minute,
		Now:                func() time.Time { return time.Unix(1_900_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestAuthorizeBuildsPKCES256ResourceRequest(t *testing.T) {
	client := newClient(t)
	origin, _ := url.Parse("https://consumer.example.test")
	authorizationURL, transaction, err := client.Authorize(origin, "google", "/projects/active?view=mine")
	if err != nil {
		t.Fatal(err)
	}

	if authorizationURL.Scheme != "https" || authorizationURL.Host != "auth.fulcrum-labs.com" || authorizationURL.Path != "/authorize" {
		t.Fatalf("authorization URL = %s", authorizationURL)
	}
	query := authorizationURL.Query()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             "conformance-public-client",
		"redirect_uri":          "https://consumer.example.test/api/auth/callback",
		"scope":                 "openid email profile",
		"state":                 transaction.State,
		"code_challenge":        transaction.Challenge,
		"code_challenge_method": "S256",
		"provider":              "google",
		"resource":              "https://consumer.example.test",
	}
	for name, expected := range want {
		if got := query.Get(name); got != expected {
			t.Errorf("query %s = %q, want %q", name, got, expected)
		}
	}
	if len(query) != len(want) {
		t.Fatalf("query = %v, want exactly %d parameters", query, len(want))
	}
	if transaction.RedirectPath != "/projects/active?view=mine" || transaction.Provider != "google" {
		t.Fatalf("transaction = %#v", transaction)
	}
	if transaction.CallbackURI != "https://consumer.example.test/api/auth/callback" {
		t.Fatalf("callback URI = %q", transaction.CallbackURI)
	}
	if transaction.ExpiresAt.Unix() != 1_900_000_600 {
		t.Fatalf("expiry = %s", transaction.ExpiresAt)
	}
	if len(transaction.Verifier) < 43 || strings.Contains(transaction.Verifier, "=") {
		t.Fatalf("verifier is not unpadded base64url: %q", transaction.Verifier)
	}
	digest := sha256.Sum256([]byte(transaction.Verifier))
	if expected := base64.RawURLEncoding.EncodeToString(digest[:]); transaction.Challenge != expected {
		t.Fatalf("challenge = %q, want %q", transaction.Challenge, expected)
	}
}

func TestAuthorizeAliasesEmailCodeAndRejectsUnknownProvider(t *testing.T) {
	client := newClient(t)
	origin, _ := url.Parse("https://consumer.example.test")
	authorizationURL, transaction, err := client.Authorize(origin, "email-code", "/")
	if err != nil {
		t.Fatal(err)
	}
	if got := authorizationURL.Query().Get("provider"); got != "code" {
		t.Fatalf("provider = %q, want code", got)
	}
	if transaction.Provider != "email-code" {
		t.Fatalf("transaction provider = %q", transaction.Provider)
	}
	if _, _, err := client.Authorize(origin, "github", "/"); !IsCode(err, CodeInvalidProvider) {
		t.Fatalf("unknown provider error = %v", err)
	}
}

func TestAuthorizeCollapsesUnsafeRedirectPaths(t *testing.T) {
	client := newClient(t)
	origin, _ := url.Parse("https://consumer.example.test")
	for _, unsafe := range []string{
		"https://attacker.example/steal",
		"//attacker.example/steal",
		`/\\attacker.example/steal`,
		"/%5c%5cattacker.example/steal",
		"/%2f%2fattacker.example/steal",
		"javascript:alert(1)",
		"relative",
	} {
		_, transaction, err := client.Authorize(origin, "google", unsafe)
		if err != nil {
			t.Fatal(err)
		}
		if transaction.RedirectPath != "/" {
			t.Errorf("redirect %q became %q, want /", unsafe, transaction.RedirectPath)
		}
	}
}

func TestCookieHelpersUseCompatibleNamesAndSecureAttributes(t *testing.T) {
	client := newClient(t)
	origin, _ := url.Parse("https://consumer.example.test")
	_, transaction, err := client.Authorize(origin, "password", "/account")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	client.SetTransactionCookies(recorder, transaction)
	client.SetSessionCookies(recorder, Tokens{AccessToken: "access-token", RefreshToken: "refresh-token"})
	cookies := recorder.Result().Cookies()
	byName := make(map[string]*http.Cookie, len(cookies))
	for _, cookie := range cookies {
		byName[cookie.Name] = cookie
		if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie %s attributes = HttpOnly:%v Secure:%v SameSite:%v", cookie.Name, cookie.HttpOnly, cookie.Secure, cookie.SameSite)
		}
	}
	for _, name := range []string{"consumer_pkce", "consumer_state", "consumer_redirect", "consumer_provider", "consumer_callback", "consumer_expires", "consumer_at", "consumer_rt"} {
		if byName[name] == nil {
			t.Errorf("missing cookie %s", name)
		}
	}
	if byName["consumer_pkce"].Path != "/api/auth/callback" || byName["consumer_state"].Path != "/" {
		t.Fatalf("transaction paths: pkce=%q state=%q", byName["consumer_pkce"].Path, byName["consumer_state"].Path)
	}
	if byName["consumer_at"].MaxAge != 900 || byName["consumer_rt"].MaxAge != 2_592_000 {
		t.Fatalf("session max ages: at=%d rt=%d", byName["consumer_at"].MaxAge, byName["consumer_rt"].MaxAge)
	}

	request := httptest.NewRequest(http.MethodGet, "https://consumer.example.test/api/auth/callback", nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	readTransaction, err := client.TransactionFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if readTransaction.Verifier != transaction.Verifier || readTransaction.State != transaction.State || readTransaction.RedirectPath != "/account" || readTransaction.Provider != "password" || readTransaction.CallbackURI != transaction.CallbackURI || !readTransaction.ExpiresAt.Equal(transaction.ExpiresAt) {
		t.Fatalf("read transaction = %#v", readTransaction)
	}
	access, refresh := client.SessionTokens(request)
	if access != "access-token" || refresh != "refresh-token" {
		t.Fatalf("session tokens = %q, %q", access, refresh)
	}
}

func TestTransactionCookiesAreHostOnlyAndPreserveHTTPCallbackAndExpiry(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	client, err := New(Config{
		Issuer:              "https://auth.fulcrum-labs.com",
		ClientID:            "conformance-public-client",
		Resource:            "http://localhost:4321",
		CallbackPath:        "/api/auth/callback",
		CookiePrefix:        "consumer",
		SessionCookieDomain: ".example.test",
		Providers:           []string{"google"},
		Now:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse("http://localhost:4321")
	_, transaction, err := client.Authorize(origin, "google", "/account")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	client.SetTransactionCookies(recorder, transaction)
	client.SetSessionCookies(recorder, Tokens{AccessToken: "access", RefreshToken: "refresh"})
	cookies := recorder.Result().Cookies()
	for _, cookie := range cookies {
		if strings.HasSuffix(cookie.Name, "_at") || strings.HasSuffix(cookie.Name, "_rt") {
			if cookie.Domain != "example.test" {
				t.Errorf("session cookie %s domain = %q", cookie.Name, cookie.Domain)
			}
		} else if cookie.Domain != "" {
			t.Errorf("transaction cookie %s domain = %q, want host-only", cookie.Name, cookie.Domain)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/api/auth/callback", nil)
	request.Host = "localhost:4321"
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	readTransaction, err := client.TransactionFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if readTransaction.CallbackURI != "http://localhost:4321/api/auth/callback" || !readTransaction.ExpiresAt.Equal(transaction.ExpiresAt) {
		t.Fatalf("reconstructed transaction = %#v", readTransaction)
	}

	now = transaction.ExpiresAt.Add(time.Second)
	if _, err := client.TransactionFromRequest(request); !IsCode(err, CodeInvalidState) {
		t.Fatalf("expired browser transaction error = %v", err)
	}
}

func TestNewUsesBoundedTransportAndRejectsUnsafeBoundaryConfig(t *testing.T) {
	client := newClient(t)
	if client.config.HTTPClient.Timeout <= 0 {
		t.Fatal("default issuer HTTP client must have a total timeout")
	}
	base := Config{
		Issuer:       "https://auth.fulcrum-labs.com",
		ClientID:     "client",
		Resource:     "https://consumer.example.test",
		CallbackPath: "/api/auth/callback",
		CookiePrefix: "consumer",
		Providers:    []string{"google"},
	}
	for name, mutate := range map[string]func(*Config){
		"issuer userinfo": func(config *Config) { config.Issuer = "https://user@auth.fulcrum-labs.com" },
		"resource":        func(config *Config) { config.Resource = "relative-resource" },
		"cookie prefix":   func(config *Config) { config.CookiePrefix = "bad prefix" },
		"login path":      func(config *Config) { config.LoginPath = "//attacker.example" },
		"logout path":     func(config *Config) { config.LogoutPath = "relative" },
		"gated path":      func(config *Config) { config.GatedPaths = []string{"/safe/*", `\\attacker.example`} },
		"cookie domain":   func(config *Config) { config.SessionCookieDomain = "bad domain" },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := New(config); !IsCode(err, CodeInvalidConfig) {
				t.Fatalf("invalid config error = %v", err)
			}
		})
	}
}
