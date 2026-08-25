package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SecretSource resolves a confidential OAuth client secret at request time.
type SecretSource interface {
	Resolve(context.Context) (string, error)
}

// SecretSourceFunc adapts a function to SecretSource.
type SecretSourceFunc func(context.Context) (string, error)

func (f SecretSourceFunc) Resolve(ctx context.Context) (string, error) { return f(ctx) }

// Config configures an OpenAuth consumer.
type Config struct {
	Issuer              string
	IssuerInternal      string
	ClientID            string
	ClientSecret        SecretSource
	Resource            string
	CallbackPath        string
	CookiePrefix        string
	SessionCookieDomain string
	Providers           []string
	GatedPaths          []string
	LoginPath           string
	LogoutRedirect      string
	AccessTokenMaxAge   time.Duration
	RefreshTokenMaxAge  time.Duration
	TransactionMaxAge   time.Duration
	ClockSkew           time.Duration
	JWKSCacheTTL        time.Duration
	HTTPClient          *http.Client
	Now                 func() time.Time
}

// Client is an immutable OpenAuth consumer.
type Client struct {
	config Config
	jwks   jwksCache
}

// New validates config and creates a client.
func New(config Config) (*Client, error) {
	issuer, err := normalizeIssuer(config.Issuer)
	if err != nil {
		return nil, errorf(CodeInvalidConfig, "issuer: %v", err)
	}
	config.Issuer = issuer
	if config.IssuerInternal == "" {
		config.IssuerInternal = issuer
	} else if config.IssuerInternal, err = normalizeIssuer(config.IssuerInternal); err != nil {
		return nil, errorf(CodeInvalidConfig, "internal issuer: %v", err)
	}
	if strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.Resource) == "" {
		return nil, errorf(CodeInvalidConfig, "client ID and resource are required")
	}
	if config.CallbackPath == "" {
		config.CallbackPath = "/api/auth/callback"
	}
	if !validAbsolutePath(config.CallbackPath) {
		return nil, errorf(CodeInvalidConfig, "callback path must be an absolute local path")
	}
	if strings.TrimSpace(config.CookiePrefix) == "" {
		return nil, errorf(CodeInvalidConfig, "cookie prefix is required")
	}
	if len(config.Providers) == 0 {
		return nil, errorf(CodeInvalidConfig, "at least one provider is required")
	}
	if config.AccessTokenMaxAge <= 0 {
		config.AccessTokenMaxAge = 15 * time.Minute
	}
	if config.RefreshTokenMaxAge <= 0 {
		config.RefreshTokenMaxAge = 30 * 24 * time.Hour
	}
	if config.TransactionMaxAge <= 0 {
		config.TransactionMaxAge = 10 * time.Minute
	}
	if config.ClockSkew <= 0 {
		config.ClockSkew = time.Minute
	}
	if config.JWKSCacheTTL <= 0 {
		config.JWKSCacheTTL = 10 * time.Minute
	}
	if config.LoginPath == "" {
		config.LoginPath = "/login"
	}
	if config.LogoutRedirect == "" {
		config.LogoutRedirect = "/"
	}
	if config.HTTPClient == nil {
		config.HTTPClient = http.DefaultClient
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	config.Providers = append([]string(nil), config.Providers...)
	config.GatedPaths = append([]string(nil), config.GatedPaths...)
	return &Client{config: config}, nil
}

func normalizeIssuer(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return "", errorf(CodeInvalidConfig, "must be an absolute HTTP URL")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errorf(CodeInvalidConfig, "must not contain a path, query, or fragment")
	}
	parsed.Path = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func validAbsolutePath(path string) bool {
	parsed, err := url.Parse(path)
	return err == nil && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && !parsed.IsAbs() && parsed.Host == ""
}
