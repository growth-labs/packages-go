package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is GitHub's REST API root.
const DefaultBaseURL = "https://api.github.com"

// DefaultCallBudget bounds outbound GitHub API calls per Client for its
// process lifetime. It exists so a runaway or looping caller cannot exhaust
// the installation's rate limit on its own; raise it explicitly for a
// caller that legitimately needs more.
const DefaultCallBudget = 500

// DefaultDedupeWindow is how long an identical read (same installation,
// repo, permission set) is rejected as a likely duplicate rather than
// re-executed. Zero disables dedupe.
const DefaultDedupeWindow = 5 * time.Minute

// DefaultRateLimitFloor is the minimum X-RateLimit-Remaining a preceding
// GitHub response may report before MintInstallationToken refuses further
// calls with CodeRateLimited rather than spending the installation's last
// headroom.
const DefaultRateLimitFloor = 50

// Config configures a github.Client.
type Config struct {
	// AppID is the GitHub App's numeric id (the JWT "iss" claim).
	AppID int64
	// PrivateKeyPEM is the App's private key, PEM-encoded (PKCS#1 or
	// PKCS#8). Loaded by the caller from a vault-delivered file; never a
	// GitHub Actions secret, never logged. The Client copies what it
	// needs (a parsed *rsa.PrivateKey) and does not retain the PEM bytes.
	PrivateKeyPEM []byte

	BaseURL      string
	HTTPClient   *http.Client
	Now          func() time.Time
	CallBudget   int
	DedupeWindow time.Duration
	RateLimitFloor int
}

// Client mints narrowly-scoped GitHub App installation tokens under a call
// budget. A Client is safe for concurrent use.
type Client struct {
	appID          int64
	key            *rsa.PrivateKey
	baseURL        string
	httpClient     *http.Client
	now            func() time.Time
	callBudget     int
	dedupeWindow   time.Duration
	rateLimitFloor int

	mu             sync.Mutex
	callsMade      int
	rateRemaining  int
	rateKnown      bool
	dedupe         map[string]time.Time
	tokens         map[string]Token
}

// New validates config, parses the App private key, and returns a Client.
// The key is parsed eagerly so a misconfigured deployment fails at startup,
// not on the first mint.
func New(config Config) (*Client, error) {
	if config.AppID <= 0 {
		return nil, errorf(CodeInvalidConfig, "app id is required")
	}
	if len(config.PrivateKeyPEM) == 0 {
		return nil, errorf(CodeInvalidConfig, "private key is required")
	}
	key, err := parsePrivateKey(config.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	callBudget := config.CallBudget
	if callBudget <= 0 {
		callBudget = DefaultCallBudget
	}
	dedupeWindow := config.DedupeWindow
	if config.DedupeWindow == 0 {
		dedupeWindow = DefaultDedupeWindow
	} else if config.DedupeWindow < 0 {
		dedupeWindow = 0
	}
	rateLimitFloor := config.RateLimitFloor
	if rateLimitFloor <= 0 {
		rateLimitFloor = DefaultRateLimitFloor
	}
	return &Client{
		appID:          config.AppID,
		key:            key,
		baseURL:        strings.TrimSuffix(baseURL, "/"),
		httpClient:     httpClient,
		now:            now,
		callBudget:     callBudget,
		dedupeWindow:   dedupeWindow,
		rateLimitFloor: rateLimitFloor,
		dedupe:         make(map[string]time.Time),
		tokens:         make(map[string]Token),
	}, nil
}

// MintInstallationToken returns a token scoped to exactly repo and
// permissions under installationID, minting fresh only when nothing valid
// is cached. Permissions must be non-empty and narrower than "every
// permission the installation holds" -- GitHub grants the full installation
// scope when permissions is omitted, which this package refuses to do
// silently.
func (c *Client) MintInstallationToken(ctx context.Context, installationID int64, repo string, permissions Permissions) (Token, error) {
	if strings.TrimSpace(repo) == "" {
		return Token{}, errorf(CodeInvalidConfig, "repo is required")
	}
	return c.mint(ctx, installationID, repo, []string{repositoryName(repo)}, permissions)
}

// MintInstallationTokenForOwner returns a token scoped to every repository
// the installation covers under owner (the "repositories" field is omitted
// from the mint request entirely, so GitHub grants exactly the
// installation's own configured access -- never broader than whatever the
// org admin already scoped that installation to). Use this only when an
// operation genuinely spans an unbounded or manifest-derived set of
// repositories under one owner (e.g. an estate-wide maintenance campaign);
// MintInstallationToken's single-repo scope is narrower and should be
// preferred whenever the caller touches exactly one repository.
func (c *Client) MintInstallationTokenForOwner(ctx context.Context, installationID int64, owner string, permissions Permissions) (Token, error) {
	if strings.TrimSpace(owner) == "" {
		return Token{}, errorf(CodeInvalidConfig, "owner is required")
	}
	return c.mint(ctx, installationID, "owner:"+owner, nil, permissions)
}

// mint is the shared budgeted-mint path: cacheLabel identifies the cache/
// dedupe entry (a repo full name for MintInstallationToken, "owner:<name>"
// for MintInstallationTokenForOwner); repos is the exact "repositories"
// request field, nil meaning omit it (installation-wide).
func (c *Client) mint(ctx context.Context, installationID int64, cacheLabel string, repos []string, permissions Permissions) (Token, error) {
	if installationID <= 0 {
		return Token{}, errorf(CodeInvalidConfig, "installation id is required")
	}
	if len(permissions) == 0 {
		return Token{}, errorf(CodeInvalidPermissions, "at least one permission is required -- an unscoped mint is refused")
	}

	cacheKey := fmt.Sprintf("%d|%s|%s", installationID, cacheLabel, permissions.key())

	c.mu.Lock()
	if cached, ok := c.tokens[cacheKey]; ok && !cached.Expired(c.now(), time.Minute) {
		c.mu.Unlock()
		return cached, nil
	}
	if c.dedupeWindow > 0 {
		if last, ok := c.dedupe[cacheKey]; ok && c.now().Sub(last) < c.dedupeWindow {
			c.mu.Unlock()
			return Token{}, errorf(CodeDuplicateRead, "identical mint for installation %d %s rejected within the %s dedupe window", installationID, cacheLabel, c.dedupeWindow)
		}
	}
	if c.callsMade >= c.callBudget {
		c.mu.Unlock()
		return Token{}, errorf(CodeCallBudgetExhausted, "call budget of %d exhausted for this client", c.callBudget)
	}
	if c.rateKnown && c.rateRemaining < c.rateLimitFloor {
		c.mu.Unlock()
		return Token{}, errorf(CodeRateLimited, "installation rate limit remaining (%d) below the configured floor (%d)", c.rateRemaining, c.rateLimitFloor)
	}
	armedAt := c.now()
	c.dedupe[cacheKey] = armedAt
	c.callsMade++
	c.mu.Unlock()

	token, err := c.mintFresh(ctx, installationID, cacheLabel, repos, permissions)
	if err != nil {
		// The dedupe entry armed above exists to reject a caller's own
		// repeated/looping duplicate request, not to punish a transient
		// transport failure for the rest of the window -- clearing it here
		// lets an immediate legitimate retry reach mintFresh again instead
		// of getting CodeDuplicateRead, which would mask the real
		// (transport-class) cause for up to DedupeWindow. Only clear the
		// entry this call itself armed: a concurrent call that legitimately
		// re-armed the same key after this one failed must not have its own
		// dedupe guard erased out from under it.
		c.mu.Lock()
		if current, ok := c.dedupe[cacheKey]; ok && current.Equal(armedAt) {
			delete(c.dedupe, cacheKey)
		}
		c.mu.Unlock()
		return Token{}, err
	}

	c.mu.Lock()
	c.tokens[cacheKey] = token
	c.mu.Unlock()
	return token, nil
}

func (c *Client) mintFresh(ctx context.Context, installationID int64, cacheLabel string, repos []string, permissions Permissions) (Token, error) {
	appJWT, err := signAppJWT(c.appID, c.key, c.now())
	if err != nil {
		return Token{}, err
	}

	body, err := json.Marshal(struct {
		Repositories []string          `json:"repositories,omitempty"`
		Permissions  map[string]string `json:"permissions"`
	}{
		Repositories: repos,
		Permissions:  permissions,
	})
	if err != nil {
		return Token{}, errorf(CodeInvalidConfig, "encode mint request: %v", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Token{}, errorf(CodeTransportUnavailable, "build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Token{}, errorf(CodeTransportUnavailable, "%v", err)
	}
	defer resp.Body.Close()

	c.recordRateLimit(resp.Header)

	switch resp.StatusCode {
	case http.StatusCreated:
		// falls through to decode below
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		return Token{}, errorf(CodeUnknownInstallation, "installation %d rejected the mint (status %d)", installationID, resp.StatusCode)
	case http.StatusForbidden, http.StatusTooManyRequests:
		return Token{}, errorf(CodeRateLimited, "GitHub refused the mint (status %d)", resp.StatusCode)
	default:
		return Token{}, errorf(CodeUnexpectedResponse, "unexpected status %d", resp.StatusCode)
	}

	var decoded struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Token{}, errorf(CodeTransportUnavailable, "read response: %v", err)
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return Token{}, errorf(CodeUnexpectedResponse, "decode response: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, decoded.ExpiresAt)
	if err != nil {
		return Token{}, errorf(CodeUnexpectedResponse, "parse expires_at: %v", err)
	}
	if decoded.Token == "" {
		return Token{}, errorf(CodeUnexpectedResponse, "response carried no token")
	}

	return Token{
		value:        decoded.Token,
		Repo:         cacheLabel,
		Permissions:  permissions.clone(),
		Installation: installationID,
		MintedAt:     c.now(),
		ExpiresAt:    expiresAt,
	}, nil
}

func (c *Client) recordRateLimit(header http.Header) {
	remaining := header.Get("X-RateLimit-Remaining")
	if remaining == "" {
		return
	}
	n, err := strconv.Atoi(remaining)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.rateRemaining = n
	c.rateKnown = true
	c.mu.Unlock()
}

// repositoryName strips an "owner/repo" prefix if present -- the
// installation access-token endpoint's "repositories" array takes bare repo
// names scoped to the installation's own owner, not "owner/repo".
func repositoryName(repo string) string {
	if idx := strings.LastIndex(repo, "/"); idx >= 0 {
		return repo[idx+1:]
	}
	return repo
}
