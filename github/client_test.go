package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

type fakeMintServer struct {
	*httptest.Server
	calls           int32
	lastPermissions map[string]string
	lastAuth        string
	rateRemaining   int
	statusOverride  int
	tokenValue      string
	expiresIn       time.Duration
}

func newFakeMintServer(t *testing.T) *fakeMintServer {
	t.Helper()
	f := &fakeMintServer{rateRemaining: 4999, tokenValue: "ghs_faketoken", expiresIn: time.Hour}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.calls, 1)
		f.lastAuth = r.Header.Get("Authorization")
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", f.rateRemaining))
		if f.statusOverride != 0 {
			w.WriteHeader(f.statusOverride)
			return
		}
		var body struct {
			Repositories []string          `json:"repositories"`
			Permissions  map[string]string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		f.lastPermissions = body.Permissions
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      f.tokenValue,
			"expires_at": time.Now().Add(f.expiresIn).UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(f.Server.Close)
	return f
}

func newTestClient(t *testing.T, server *fakeMintServer, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		AppID:         12345,
		PrivateKeyPEM: testKeyPEM(t),
		BaseURL:       server.URL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestMintInstallationTokenSendsExactlyTheRequestedPermissionsAndAnAppJWT(t *testing.T) {
	server := newFakeMintServer(t)
	client := newTestClient(t, server, nil)

	token, err := client.MintInstallationToken(context.Background(), 999, "fulcrum-labs/platform-foundations", Permissions{
		"contents": "write",
	})
	if err != nil {
		t.Fatalf("MintInstallationToken: %v", err)
	}
	if token.Value() != "ghs_faketoken" {
		t.Fatalf("token value = %q, want the fake server's token", token.Value())
	}
	if got, want := server.lastPermissions, map[string]string{"contents": "write"}; got["contents"] != want["contents"] || len(got) != len(want) {
		t.Fatalf("server saw permissions %v, want %v -- a caller must never receive more than it asked for", got, want)
	}
	if !strings.HasPrefix(server.lastAuth, "Bearer ") {
		t.Fatalf("Authorization header = %q, want a Bearer App JWT", server.lastAuth)
	}
}

func TestMintInstallationTokenRefusesAnEmptyPermissionSet(t *testing.T) {
	server := newFakeMintServer(t)
	client := newTestClient(t, server, nil)

	_, err := client.MintInstallationToken(context.Background(), 999, "platform-foundations", nil)
	if !IsCode(err, CodeInvalidPermissions) {
		t.Fatalf("err = %v, want CodeInvalidPermissions -- an unscoped mint must never silently fall back to the installation's full grant", err)
	}
	if atomic.LoadInt32(&server.calls) != 0 {
		t.Fatalf("server saw %d calls, want 0 -- refusing an unscoped request must happen before any network call", server.calls)
	}
}

func TestMintInstallationTokenReusesACachedTokenInsteadOfMintingAgain(t *testing.T) {
	server := newFakeMintServer(t)
	client := newTestClient(t, server, nil)
	perms := Permissions{"contents": "write"}

	if _, err := client.MintInstallationToken(context.Background(), 1, "repo-a", perms); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	if _, err := client.MintInstallationToken(context.Background(), 1, "repo-a", perms); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	if calls := atomic.LoadInt32(&server.calls); calls != 1 {
		t.Fatalf("server saw %d calls, want 1 -- a live cached token must never be re-minted", calls)
	}
}

func TestMintInstallationTokenRejectsAnIdenticalMintWithinTheDedupeWindowAfterCacheEviction(t *testing.T) {
	server := newFakeMintServer(t)
	callNow := time.Now()
	client := newTestClient(t, server, func(c *Config) {
		c.Now = func() time.Time { return callNow }
		c.DedupeWindow = time.Hour
	})
	perms := Permissions{"contents": "write"}

	if _, err := client.MintInstallationToken(context.Background(), 1, "repo-a", perms); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	// Force the cache to miss (simulate an expired token) while staying inside
	// the dedupe window, by clearing the cache directly -- the dedupe guard
	// must still catch the identical re-request even though the token cache
	// itself no longer has an answer.
	client.mu.Lock()
	client.tokens = make(map[string]Token)
	client.mu.Unlock()

	_, err := client.MintInstallationToken(context.Background(), 1, "repo-a", perms)
	if !IsCode(err, CodeDuplicateRead) {
		t.Fatalf("err = %v, want CodeDuplicateRead", err)
	}
	if calls := atomic.LoadInt32(&server.calls); calls != 1 {
		t.Fatalf("server saw %d calls, want 1 -- the dedupe guard must block the second network call entirely", calls)
	}
}

func TestMintInstallationTokenStopsAtItsCallBudget(t *testing.T) {
	server := newFakeMintServer(t)
	client := newTestClient(t, server, func(c *Config) {
		c.CallBudget = 1
		c.DedupeWindow = -1 // disabled, so budget alone is under test
	})

	if _, err := client.MintInstallationToken(context.Background(), 1, "repo-a", Permissions{"contents": "write"}); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	_, err := client.MintInstallationToken(context.Background(), 2, "repo-b", Permissions{"contents": "write"})
	if !IsCode(err, CodeCallBudgetExhausted) {
		t.Fatalf("err = %v, want CodeCallBudgetExhausted", err)
	}
}

func TestMintInstallationTokenRefusesWhenTheLastObservedRateLimitIsBelowTheFloor(t *testing.T) {
	server := newFakeMintServer(t)
	server.rateRemaining = 10
	client := newTestClient(t, server, func(c *Config) {
		c.RateLimitFloor = 50
		c.DedupeWindow = -1
	})

	// First call succeeds and records the low X-RateLimit-Remaining header.
	if _, err := client.MintInstallationToken(context.Background(), 1, "repo-a", Permissions{"contents": "write"}); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	_, err := client.MintInstallationToken(context.Background(), 2, "repo-b", Permissions{"contents": "write"})
	if !IsCode(err, CodeRateLimited) {
		t.Fatalf("err = %v, want CodeRateLimited once headroom is below the floor", err)
	}
	if calls := atomic.LoadInt32(&server.calls); calls != 1 {
		t.Fatalf("server saw %d calls, want 1 -- the preflight must refuse before spending another call", calls)
	}
}

func TestMintInstallationTokenMapsA404ToUnknownInstallation(t *testing.T) {
	server := newFakeMintServer(t)
	server.statusOverride = http.StatusNotFound
	client := newTestClient(t, server, nil)

	_, err := client.MintInstallationToken(context.Background(), 1, "repo-a", Permissions{"contents": "write"})
	if !IsCode(err, CodeUnknownInstallation) {
		t.Fatalf("err = %v, want CodeUnknownInstallation", err)
	}
}

func TestCodeClassDistinguishesConfigurationFromTransportFailures(t *testing.T) {
	configCodes := []Code{CodeInvalidConfig, CodeInvalidPrivateKey, CodeUnknownInstallation, CodeInvalidPermissions}
	transportCodes := []Code{CodeTransportUnavailable, CodeRateLimited, CodeCallBudgetExhausted, CodeDuplicateRead, CodeUnexpectedResponse}
	for _, c := range configCodes {
		if c.Class() != "configuration" {
			t.Fatalf("%s.Class() = %q, want configuration", c, c.Class())
		}
	}
	for _, c := range transportCodes {
		if c.Class() != "transport" {
			t.Fatalf("%s.Class() = %q, want transport", c, c.Class())
		}
	}
}

func TestTokenNeverReflectsItsValueThroughFmt(t *testing.T) {
	token := Token{value: "ghs_supersecret"}
	if s := fmt.Sprintf("%v", token); strings.Contains(s, "ghs_supersecret") {
		t.Fatalf("%%v of a Token leaked its value: %q", s)
	}
	if s := fmt.Sprintf("%#v", token); strings.Contains(s, "ghs_supersecret") {
		t.Fatalf("%%#v of a Token leaked its value: %q", s)
	}
	if token.Value() != "ghs_supersecret" {
		t.Fatalf("Value() = %q, want the underlying token still reachable explicitly", token.Value())
	}
}

func TestNewRejectsAMalformedPrivateKey(t *testing.T) {
	_, err := New(Config{AppID: 1, PrivateKeyPEM: []byte("not a key")})
	if !IsCode(err, CodeInvalidPrivateKey) {
		t.Fatalf("err = %v, want CodeInvalidPrivateKey", err)
	}
}

func TestNewRequiresAnAppID(t *testing.T) {
	_, err := New(Config{PrivateKeyPEM: testKeyPEM(t)})
	if !IsCode(err, CodeInvalidConfig) {
		t.Fatalf("err = %v, want CodeInvalidConfig", err)
	}
}
