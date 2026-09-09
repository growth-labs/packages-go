package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/growth-labs/packages-go/testkit"
)

type jwtFixture struct {
	key       *ecdsa.PrivateKey
	kid       string
	issuer    string
	audience  string
	subject   string
	userID    string
	now       time.Time
	expiresAt time.Time
	notBefore time.Time
	issuedAt  time.Time
}

func newJWTFixture(t *testing.T, issuer string, now time.Time) jwtFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return jwtFixture{
		key:       key,
		kid:       "fixture-key",
		issuer:    issuer,
		audience:  "https://consumer.example.test",
		subject:   "user:01KP8KA31Z3AGRCC578R9HXW0H",
		userID:    "01KP8KA31Z3AGRCC578R9HXW0H",
		now:       now,
		expiresAt: now.Add(15 * time.Minute),
		notBefore: now.Add(-time.Second),
		issuedAt:  now,
	}
}

func (f jwtFixture) token(t *testing.T) string {
	t.Helper()
	header := map[string]any{"alg": "ES256", "kid": f.kid, "typ": "JWT"}
	payload := map[string]any{
		"iss":       f.issuer,
		"sub":       f.subject,
		"aud":       f.audience,
		"mode":      "access",
		"type":      "user",
		"scope":     "openid email profile",
		"client_id": "conformance-public-client",
		"roles":     []string{"member"},
		"iat":       f.issuedAt.Unix(),
		"nbf":       f.notBefore.Unix(),
		"exp":       f.expiresAt.Unix(),
		"properties": map[string]any{
			"userId":    f.userID,
			"email":     "member@example.test",
			"name":      "Conformance Member",
			"image":     "https://consumer.example.test/avatar.png",
			"isNewUser": false,
		},
	}
	encodedHeader := encodeJSON(t, header)
	encodedPayload := encodeJSON(t, payload)
	signingInput := encodedHeader + "." + encodedPayload
	digest := sha256Bytes([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, digest)
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func jwkFor(key *ecdsa.PrivateKey, kid string) map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"alg": "ES256",
		"use": "sig",
		"kid": kid,
		"x":   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
}

type jwksServer struct {
	server   *httptest.Server
	mu       sync.Mutex
	keys     []map[string]any
	status   int
	requests int
}

func newJWKSServer(t *testing.T) *jwksServer {
	t.Helper()
	fixtureServer := &jwksServer{status: http.StatusOK}
	fixtureServer.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fixtureServer.mu.Lock()
		defer fixtureServer.mu.Unlock()
		fixtureServer.requests++
		if request.URL.Path != "/.well-known/jwks.json" {
			http.NotFound(response, request)
			return
		}
		response.WriteHeader(fixtureServer.status)
		if fixtureServer.status == http.StatusOK {
			_ = json.NewEncoder(response).Encode(map[string]any{"keys": fixtureServer.keys})
		}
	}))
	t.Cleanup(fixtureServer.server.Close)
	return fixtureServer
}

func (s *jwksServer) set(keys []map[string]any, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = keys
	s.status = status
}

func (s *jwksServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func verifierClient(t *testing.T, issuer, internalIssuer string, now func() time.Time) *Client {
	t.Helper()
	client, err := New(Config{
		Issuer:         issuer,
		IssuerInternal: internalIssuer,
		ClientID:       "conformance-public-client",
		Resource:       "https://consumer.example.test",
		CallbackPath:   "/api/auth/callback",
		CookiePrefix:   "consumer",
		Providers:      []string{"google"},
		ClockSkew:      time.Second,
		JWKSCacheTTL:   10 * time.Minute,
		Now:            now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestVerifyMaterializesPrincipalFromValidES256Token(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newJWKSServer(t)
	fixture := newJWTFixture(t, "https://auth.fulcrum-labs.com", now)
	server.set([]map[string]any{jwkFor(fixture.key, fixture.kid)}, http.StatusOK)
	client := verifierClient(t, fixture.issuer, server.server.URL, func() time.Time { return now })

	principal, err := client.Verify(context.Background(), fixture.token(t))
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != fixture.subject || principal.UserID != fixture.userID || principal.Email != "member@example.test" || principal.Name != "Conformance Member" {
		t.Fatalf("principal = %#v", principal)
	}
	if strings.Join(principal.Roles, ",") != "member" || strings.Join(principal.Audiences, ",") != fixture.audience {
		t.Fatalf("principal roles/audiences = %#v", principal)
	}
}

func TestVerifyCanonicalIdentityFormatsAndExactBinding(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newJWKSServer(t)
	base := newJWTFixture(t, "https://auth.fulcrum-labs.com", now)
	server.set([]map[string]any{jwkFor(base.key, base.kid)}, http.StatusOK)
	client := verifierClient(t, base.issuer, server.server.URL, func() time.Time { return now })
	const uuid = "a340f47a-1e32-4a80-9125-15ef5db0151c"
	tests := []struct {
		name, subjectID, propertyID string
		valid                       bool
	}{
		{"canonical ULID", "01KP8KA31Z3AGRCC578R9HXW0H", "01KP8KA31Z3AGRCC578R9HXW0H", true},
		{"canonical UUID", uuid, uuid, true},
		{"different UUID property", uuid, "b340f47a-1e32-4a80-9125-15ef5db0151c", false},
		{"UUID property case mismatch", uuid, strings.ToUpper(uuid), false},
		{"uppercase UUID", strings.ToUpper(uuid), strings.ToUpper(uuid), true},
		{"mixed case UUID", "a340F47a-1E32-4a80-9125-15ef5db0151C", "a340F47a-1E32-4a80-9125-15ef5db0151C", true},
		{"UUID version 1 variant 8", "a340f47a-1e32-1a80-8125-15ef5db0151c", "a340f47a-1e32-1a80-8125-15ef5db0151c", true},
		{"UUID version 8 variant b", "a340f47a-1e32-8a80-b125-15ef5db0151c", "a340f47a-1e32-8a80-b125-15ef5db0151c", true},
		{"lowercase ULID", "01kp8ka31z3agrcc578r9hxw0h", "01kp8ka31z3agrcc578r9hxw0h", false},
		{"unhyphenated UUID", "a340f47a1e324a80912515ef5db0151c", "a340f47a1e324a80912515ef5db0151c", false},
		{"invalid UUID hex", "g340f47a-1e32-4a80-9125-15ef5db0151c", "g340f47a-1e32-4a80-9125-15ef5db0151c", false},
		{"invalid UUID version", "a340f47a-1e32-0a80-9125-15ef5db0151c", "a340f47a-1e32-0a80-9125-15ef5db0151c", false},
		{"reserved UUID version", "a340f47a-1e32-9a80-9125-15ef5db0151c", "a340f47a-1e32-9a80-9125-15ef5db0151c", false},
		{"invalid UUID variant", "a340f47a-1e32-4a80-7125-15ef5db0151c", "a340f47a-1e32-4a80-7125-15ef5db0151c", false},
		{"reserved UUID variant", "a340f47a-1e32-4a80-c125-15ef5db0151c", "a340f47a-1e32-4a80-c125-15ef5db0151c", false},
		{"invalid ULID first character", "81KP8KA31Z3AGRCC578R9HXW0H", "81KP8KA31Z3AGRCC578R9HXW0H", false},
		{"opaque string", "arbitrary-account", "arbitrary-account", false},
		{"trailing whitespace", uuid + " ", uuid + " ", false},
		{"trailing newline", uuid + "\n", uuid + "\n", false},
		{"embedded subject prefix", "user:" + uuid, "user:" + uuid, false},
		{"empty identity", "", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := base
			fixture.subject = "user:" + test.subjectID
			fixture.userID = test.propertyID
			principal, err := client.Verify(context.Background(), fixture.token(t))
			if !test.valid {
				if !IsCode(err, CodeInvalidToken) {
					t.Fatalf("malformed or inconsistent identity error = %v, want invalid_token", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonical identity rejected: %v", err)
			}
			if principal.Subject != "user:"+test.subjectID || principal.UserID != test.propertyID {
				t.Fatal("verification must preserve the canonical subject and user ID exactly")
			}
		})
	}
}

func TestVerifyAudienceIssuerAndExpiryGuardsAreFalsifiable(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newJWKSServer(t)
	base := newJWTFixture(t, "https://auth.fulcrum-labs.com", now)
	server.set([]map[string]any{jwkFor(base.key, base.kid)}, http.StatusOK)

	t.Run("audience", func(t *testing.T) {
		unsafe := base
		unsafe.audience = "https://other.example.test"
		testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
			client := verifierClient(t, base.issuer, server.server.URL, func() time.Time { return now })
			if mutation.GuardsDisabled() {
				client.config.Resource = unsafe.audience
			}
			_, err := client.Verify(context.Background(), unsafe.token(t))
			return err
		})
	})

	t.Run("issuer", func(t *testing.T) {
		unsafe := base
		unsafe.issuer = "https://wrong-issuer.example.test"
		testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
			client := verifierClient(t, base.issuer, server.server.URL, func() time.Time { return now })
			if mutation.GuardsDisabled() {
				client.config.Issuer = unsafe.issuer
			}
			_, err := client.Verify(context.Background(), unsafe.token(t))
			return err
		})
	})

	t.Run("expiry", func(t *testing.T) {
		unsafe := base
		unsafe.expiresAt = now.Add(-2 * time.Second)
		unsafe.issuedAt = now.Add(-10 * time.Minute)
		unsafe.notBefore = now.Add(-10 * time.Minute)
		testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
			clock := now
			if mutation.GuardsDisabled() {
				clock = now.Add(-3 * time.Second)
			}
			client := verifierClient(t, base.issuer, server.server.URL, func() time.Time { return clock })
			_, err := client.Verify(context.Background(), unsafe.token(t))
			return err
		})
	})
}

func TestVerifyRejectsFutureAndInconsistentClaimsAndTampering(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newJWKSServer(t)
	base := newJWTFixture(t, "https://auth.fulcrum-labs.com", now)
	server.set([]map[string]any{jwkFor(base.key, base.kid)}, http.StatusOK)
	client := verifierClient(t, base.issuer, server.server.URL, func() time.Time { return now })

	tests := map[string]struct {
		mutate func(*jwtFixture)
		code   Code
	}{
		"future nbf":       {mutate: func(f *jwtFixture) { f.notBefore = now.Add(2 * time.Second) }, code: CodeTokenNotYetValid},
		"future iat":       {mutate: func(f *jwtFixture) { f.issuedAt = now.Add(2 * time.Second) }, code: CodeTokenIssuedInFuture},
		"subject mismatch": {mutate: func(f *jwtFixture) { f.userID = "01KP8KA31Z3AGRCC578R9HXW0J" }, code: CodeInvalidToken},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			unsafe := base
			testCase.mutate(&unsafe)
			_, err := client.Verify(context.Background(), unsafe.token(t))
			if !IsCode(err, testCase.code) {
				t.Fatalf("error = %v, want %s", err, testCase.code)
			}
		})
	}

	token := base.token(t)
	parts := strings.Split(token, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signature[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	if _, err := client.Verify(context.Background(), strings.Join(parts, ".")); !IsCode(err, CodeInvalidSignature) {
		t.Fatalf("tampered signature error = %v", err)
	}
}

func TestVerifyJWKSCacheRefreshAndStaleFallback(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	clock := now
	server := newJWKSServer(t)
	first := newJWTFixture(t, "https://auth.fulcrum-labs.com", now)
	server.set([]map[string]any{jwkFor(first.key, first.kid)}, http.StatusOK)
	client := verifierClient(t, first.issuer, server.server.URL, func() time.Time { return clock })

	if _, err := client.Verify(context.Background(), first.token(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Verify(context.Background(), first.token(t)); err != nil {
		t.Fatal(err)
	}
	if server.count() != 1 {
		t.Fatalf("JWKS fetches = %d, want 1", server.count())
	}

	second := newJWTFixture(t, first.issuer, now)
	second.kid = "rotated-key"
	server.set([]map[string]any{jwkFor(first.key, first.kid), jwkFor(second.key, second.kid)}, http.StatusOK)
	if _, err := client.Verify(context.Background(), second.token(t)); err != nil {
		t.Fatal(err)
	}
	if server.count() != 2 {
		t.Fatalf("JWKS fetches after rotation = %d, want 2", server.count())
	}

	clock = now.Add(11 * time.Minute)
	server.set(nil, http.StatusServiceUnavailable)
	if _, err := client.Verify(context.Background(), first.token(t)); err != nil {
		t.Fatalf("stale cache verification = %v", err)
	}
	if server.count() != 3 {
		t.Fatalf("JWKS fetches after TTL = %d, want 3", server.count())
	}
}

func sha256Bytes(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}
