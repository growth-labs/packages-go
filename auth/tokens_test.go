package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/growth-labs/packages-go/testkit"
)

type tokenFixtureServer struct {
	testing *testing.T
	server  *httptest.Server
	key     *ecdsa.PrivateKey
	now     time.Time

	mu                sync.Mutex
	requests          int
	lastForm          url.Values
	lastAuthorization string
	disablePKCE       bool
	refuseRefresh     bool
}

func newTokenFixtureServer(t *testing.T, now time.Time) *tokenFixtureServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &tokenFixtureServer{testing: t, key: key, now: now}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (s *tokenFixtureServer) serveHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/.well-known/jwks.json" {
		_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "token-key",
			"x": base64.RawURLEncoding.EncodeToString(s.key.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(s.key.Y.FillBytes(make([]byte, 32))),
		}}})
		return
	}
	if request.URL.Path != "/token" && request.URL.Path != "/revoke" {
		http.NotFound(response, request)
		return
	}
	_ = request.ParseForm()
	s.mu.Lock()
	s.requests++
	s.lastForm = request.PostForm
	s.lastAuthorization = request.Header.Get("Authorization")
	disablePKCE := s.disablePKCE
	refuseRefresh := s.refuseRefresh
	s.mu.Unlock()

	if request.URL.Path == "/revoke" {
		response.WriteHeader(http.StatusOK)
		return
	}
	if request.PostForm.Get("grant_type") == "authorization_code" && request.PostForm.Get("code_verifier") != "correct-verifier" && !disablePKCE {
		writeOAuthError(response, "invalid_grant", "PKCE verification failed")
		return
	}
	if request.PostForm.Get("grant_type") == "refresh_token" && refuseRefresh {
		writeOAuthError(response, "invalid_grant", "Refresh token has been used or expired")
		return
	}
	_ = json.NewEncoder(response).Encode(map[string]any{
		"access_token":  s.accessToken(),
		"refresh_token": "user:01KP8KA31Z3AGRCC578R9HXW0H:successor-token",
		"token_type":    "Bearer",
		"expires_in":    900,
	})
}

func writeOAuthError(response http.ResponseWriter, code, description string) {
	response.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(response).Encode(map[string]string{"error": code, "error_description": description})
}

func (s *tokenFixtureServer) accessToken() string {
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": "token-key", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss":   s.server.URL,
		"sub":   "user:01KP8KA31Z3AGRCC578R9HXW0H",
		"aud":   "https://consumer.example.test",
		"mode":  "access",
		"type":  "user",
		"roles": []string{"member"},
		"iat":   s.now.Unix(),
		"nbf":   s.now.Add(-time.Second).Unix(),
		"exp":   s.now.Add(15 * time.Minute).Unix(),
		"properties": map[string]any{
			"userId":    "01KP8KA31Z3AGRCC578R9HXW0H",
			"email":     "member@example.test",
			"name":      "Conformance Member",
			"image":     nil,
			"isNewUser": false,
		},
	})
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(signingInput))
	r, signatureS, _ := ecdsa.Sign(rand.Reader, s.key, digest[:])
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	signatureS.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (s *tokenFixtureServer) snapshot() (int, url.Values, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.lastForm, s.lastAuthorization
}

func tokenClient(t *testing.T, server *tokenFixtureServer, secret SecretSource) *Client {
	t.Helper()
	client, err := New(Config{
		Issuer:       server.server.URL,
		ClientID:     "conformance-public-client",
		ClientSecret: secret,
		Resource:     "https://consumer.example.test",
		CallbackPath: "/api/auth/callback",
		CookiePrefix: "consumer",
		Providers:    []string{"google"},
		Now:          func() time.Time { return server.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func validExchangeRequest() ExchangeRequest {
	return ExchangeRequest{
		Code:  "authorization-code",
		State: "stored-state",
		Transaction: Transaction{
			Verifier:    "correct-verifier",
			State:       "stored-state",
			CallbackURI: "https://consumer.example.test/api/auth/callback",
			ExpiresAt:   time.Unix(1_900_000_600, 0),
		},
	}
}

func TestExchangePostsPublicClientFormAndVerifiesTokens(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newTokenFixtureServer(t, now)
	client := tokenClient(t, server, nil)
	tokens, principal, err := client.Exchange(context.Background(), validExchangeRequest())
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken != "user:01KP8KA31Z3AGRCC578R9HXW0H:successor-token" || principal.UserID != "01KP8KA31Z3AGRCC578R9HXW0H" {
		t.Fatalf("exchange = %#v %#v", tokens, principal)
	}
	_, form, authorization := server.snapshot()
	want := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"authorization-code"},
		"code_verifier": {"correct-verifier"},
		"redirect_uri":  {"https://consumer.example.test/api/auth/callback"},
		"client_id":     {"conformance-public-client"},
		"resource":      {"https://consumer.example.test"},
	}
	if form.Encode() != want.Encode() || authorization != "" {
		t.Fatalf("form/auth = %q, %q; want %q, empty", form.Encode(), authorization, want.Encode())
	}
}

func TestExchangeStateAndPKCEGuardsAreFalsifiableAtWiringPoint(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newTokenFixtureServer(t, now)

	t.Run("state", func(t *testing.T) {
		testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
			request := validExchangeRequest()
			request.State = "wrong-state"
			if mutation.GuardsDisabled() {
				request.State = request.Transaction.State
			}
			_, _, err := tokenClient(t, server, nil).Exchange(context.Background(), request)
			return err
		})
	})

	t.Run("PKCE verifier", func(t *testing.T) {
		testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
			server.mu.Lock()
			server.disablePKCE = mutation.GuardsDisabled()
			server.mu.Unlock()
			request := validExchangeRequest()
			request.Transaction.Verifier = "wrong-verifier"
			_, _, err := tokenClient(t, server, nil).Exchange(context.Background(), request)
			return err
		})
	})
}

func TestSecretResolutionFailureIsFalsifiableAndPrecedesIssuerIO(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newTokenFixtureServer(t, now)
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		secret := SecretSourceFunc(func(context.Context) (string, error) {
			if mutation.GuardsDisabled() {
				return "resolved-secret", nil
			}
			return "", errors.New("binding rejected")
		})
		_, _, err := tokenClient(t, server, secret).Exchange(context.Background(), validExchangeRequest())
		return err
	})
	requests, _, _ := server.snapshot()
	if requests != 1 {
		t.Fatalf("issuer requests = %d, want only the guard-disabled proof request", requests)
	}
}

func TestConfidentialExchangeUsesPercentEncodedClientSecretBasic(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newTokenFixtureServer(t, now)
	client := tokenClient(t, server, SecretSourceFunc(func(context.Context) (string, error) {
		return "secret:with space", nil
	}))
	client.config.ClientID = "client id"
	if _, _, err := client.Exchange(context.Background(), validExchangeRequest()); err != nil {
		t.Fatal(err)
	}
	_, _, authorization := server.snapshot()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("client+id:secret%3Awith+space"))
	if authorization != want {
		t.Fatalf("authorization = %q, want %q", authorization, want)
	}
}

func TestRefreshAndRevokeUseResourceAndPreserveInvalidGrant(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newTokenFixtureServer(t, now)
	client := tokenClient(t, server, nil)

	tokens, principal, err := client.Refresh(context.Background(), "user:01KP8KA31Z3AGRCC578R9HXW0H:current-token")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.RefreshToken == "" || principal.Subject == "" {
		t.Fatalf("refresh = %#v %#v", tokens, principal)
	}
	_, form, _ := server.snapshot()
	if form.Get("grant_type") != "refresh_token" || form.Get("resource") != "https://consumer.example.test" || form.Get("client_id") != "conformance-public-client" {
		t.Fatalf("refresh form = %v", form)
	}

	server.mu.Lock()
	server.refuseRefresh = true
	server.mu.Unlock()
	_, _, err = client.Refresh(context.Background(), "user:01KP8KA31Z3AGRCC578R9HXW0H:used-token")
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.OAuthCode != "invalid_grant" || oauthErr.Description != "Refresh token has been used or expired" {
		t.Fatalf("refresh refusal = %#v (%v)", oauthErr, err)
	}

	if err := client.Revoke(context.Background(), "user:01KP8KA31Z3AGRCC578R9HXW0H:successor-token"); err != nil {
		t.Fatal(err)
	}
	_, form, _ = server.snapshot()
	if form.Get("token") == "" || form.Get("token_type_hint") != "refresh_token" || form.Get("client_id") != "conformance-public-client" {
		t.Fatalf("revoke form = %v", form)
	}
}

func TestExchangeRejectsExpiredTransactionBeforeIssuerIO(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newTokenFixtureServer(t, now)
	request := validExchangeRequest()
	request.Transaction.ExpiresAt = now.Add(-time.Second)
	_, _, err := tokenClient(t, server, nil).Exchange(context.Background(), request)
	if !IsCode(err, CodeInvalidState) {
		t.Fatalf("expired transaction error = %v", err)
	}
	requests, _, _ := server.snapshot()
	if requests != 0 {
		t.Fatalf("issuer requests = %d, want 0", requests)
	}
}

func TestOAuthErrorsNeverContainConfidentialSecret(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	server := newTokenFixtureServer(t, now)
	server.mu.Lock()
	server.disablePKCE = false
	server.mu.Unlock()
	client := tokenClient(t, server, SecretSourceFunc(func(context.Context) (string, error) {
		return "never-reflect-this-secret", nil
	}))
	request := validExchangeRequest()
	request.Transaction.Verifier = "wrong-verifier"
	_, _, err := client.Exchange(context.Background(), request)
	if err == nil || strings.Contains(err.Error(), "never-reflect-this-secret") {
		t.Fatalf("error = %v", err)
	}
}
