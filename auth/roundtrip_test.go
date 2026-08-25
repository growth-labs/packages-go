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
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type refreshRecord struct {
	usedAt    time.Time
	successor string
}

type roundTripIssuer struct {
	t      *testing.T
	server *httptest.Server
	key    *ecdsa.PrivateKey

	mu            sync.Mutex
	now           time.Time
	codeChallenge string
	codeResource  string
	refresh       map[string]*refreshRecord
	nextRefresh   int
	revoked       []string
}

func newRoundTripIssuer(t *testing.T, now time.Time) *roundTripIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &roundTripIssuer{t: t, key: key, now: now, refresh: make(map[string]*refreshRecord)}
	issuer.server = httptest.NewServer(http.HandlerFunc(issuer.serveHTTP))
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (i *roundTripIssuer) currentTime() time.Time {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.now
}

func (i *roundTripIssuer) setTime(now time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.now = now
}

func (i *roundTripIssuer) serveHTTP(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/.well-known/jwks.json":
		i.writeJWKS(response)
	case "/authorize":
		i.authorize(response, request)
	case "/token":
		i.token(response, request)
	case "/revoke":
		i.revoke(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (i *roundTripIssuer) writeJWKS(response http.ResponseWriter) {
	_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "roundtrip-key",
		"x": base64.RawURLEncoding.EncodeToString(i.key.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(i.key.Y.FillBytes(make([]byte, 32))),
	}}})
}

func (i *roundTripIssuer) authorize(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	if query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || query.Get("resource") == "" || query.Get("state") == "" {
		http.Error(response, "invalid authorization request", http.StatusBadRequest)
		return
	}
	i.mu.Lock()
	i.codeChallenge = query.Get("code_challenge")
	i.codeResource = query.Get("resource")
	i.mu.Unlock()
	callback, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		http.Error(response, "invalid callback", http.StatusBadRequest)
		return
	}
	callbackQuery := callback.Query()
	callbackQuery.Set("code", "roundtrip-code")
	callbackQuery.Set("state", query.Get("state"))
	callback.RawQuery = callbackQuery.Encode()
	http.Redirect(response, request, callback.String(), http.StatusFound)
}

func (i *roundTripIssuer) token(response http.ResponseWriter, request *http.Request) {
	_ = request.ParseForm()
	switch request.PostForm.Get("grant_type") {
	case "authorization_code":
		digest := sha256.Sum256([]byte(request.PostForm.Get("code_verifier")))
		challenge := base64.RawURLEncoding.EncodeToString(digest[:])
		i.mu.Lock()
		valid := request.PostForm.Get("code") == "roundtrip-code" && challenge == i.codeChallenge && request.PostForm.Get("resource") == i.codeResource
		i.mu.Unlock()
		if !valid {
			roundTripOAuthError(response, "invalid_grant", "PKCE verification failed")
			return
		}
		refresh := i.newRefreshToken()
		i.writeTokens(response, refresh)
	case "refresh_token":
		i.rotateRefresh(response, request.PostForm.Get("refresh_token"))
	default:
		roundTripOAuthError(response, "unsupported_grant_type", "Unsupported grant type")
	}
}

func (i *roundTripIssuer) newRefreshToken() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	token := fmt.Sprintf("user:01KP8KA31Z3AGRCC578R9HXW0H:refresh-%d", i.nextRefresh)
	i.nextRefresh++
	i.refresh[token] = &refreshRecord{}
	return token
}

func (i *roundTripIssuer) rotateRefresh(response http.ResponseWriter, token string) {
	i.mu.Lock()
	record := i.refresh[token]
	now := i.now
	if record == nil {
		i.mu.Unlock()
		roundTripOAuthError(response, "invalid_grant", "Refresh token has been used or expired")
		return
	}
	if !record.usedAt.IsZero() {
		if now.Sub(record.usedAt) <= 600*time.Second {
			successor := record.successor
			i.mu.Unlock()
			i.writeTokens(response, successor)
			return
		}
		i.mu.Unlock()
		roundTripOAuthError(response, "invalid_grant", "Refresh token has been used or expired")
		return
	}
	successor := fmt.Sprintf("user:01KP8KA31Z3AGRCC578R9HXW0H:refresh-%d", i.nextRefresh)
	i.nextRefresh++
	record.usedAt = now
	record.successor = successor
	i.refresh[successor] = &refreshRecord{}
	i.mu.Unlock()
	i.writeTokens(response, successor)
}

func roundTripOAuthError(response http.ResponseWriter, code, description string) {
	response.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(response).Encode(map[string]string{"error": code, "error_description": description})
}

func (i *roundTripIssuer) writeTokens(response http.ResponseWriter, refresh string) {
	_ = json.NewEncoder(response).Encode(map[string]any{
		"access_token":  i.signAccessToken(),
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    900,
	})
}

func (i *roundTripIssuer) signAccessToken() string {
	i.mu.Lock()
	now := i.now
	resource := i.codeResource
	i.mu.Unlock()
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": "roundtrip-key", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss":       i.server.URL,
		"sub":       "user:01KP8KA31Z3AGRCC578R9HXW0H",
		"aud":       resource,
		"mode":      "access",
		"type":      "user",
		"scope":     "openid email profile",
		"client_id": "roundtrip-client",
		"roles":     []string{"member"},
		"iat":       now.Unix(),
		"nbf":       now.Add(-time.Second).Unix(),
		"exp":       now.Add(15 * time.Minute).Unix(),
		"properties": map[string]any{
			"userId":    "01KP8KA31Z3AGRCC578R9HXW0H",
			"email":     "member@example.test",
			"name":      "Round Trip Member",
			"image":     nil,
			"isNewUser": false,
		},
	})
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(signingInput))
	r, signatureS, _ := ecdsa.Sign(rand.Reader, i.key, digest[:])
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	signatureS.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (i *roundTripIssuer) revoke(response http.ResponseWriter, request *http.Request) {
	_ = request.ParseForm()
	i.mu.Lock()
	i.revoked = append(i.revoked, request.PostForm.Get("token"))
	i.mu.Unlock()
	response.WriteHeader(http.StatusOK)
}

func (i *roundTripIssuer) revokedCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.revoked)
}

func TestFakeIssuerRoundTripAuthorizeCallbackVerifyRefreshReuseAndLogout(t *testing.T) {
	start := time.Unix(1_900_000_000, 0)
	issuer := newRoundTripIssuer(t, start)
	var client *Client

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(response http.ResponseWriter, request *http.Request) {
		origin := &url.URL{Scheme: "https", Host: request.Host}
		authorizationURL, transaction, err := client.Authorize(origin, request.URL.Query().Get("provider"), request.URL.Query().Get("redirect"))
		if err != nil {
			http.Error(response, err.Error(), http.StatusBadRequest)
			return
		}
		client.SetTransactionCookies(response, transaction)
		http.Redirect(response, request, authorizationURL.String(), http.StatusFound)
	})
	mux.HandleFunc("/api/auth/callback", func(response http.ResponseWriter, request *http.Request) {
		client.Callback(response, request)
	})
	mux.HandleFunc("/logout", func(response http.ResponseWriter, request *http.Request) {
		client.Logout(response, request)
	})
	mux.Handle("/private", http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := PrincipalFromContext(request.Context())
		if !ok {
			http.Error(response, "missing principal", http.StatusInternalServerError)
			return
		}
		_, _ = response.Write([]byte(principal.Subject))
	}))
	mux.HandleFunc("/", func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) })

	var appHandler http.Handler = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mux.ServeHTTP(response, request)
	})
	app := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		client.Middleware(appHandler).ServeHTTP(response, request)
	}))
	t.Cleanup(app.Close)

	var err error
	client, err = New(Config{
		Issuer:         issuer.server.URL,
		ClientID:       "roundtrip-client",
		Resource:       app.URL,
		CallbackPath:   "/api/auth/callback",
		CookiePrefix:   "roundtrip",
		Providers:      []string{"google"},
		GatedPaths:     []string{"/private"},
		LoginPath:      "/login",
		LogoutRedirect: "/",
		HTTPClient:     issuer.server.Client(),
		Now:            issuer.currentTime,
	})
	if err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	browser := app.Client()
	browser.Jar = jar
	response, err := browser.Get(app.URL + "/login?provider=google&redirect=%2Fprivate")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK || body != "user:01KP8KA31Z3AGRCC578R9HXW0H" {
		t.Fatalf("callback final response = %d %q", response.StatusCode, body)
	}
	appURL, _ := url.Parse(app.URL)
	initialRefresh := cookieValue(jar.Cookies(appURL), "roundtrip_rt")
	if !strings.HasSuffix(initialRefresh, ":refresh-0") {
		t.Fatalf("initial refresh token shape = %q", initialRefresh)
	}

	refreshAt := start.Add(16*time.Minute + time.Second)
	issuer.setTime(refreshAt)
	response, err = browser.Get(app.URL + "/private")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	rotatedRefresh := cookieValue(jar.Cookies(appURL), "roundtrip_rt")
	if !strings.HasSuffix(rotatedRefresh, ":refresh-1") {
		t.Fatalf("silent refresh cookie = %q", rotatedRefresh)
	}

	issuer.setTime(refreshAt.Add(600 * time.Second))
	tokens, _, err := client.Refresh(context.Background(), initialRefresh)
	if err != nil || tokens.RefreshToken != rotatedRefresh {
		t.Fatalf("reuse at 600 seconds = %#v, %v", tokens, err)
	}
	issuer.setTime(refreshAt.Add(601 * time.Second))
	if _, _, err := client.Refresh(context.Background(), initialRefresh); !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("late reuse error = %v", err)
	}
	if _, _, err := client.Refresh(context.Background(), rotatedRefresh); err != nil {
		t.Fatalf("successor chain after late reuse = %v", err)
	}

	response, err = browser.Get(app.URL + "/logout")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	if cookieValue(jar.Cookies(appURL), "roundtrip_at") != "" || cookieValue(jar.Cookies(appURL), "roundtrip_rt") != "" {
		t.Fatalf("logout left session cookies: %v", jar.Cookies(appURL))
	}
	if issuer.revokedCount() != 1 {
		t.Fatalf("revocations = %d, want 1", issuer.revokedCount())
	}
}

func TestMiddlewareFailOpenFailClosedAndSecretFailure(t *testing.T) {
	var issuerRequests atomic.Int32
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		issuerRequests.Add(1)
		return nil, errors.New("issuer offline")
	})
	newMiddlewareClient := func(t *testing.T, secret SecretSource) *Client {
		t.Helper()
		client, err := New(Config{
			Issuer:       "https://auth.example.test",
			ClientID:     "client",
			ClientSecret: secret,
			Resource:     "https://consumer.example.test",
			CallbackPath: "/api/auth/callback",
			CookiePrefix: "consumer",
			Providers:    []string{"google"},
			GatedPaths:   []string{"/private/*"},
			LoginPath:    "/login",
			HTTPClient:   &http.Client{Transport: transport},
		})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	next := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) })

	publicRequest := httptest.NewRequest(http.MethodGet, "https://consumer.example.test/public", nil)
	publicRequest.AddCookie(&http.Cookie{Name: "consumer_at", Value: "not-a-jwt"})
	publicResponse := httptest.NewRecorder()
	newMiddlewareClient(t, nil).Middleware(next).ServeHTTP(publicResponse, publicRequest)
	if publicResponse.Code != http.StatusNoContent {
		t.Fatalf("public offline status = %d", publicResponse.Code)
	}

	gatedRequest := httptest.NewRequest(http.MethodGet, "https://consumer.example.test/private/item", nil)
	gatedResponse := httptest.NewRecorder()
	newMiddlewareClient(t, nil).Middleware(next).ServeHTTP(gatedResponse, gatedRequest)
	if gatedResponse.Code != http.StatusFound || !strings.Contains(gatedResponse.Header().Get("Location"), "/login?redirect=%2Fprivate%2Fitem") {
		t.Fatalf("gated response = %d %q", gatedResponse.Code, gatedResponse.Header().Get("Location"))
	}

	secretRequest := httptest.NewRequest(http.MethodGet, "https://consumer.example.test/public", nil)
	secretRequest.AddCookie(&http.Cookie{Name: "consumer_at", Value: "not-a-jwt"})
	secretRequest.AddCookie(&http.Cookie{Name: "consumer_rt", Value: "refresh-token"})
	secretResponse := httptest.NewRecorder()
	client := newMiddlewareClient(t, SecretSourceFunc(func(context.Context) (string, error) { return "", errors.New("binding rejected") }))
	client.Middleware(next).ServeHTTP(secretResponse, secretRequest)
	if secretResponse.Code != http.StatusServiceUnavailable || secretResponse.Body.String() != "Service unavailable\n" || secretResponse.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("secret response = %d %q %q", secretResponse.Code, secretResponse.Body.String(), secretResponse.Header().Get("Cache-Control"))
	}
	if issuerRequests.Load() != 0 {
		t.Fatalf("issuer requests before secret failure = %d", issuerRequests.Load())
	}
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func cookieValue(cookies []*http.Cookie, name string) string {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func isOAuthCode(err error, code string) bool {
	var oauthErr *OAuthError
	return errors.As(err, &oauthErr) && oauthErr.OAuthCode == code
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
