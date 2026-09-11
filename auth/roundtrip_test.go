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

	"github.com/growth-labs/packages-go/testkit"
)

type refreshRecord struct {
	usedAt    time.Time
	successor string
}

type roundTripIssuer struct {
	t      *testing.T
	server *httptest.Server
	key    *ecdsa.PrivateKey
	userID string

	mu               sync.Mutex
	now              time.Time
	codeChallenge    string
	codeResource     string
	refresh          map[string]*refreshRecord
	nextRefresh      int
	refreshCalls     int
	revoked          []string
	disableLateReuse bool
}

func newRoundTripIssuer(t *testing.T, now time.Time) *roundTripIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &roundTripIssuer{t: t, key: key, userID: "01KP8KA31Z3AGRCC578R9HXW0H", now: now, refresh: make(map[string]*refreshRecord)}
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
		i.mu.Lock()
		i.refreshCalls++
		i.mu.Unlock()
		i.rotateRefresh(response, request.PostForm.Get("refresh_token"))
	default:
		roundTripOAuthError(response, "unsupported_grant_type", "Unsupported grant type")
	}
}

func (i *roundTripIssuer) newRefreshToken() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	token := fmt.Sprintf("user:%s:refresh-%d", i.userID, i.nextRefresh)
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
		if now.Sub(record.usedAt) <= 600*time.Second || i.disableLateReuse {
			successor := record.successor
			i.mu.Unlock()
			i.writeTokens(response, successor)
			return
		}
		i.mu.Unlock()
		roundTripOAuthError(response, "invalid_grant", "Refresh token has been used or expired")
		return
	}
	successor := fmt.Sprintf("user:%s:refresh-%d", i.userID, i.nextRefresh)
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
		"sub":       "user:" + i.userID,
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
			"userId":    i.userID,
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

func (i *roundTripIssuer) refreshCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.refreshCalls
}

func TestFakeIssuerRoundTripAuthorizeCallbackVerifyRefreshReuseAndLogout(t *testing.T) {
	for _, test := range []struct{ name, userID string }{
		{"ULID", "01KP8KA31Z3AGRCC578R9HXW0H"},
		{"UUID", "a340f47a-1e32-4a80-9125-15ef5db0151c"},
	} {
		t.Run(test.name, func(t *testing.T) {
			testCanonicalIdentityRoundTrip(t, test.userID)
		})
	}
}

func testCanonicalIdentityRoundTrip(t *testing.T, userID string) {
	t.Helper()
	start := time.Unix(1_900_000_000, 0)
	issuer := newRoundTripIssuer(t, start)
	issuer.userID = userID
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
	if response.StatusCode != http.StatusOK || body != "user:"+userID {
		t.Fatalf("callback final response = %d %q", response.StatusCode, body)
	}
	response, err = browser.Get(app.URL + "/private")
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, response); response.StatusCode != http.StatusOK || body != "user:"+userID {
		t.Fatalf("session reload response = %d %q", response.StatusCode, body)
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

func TestCallbackValidatesStateBeforeOAuthError(t *testing.T) {
	client := newMiddlewareClientForCallback(t, nil)
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		state := "wrong"
		if mutation.GuardsDisabled() {
			state = "expected"
		}
		_, transaction, err := client.Authorize(mustURL(t, "https://consumer.example.test"), "google", "/")
		if err != nil {
			return err
		}
		transaction.State = "expected"
		cookies := httptest.NewRecorder()
		client.SetTransactionCookies(cookies, transaction)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://consumer.example.test/api/auth/callback?error=access_denied&state="+state, nil)
		for _, cookie := range cookies.Result().Cookies() {
			request.AddCookie(cookie)
		}
		client.Callback(recorder, request)
		if recorder.Code == http.StatusForbidden {
			return errors.New("callback state rejected")
		}
		if recorder.Code != http.StatusFound {
			return fmt.Errorf("unexpected callback status %d", recorder.Code)
		}
		return nil
	})
}

func TestHTTPCallbackPreservesAuthorizedRedirectURI(t *testing.T) {
	start := time.Unix(1_900_000_000, 0)
	issuer := newRoundTripIssuer(t, start)
	var client *Client
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(response http.ResponseWriter, request *http.Request) {
		target, transaction, err := client.Authorize(&url.URL{Scheme: "http", Host: request.Host}, "google", "/")
		if err != nil {
			t.Fatal(err)
		}
		client.SetTransactionCookies(response, transaction)
		http.Redirect(response, request, target.String(), http.StatusFound)
	})
	mux.HandleFunc("/api/auth/callback", clientCallback(&client))
	mux.HandleFunc("/", func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) })
	app := httptest.NewServer(mux)
	t.Cleanup(app.Close)

	var err error
	client, err = New(Config{
		Issuer:       issuer.server.URL,
		ClientID:     "roundtrip-client",
		Resource:     app.URL,
		CallbackPath: "/api/auth/callback",
		CookiePrefix: "roundtrip-http",
		Providers:    []string{"google"},
		HTTPClient:   issuer.server.Client(),
		Now:          issuer.currentTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	loginResponse, err := noRedirect.Get(app.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer loginResponse.Body.Close()
	issuerResponse, err := noRedirect.Get(loginResponse.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	defer issuerResponse.Body.Close()
	callbackRequest, err := http.NewRequest(http.MethodGet, issuerResponse.Header.Get("Location"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range loginResponse.Cookies() {
		callbackRequest.AddCookie(cookie)
	}
	callbackResponse, err := noRedirect.Do(callbackRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer callbackResponse.Body.Close()
	if callbackResponse.StatusCode != http.StatusFound || callbackResponse.Header.Get("Location") != "/" || cookieValue(callbackResponse.Cookies(), "roundtrip-http_at") == "" {
		t.Fatalf("HTTP callback = %d %q cookies=%v", callbackResponse.StatusCode, callbackResponse.Header.Get("Location"), callbackResponse.Cookies())
	}
}

func clientCallback(client **Client) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		(*client).Callback(response, request)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestMiddlewareBypassesLogoutRefreshAndStillClearsOnSecretFailure(t *testing.T) {
	start := time.Unix(1_900_000_000, 0)
	issuer := newRoundTripIssuer(t, start)
	issuer.mu.Lock()
	issuer.codeResource = "https://consumer.example.test"
	issuer.mu.Unlock()
	refresh := issuer.newRefreshToken()

	newLogoutClient := func(secret SecretSource) *Client {
		client, err := New(Config{
			Issuer:       issuer.server.URL,
			ClientID:     "roundtrip-client",
			ClientSecret: secret,
			Resource:     "https://consumer.example.test",
			CallbackPath: "/api/auth/callback",
			CookiePrefix: "roundtrip",
			Providers:    []string{"google"},
			LoginPath:    "/login",
			LogoutPath:   "/logout",
			HTTPClient:   issuer.server.Client(),
			Now:          issuer.currentTime,
		})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}

	publicClient := newLogoutClient(nil)
	publicRequest := httptest.NewRequest(http.MethodGet, "https://consumer.example.test/logout", nil)
	publicRequest.AddCookie(&http.Cookie{Name: "roundtrip_at", Value: "expired"})
	publicRequest.AddCookie(&http.Cookie{Name: "roundtrip_rt", Value: refresh})
	publicResponse := httptest.NewRecorder()
	publicClient.Middleware(http.HandlerFunc(publicClient.Logout)).ServeHTTP(publicResponse, publicRequest)
	if issuer.refreshCount() != 0 || issuer.revokedCount() != 1 {
		t.Fatalf("logout refreshes=%d revocations=%d", issuer.refreshCount(), issuer.revokedCount())
	}
	assertClearedSessionCookies(t, publicResponse.Result().Cookies())

	secretClient := newLogoutClient(SecretSourceFunc(func(context.Context) (string, error) {
		return "", errors.New("binding rejected")
	}))
	secretRequest := httptest.NewRequest(http.MethodGet, "https://consumer.example.test/logout", nil)
	secretRequest.AddCookie(&http.Cookie{Name: "roundtrip_rt", Value: refresh})
	secretResponse := httptest.NewRecorder()
	secretClient.Middleware(http.HandlerFunc(secretClient.Logout)).ServeHTTP(secretResponse, secretRequest)
	if secretResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("secret logout status = %d", secretResponse.Code)
	}
	assertClearedSessionCookies(t, secretResponse.Result().Cookies())
}

func newMiddlewareClientForCallback(t *testing.T, secret SecretSource) *Client {
	t.Helper()
	client, err := New(Config{
		Issuer:       "https://auth.example.test",
		ClientID:     "client",
		ClientSecret: secret,
		Resource:     "https://consumer.example.test",
		CallbackPath: "/api/auth/callback",
		CookiePrefix: "consumer",
		Providers:    []string{"google"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func assertClearedSessionCookies(t *testing.T, cookies []*http.Cookie) {
	t.Helper()
	cleared := map[string]bool{}
	for _, cookie := range cookies {
		if cookie.MaxAge < 0 {
			cleared[cookie.Name] = true
		}
	}
	if !cleared["roundtrip_at"] || !cleared["roundtrip_rt"] {
		t.Fatalf("cleared session cookies = %v", cleared)
	}
}

func TestRefreshReuseGuardIsFalsifiableAtRefreshWiringPoint(t *testing.T) {
	start := time.Unix(1_900_000_000, 0)
	issuer := newRoundTripIssuer(t, start)
	issuer.mu.Lock()
	issuer.codeResource = "https://consumer.example.test"
	issuer.mu.Unlock()
	client, err := New(Config{
		Issuer:       issuer.server.URL,
		ClientID:     "roundtrip-client",
		Resource:     "https://consumer.example.test",
		CallbackPath: "/api/auth/callback",
		CookiePrefix: "roundtrip",
		Providers:    []string{"google"},
		HTTPClient:   issuer.server.Client(),
		Now:          issuer.currentTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	original := issuer.newRefreshToken()
	if _, _, err := client.Refresh(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	issuer.setTime(start.Add(601 * time.Second))

	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		issuer.mu.Lock()
		issuer.disableLateReuse = mutation.GuardsDisabled()
		issuer.mu.Unlock()
		_, _, err := client.Refresh(context.Background(), original)
		return err
	})
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

func TestMiddlewareGatedRedirectKeepsQuery(t *testing.T) {
	client, err := New(Config{
		Issuer:       "https://auth.example.test",
		ClientID:     "client",
		Resource:     "https://consumer.example.test",
		CallbackPath: "/api/auth/callback",
		CookiePrefix: "consumer",
		Providers:    []string{"google"},
		GatedPaths:   []string{"/devices", "/devices/*"},
		LoginPath:    "/login",
		HTTPClient:   &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("issuer offline") })},
	})
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) })

	cases := []struct {
		name     string
		target   string
		location string
	}{
		{name: "query survives", target: "https://consumer.example.test/devices?pair_state=abc-_", location: "/login?redirect=%2Fdevices%3Fpair_state%3Dabc-_"},
		{name: "no query unchanged", target: "https://consumer.example.test/devices", location: "/login?redirect=%2Fdevices"},
		{name: "encoded slash in query falls back to the path", target: "https://consumer.example.test/devices?next=%2Fadmin", location: "/login?redirect=%2Fdevices"},
		{name: "backslash in query falls back to the path", target: `https://consumer.example.test/devices?next=\evil`, location: "/login?redirect=%2Fdevices"},
		{name: "fragment never appears", target: "https://consumer.example.test/devices?pair_state=abc#section", location: "/login?redirect=%2Fdevices%3Fpair_state%3Dabc"},
		{name: "nested path keeps query", target: "https://consumer.example.test/devices/pair?pair_state=abc", location: "/login?redirect=%2Fdevices%2Fpair%3Fpair_state%3Dabc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tc.target, nil)
			response := httptest.NewRecorder()
			client.Middleware(next).ServeHTTP(response, request)
			if response.Code != http.StatusFound || response.Header().Get("Location") != tc.location {
				t.Fatalf("gated response = %d %q, want 302 %q", response.Code, response.Header().Get("Location"), tc.location)
			}
		})
	}
}
