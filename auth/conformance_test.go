package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/growth-labs/packages-go/testkit"
)

// Source: growth-labs/identity-platform PR #159, exact head
// 75b4960f97cd2a5b65bd17a890be973ca555b3c7.
//
//go:embed testdata/conformance/v1/*.json
var conformanceFiles embed.FS

type conformanceManifest struct {
	Contract      string `json:"contract"`
	FormatVersion string `json:"format_version"`
	Issuer        string `json:"issuer"`
	Constants     struct {
		AccessTokenTTLSeconds    int `json:"access_token_ttl_seconds"`
		RefreshTokenTTLSeconds   int `json:"refresh_token_ttl_seconds"`
		RefreshReuseGraceSeconds int `json:"refresh_reuse_grace_seconds"`
	} `json:"constants"`
	Cases map[string]string `json:"cases"`
}

type conformanceAuthorize struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Request     struct {
		Method string            `json:"method"`
		Path   string            `json:"path"`
		Query  map[string]string `json:"query"`
	} `json:"request"`
}

type conformanceToken struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Request     struct {
		Method      string            `json:"method"`
		Path        string            `json:"path"`
		ContentType string            `json:"content_type"`
		Form        map[string]string `json:"form"`
	} `json:"request"`
	Success           conformanceResponseMatcher `json:"success"`
	AccessTokenClaims conformanceJSONMatcher     `json:"access_token_claims"`
}

type conformanceJSONMatcher struct {
	Type       string                            `json:"type"`
	Required   []string                          `json:"required"`
	Properties map[string]conformanceJSONMatcher `json:"properties"`
	Pattern    string                            `json:"pattern"`
	Const      json.RawMessage                   `json:"const"`
	Minimum    *int                              `json:"minimum"`
	Maximum    *int                              `json:"maximum"`
	Invariants []string                          `json:"invariants"`
}

type conformanceResponseMatcher struct {
	Status int                    `json:"status"`
	Body   conformanceJSONMatcher `json:"body"`
}

type conformanceOAuthBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	State            string `json:"state"`
}

type conformanceRefresh struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Request     struct {
		Method      string            `json:"method"`
		Path        string            `json:"path"`
		ContentType string            `json:"content_type"`
		Form        map[string]string `json:"form"`
	} `json:"request"`
	Scenarios struct {
		FirstUse struct {
			Status              int  `json:"status"`
			RotatesRefreshToken bool `json:"rotates_refresh_token"`
		} `json:"first_use"`
		ReuseWithinGrace struct {
			AtOrBeforeSeconds         int  `json:"at_or_before_seconds"`
			Status                    int  `json:"status"`
			SameSuccessorRefreshToken bool `json:"same_successor_refresh_token"`
		} `json:"reuse_within_grace"`
		ReuseAfterGrace struct {
			AfterSeconds int `json:"after_seconds"`
			Status       int `json:"status"`
			Body         struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			} `json:"body"`
			CurrentChainSurvives bool `json:"current_chain_survives"`
		} `json:"reuse_after_grace"`
		MembershipRemoved struct {
			Status int `json:"status"`
			Body   struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			} `json:"body"`
		} `json:"membership_removed"`
	} `json:"scenarios"`
}

type conformanceRefusals struct {
	ID                       string `json:"id"`
	Description              string `json:"description"`
	InteractiveGatedResource struct {
		Transport     string               `json:"transport"`
		Status        int                  `json:"status"`
		CallbackQuery conformanceOAuthBody `json:"callback_query"`
	} `json:"interactive_gated_resource"`
	ConsumerAPIGatedResource conformanceAPIRefusal `json:"consumer_api_gated_resource"`
	MissingResource          conformanceAPIRefusal `json:"missing_resource"`
}

type conformanceAPIRefusal struct {
	Request struct {
		Method string            `json:"method"`
		Path   string            `json:"path"`
		Body   map[string]string `json:"body"`
	} `json:"request"`
	Response struct {
		Status int                  `json:"status"`
		Body   conformanceOAuthBody `json:"body"`
	} `json:"response"`
}

func loadConformance[T any](t *testing.T, path string) T {
	t.Helper()
	fixtures, err := testkit.LoadJSON[T](conformanceFiles, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 1 {
		t.Fatalf("fixture count for %s = %d, want 1", path, len(fixtures))
	}
	return fixtures[0]
}

func TestConformanceManifestAndAuthorizeRequest(t *testing.T) {
	manifest := loadConformance[conformanceManifest](t, "testdata/conformance/v1/manifest.json")
	authorize := loadConformance[conformanceAuthorize](t, "testdata/conformance/v1/authorize.json")
	if manifest.Contract != "growth-labs.identity.consumer" || manifest.FormatVersion != "1.0.0" {
		t.Fatalf("manifest identity = %q %q", manifest.Contract, manifest.FormatVersion)
	}
	if manifest.Constants.AccessTokenTTLSeconds != 900 || manifest.Constants.RefreshTokenTTLSeconds != 2_592_000 || manifest.Constants.RefreshReuseGraceSeconds != 600 {
		t.Fatalf("manifest constants = %#v", manifest.Constants)
	}
	if len(manifest.Cases) != 4 || manifest.Cases["authorize"] != "authorize.json" {
		t.Fatalf("manifest cases = %v", manifest.Cases)
	}

	redirectURI, _ := url.Parse(authorize.Request.Query["redirect_uri"])
	origin := &url.URL{Scheme: redirectURI.Scheme, Host: redirectURI.Host}
	client, err := New(Config{
		Issuer:       manifest.Issuer,
		ClientID:     authorize.Request.Query["client_id"],
		Resource:     authorize.Request.Query["resource"],
		CallbackPath: redirectURI.Path,
		CookiePrefix: "conformance",
		Providers:    []string{"google"},
	})
	if err != nil {
		t.Fatal(err)
	}
	gotURL, transaction, err := client.Authorize(origin, "google", "/")
	if err != nil {
		t.Fatal(err)
	}
	if authorize.Request.Method != http.MethodGet || gotURL.Path != authorize.Request.Path {
		t.Fatalf("authorize method/path = %s %s", authorize.Request.Method, gotURL.Path)
	}
	for key, expected := range authorize.Request.Query {
		if key == "state" || key == "code_challenge" {
			continue
		}
		if got := gotURL.Query().Get(key); got != expected {
			t.Errorf("authorize query %s = %q, want %q", key, got, expected)
		}
	}
	digest := sha256.Sum256([]byte(transaction.Verifier))
	if gotURL.Query().Get("state") != transaction.State || gotURL.Query().Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("dynamic PKCE/state substitution failed: %s", gotURL)
	}

	recorder := httptest.NewRecorder()
	client.SetSessionCookies(recorder, Tokens{AccessToken: "fixture-access", RefreshToken: "fixture-refresh"})
	cookies := recorder.Result().Cookies()
	if cookies[0].MaxAge != manifest.Constants.AccessTokenTTLSeconds || cookies[1].MaxAge != manifest.Constants.RefreshTokenTTLSeconds {
		t.Fatalf("cookie TTLs = %d %d", cookies[0].MaxAge, cookies[1].MaxAge)
	}
}

func TestConformanceTokenAndRefreshScenariosExecute(t *testing.T) {
	manifest := loadConformance[conformanceManifest](t, "testdata/conformance/v1/manifest.json")
	tokenFixture := loadConformance[conformanceToken](t, "testdata/conformance/v1/token.json")
	refreshFixture := loadConformance[conformanceRefresh](t, "testdata/conformance/v1/refresh.json")
	now := time.Unix(1_900_000_000, 0)
	transport := newConformanceFixtureTransport(t, manifest, tokenFixture, refreshFixture, now)
	client, err := New(Config{
		Issuer:       manifest.Issuer,
		ClientID:     tokenFixture.Request.Form["client_id"],
		Resource:     tokenFixture.Request.Form["resource"],
		CallbackPath: "/api/auth/callback",
		CookiePrefix: "conformance",
		Providers:    []string{"google"},
		HTTPClient:   &http.Client{Transport: transport},
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	transport.mode = "token"
	tokens, principal, err := client.Exchange(context.Background(), ExchangeRequest{
		Code:  tokenFixture.Request.Form["code"],
		State: "conformance-state",
		Transaction: Transaction{
			Verifier:    tokenFixture.Request.Form["code_verifier"],
			State:       "conformance-state",
			CallbackURI: tokenFixture.Request.Form["redirect_uri"],
			ExpiresAt:   now.Add(10 * time.Minute),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertConformanceRequest(t, transport.lastRequest(), tokenFixture.Request.Method, tokenFixture.Request.Path, tokenFixture.Request.ContentType, tokenFixture.Request.Form)
	assertJSONMatcher(t, tokenFixture.Success.Body, transport.lastResponse)
	assertJSONMatcher(t, tokenFixture.AccessTokenClaims, transport.lastClaims)
	if principal.Subject != "user:01KP8KA31Z3AGRCC578R9HXW0H" || principal.UserID != "01KP8KA31Z3AGRCC578R9HXW0H" || tokens.RefreshToken != transport.originalRefresh {
		t.Fatalf("token success = %#v %#v", tokens, principal)
	}
	assertClaimInvariants(t, tokenFixture.AccessTokenClaims.Invariants, transport.lastClaims, manifest.Constants.AccessTokenTTLSeconds)

	transport.mode = "refresh-first"
	first, _, err := client.Refresh(context.Background(), transport.originalRefresh)
	if err != nil || first.RefreshToken == transport.originalRefresh || refreshFixture.Scenarios.FirstUse.Status != http.StatusOK || !refreshFixture.Scenarios.FirstUse.RotatesRefreshToken {
		t.Fatalf("first refresh = %#v, %v", first, err)
	}
	expectedRefreshForm := cloneStrings(refreshFixture.Request.Form)
	expectedRefreshForm["refresh_token"] = transport.originalRefresh
	assertConformanceRequest(t, transport.lastRequest(), refreshFixture.Request.Method, refreshFixture.Request.Path, refreshFixture.Request.ContentType, expectedRefreshForm)

	transport.mode = "refresh-reuse"
	reused, _, err := client.Refresh(context.Background(), transport.originalRefresh)
	if err != nil || reused.RefreshToken != first.RefreshToken || refreshFixture.Scenarios.ReuseWithinGrace.Status != http.StatusOK || !refreshFixture.Scenarios.ReuseWithinGrace.SameSuccessorRefreshToken {
		t.Fatalf("within-grace refresh = %#v, %v", reused, err)
	}
	if refreshFixture.Scenarios.ReuseWithinGrace.AtOrBeforeSeconds != manifest.Constants.RefreshReuseGraceSeconds || refreshFixture.Scenarios.ReuseAfterGrace.AfterSeconds != manifest.Constants.RefreshReuseGraceSeconds {
		t.Fatalf("refresh boundary = %#v", refreshFixture.Scenarios)
	}

	transport.mode = "refresh-late"
	_, _, err = client.Refresh(context.Background(), transport.originalRefresh)
	assertOAuthError(t, err, refreshFixture.Scenarios.ReuseAfterGrace.Status, refreshFixture.Scenarios.ReuseAfterGrace.Body.Error, refreshFixture.Scenarios.ReuseAfterGrace.Body.ErrorDescription)
	transport.mode = "refresh-successor"
	if _, _, err := client.Refresh(context.Background(), first.RefreshToken); err != nil || !refreshFixture.Scenarios.ReuseAfterGrace.CurrentChainSurvives {
		t.Fatalf("successor after late reuse = %v", err)
	}

	transport.mode = "membership-removed"
	_, _, err = client.Refresh(context.Background(), first.RefreshToken)
	assertOAuthError(t, err, refreshFixture.Scenarios.MembershipRemoved.Status, refreshFixture.Scenarios.MembershipRemoved.Body.Error, refreshFixture.Scenarios.MembershipRemoved.Body.ErrorDescription)
}

func TestConformanceRefusalScenariosExecute(t *testing.T) {
	manifest := loadConformance[conformanceManifest](t, "testdata/conformance/v1/manifest.json")
	refusals := loadConformance[conformanceRefusals](t, "testdata/conformance/v1/refusals.json")
	client, err := New(Config{
		Issuer:       manifest.Issuer,
		ClientID:     "conformance-public-client",
		Resource:     "https://consumer.example.test",
		CallbackPath: "/api/auth/callback",
		CookiePrefix: "conformance",
		Providers:    []string{"google"},
		LoginPath:    "/login",
		Now:          func() time.Time { return time.Unix(1_900_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse("https://consumer.example.test")
	_, transaction, err := client.Authorize(origin, "google", "/")
	if err != nil {
		t.Fatal(err)
	}
	transaction.State = refusals.InteractiveGatedResource.CallbackQuery.State
	recorder := httptest.NewRecorder()
	client.SetTransactionCookies(recorder, transaction)
	request := httptest.NewRequest(http.MethodGet, "https://consumer.example.test/api/auth/callback?"+url.Values{
		"error":             {refusals.InteractiveGatedResource.CallbackQuery.Error},
		"error_description": {refusals.InteractiveGatedResource.CallbackQuery.ErrorDescription},
		"state":             {refusals.InteractiveGatedResource.CallbackQuery.State},
	}.Encode(), nil)
	for _, cookie := range recorder.Result().Cookies() {
		request.AddCookie(cookie)
	}
	callbackResponse := httptest.NewRecorder()
	client.Callback(callbackResponse, request)
	if refusals.InteractiveGatedResource.Transport != "oauth_redirect" || callbackResponse.Code != refusals.InteractiveGatedResource.Status || callbackResponse.Header().Get("Location") != "/login?error=auth_failed" {
		t.Fatalf("interactive refusal response = %d %q", callbackResponse.Code, callbackResponse.Header().Get("Location"))
	}

	for name, refusal := range map[string]conformanceAPIRefusal{
		"consumer gated":   refusals.ConsumerAPIGatedResource,
		"missing resource": refusals.MissingResource,
	} {
		t.Run(name, func(t *testing.T) {
			if refusal.Request.Method != http.MethodPost || refusal.Request.Path == "" || refusal.Request.Body["client_id"] == "" {
				t.Fatalf("request matcher = %#v", refusal.Request)
			}
			body, _ := json.Marshal(refusal.Response.Body)
			err := decodeOAuthError(&http.Response{StatusCode: refusal.Response.Status, Body: io.NopCloser(strings.NewReader(string(body)))})
			assertOAuthError(t, err, refusal.Response.Status, refusal.Response.Body.Error, refusal.Response.Body.ErrorDescription)
		})
	}
}

func assertConformanceRequest(t *testing.T, request *http.Request, method, path, contentType string, expected map[string]string) {
	t.Helper()
	if request.Method != method || request.URL.Path != path || request.Header.Get("Content-Type") != contentType {
		t.Fatalf("request boundary = %s %s %q", request.Method, request.URL.Path, request.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(request.Body)
	form, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range expected {
		if form.Get(name) != value {
			t.Errorf("form %s = %q, want %q", name, form.Get(name), value)
		}
	}
	if len(form) != len(expected) {
		t.Fatalf("form = %v, want exactly %d fields", form, len(expected))
	}
}

func assertOAuthError(t *testing.T, err error, status int, code, description string) {
	t.Helper()
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Status != status || oauthErr.OAuthCode != code || oauthErr.Description != description {
		t.Fatalf("OAuth error = %#v (%v)", oauthErr, err)
	}
}

func cloneStrings(source map[string]string) map[string]string {
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func assertJSONMatcher(t *testing.T, matcher conformanceJSONMatcher, value any) {
	t.Helper()
	if len(matcher.Const) > 0 {
		actual, _ := json.Marshal(value)
		var normalized any
		if err := json.Unmarshal(matcher.Const, &normalized); err != nil {
			t.Fatal(err)
		}
		expected, _ := json.Marshal(normalized)
		if string(actual) != string(expected) {
			t.Fatalf("const matcher = %s, want %s", actual, expected)
		}
	}
	switch matcher.Type {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("object matcher got %T", value)
		}
		for _, required := range matcher.Required {
			if _, present := object[required]; !present {
				t.Fatalf("required property %q is missing", required)
			}
		}
		for name, property := range matcher.Properties {
			if child, present := object[name]; present {
				assertJSONMatcher(t, property, child)
			}
		}
	case "string":
		text, ok := value.(string)
		if !ok {
			t.Fatalf("string matcher got %T", value)
		}
		if matcher.Pattern != "" && !regexp.MustCompile(matcher.Pattern).MatchString(text) {
			t.Fatalf("value %q does not match %q", text, matcher.Pattern)
		}
	case "integer":
		number, ok := value.(int)
		if !ok {
			t.Fatalf("integer matcher got %T", value)
		}
		if matcher.Minimum != nil && number < *matcher.Minimum || matcher.Maximum != nil && number > *matcher.Maximum {
			t.Fatalf("integer %d outside fixture bounds", number)
		}
	}
}

func assertClaimInvariants(t *testing.T, invariants []string, claims map[string]any, accessTTL int) {
	t.Helper()
	for _, invariant := range invariants {
		switch invariant {
		case "sub_suffix_equals_properties.userId":
			properties := claims["properties"].(map[string]any)
			if strings.TrimPrefix(claims["sub"].(string), "user:") != properties["userId"] {
				t.Fatal("subject suffix does not equal properties.userId")
			}
		case "exp_minus_iat_equals_manifest.constants.access_token_ttl_seconds":
			if claims["exp"].(int)-claims["iat"].(int) != accessTTL {
				t.Fatal("access token TTL does not match manifest")
			}
		default:
			t.Fatalf("unsupported fixture invariant %q", invariant)
		}
	}
}

type conformanceFixtureTransport struct {
	t               *testing.T
	key             *ecdsa.PrivateKey
	manifest        conformanceManifest
	tokenFixture    conformanceToken
	refreshFixture  conformanceRefresh
	now             time.Time
	mode            string
	requests        []*http.Request
	lastResponse    map[string]any
	lastClaims      map[string]any
	originalRefresh string
	successor       string
}

func newConformanceFixtureTransport(t *testing.T, manifest conformanceManifest, tokenFixture conformanceToken, refreshFixture conformanceRefresh, now time.Time) *conformanceFixtureTransport {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &conformanceFixtureTransport{
		t:               t,
		key:             key,
		manifest:        manifest,
		tokenFixture:    tokenFixture,
		refreshFixture:  refreshFixture,
		now:             now,
		originalRefresh: "user:01KP8KA31Z3AGRCC578R9HXW0H:refresh-original",
		successor:       "user:01KP8KA31Z3AGRCC578R9HXW0H:refresh-successor",
	}
}

func (f *conformanceFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodGet && request.URL.Path == "/.well-known/jwks.json" {
		return f.jsonResponse(request, http.StatusOK, map[string]any{"keys": []any{f.jwk()}}), nil
	}
	body, _ := io.ReadAll(request.Body)
	clone := request.Clone(request.Context())
	clone.Body = io.NopCloser(strings.NewReader(string(body)))
	f.requests = append(f.requests, clone)

	switch f.mode {
	case "token":
		return f.tokenResponse(request, f.originalRefresh), nil
	case "refresh-first", "refresh-reuse":
		return f.tokenResponse(request, f.successor), nil
	case "refresh-successor":
		return f.tokenResponse(request, "user:01KP8KA31Z3AGRCC578R9HXW0H:refresh-next"), nil
	case "refresh-late":
		body := f.refreshFixture.Scenarios.ReuseAfterGrace.Body
		return f.jsonResponse(request, f.refreshFixture.Scenarios.ReuseAfterGrace.Status, map[string]any{"error": body.Error, "error_description": body.ErrorDescription}), nil
	case "membership-removed":
		body := f.refreshFixture.Scenarios.MembershipRemoved.Body
		return f.jsonResponse(request, f.refreshFixture.Scenarios.MembershipRemoved.Status, map[string]any{"error": body.Error, "error_description": body.ErrorDescription}), nil
	default:
		return nil, fmt.Errorf("unexpected conformance transport mode %q", f.mode)
	}
}

func (f *conformanceFixtureTransport) tokenResponse(request *http.Request, refresh string) *http.Response {
	f.lastClaims = map[string]any{
		"iss":       f.manifest.Issuer,
		"sub":       "user:01KP8KA31Z3AGRCC578R9HXW0H",
		"aud":       f.tokenFixture.Request.Form["resource"],
		"mode":      "access",
		"type":      "user",
		"scope":     "openid email profile",
		"client_id": f.tokenFixture.Request.Form["client_id"],
		"roles":     []string{"member"},
		"iat":       int(f.now.Unix()),
		"nbf":       int(f.now.Add(-time.Second).Unix()),
		"exp":       int(f.now.Unix()) + f.manifest.Constants.AccessTokenTTLSeconds,
		"properties": map[string]any{
			"userId":    "01KP8KA31Z3AGRCC578R9HXW0H",
			"email":     "member@example.test",
			"name":      "Conformance Member",
			"image":     "https://consumer.example.test/avatar.png",
			"isNewUser": false,
		},
	}
	f.lastResponse = map[string]any{
		"access_token":  f.signJWT(f.lastClaims),
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    f.manifest.Constants.AccessTokenTTLSeconds,
	}
	return f.jsonResponse(request, f.tokenFixture.Success.Status, f.lastResponse)
}

func (f *conformanceFixtureTransport) signJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": "conformance-key", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, digest[:])
	if err != nil {
		f.t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (f *conformanceFixtureTransport) jwk() map[string]any {
	return map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "conformance-key",
		"x": base64.RawURLEncoding.EncodeToString(f.key.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(f.key.Y.FillBytes(make([]byte, 32))),
	}
}

func (f *conformanceFixtureTransport) jsonResponse(request *http.Request, status int, body any) *http.Response {
	encoded, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(encoded))), Request: request}
}

func (f *conformanceFixtureTransport) lastRequest() *http.Request {
	return f.requests[len(f.requests)-1]
}
