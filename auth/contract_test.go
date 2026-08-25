package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"
)

const liveFulcrumIssuer = "https://auth.fulcrum-labs.com"
const maxLiveContractBytes = 1 << 20

func TestLiveIssuerDiscoveryContractReadOnly(t *testing.T) {
	var discovery struct {
		Issuer                        string   `json:"issuer"`
		AuthorizationEndpoint         string   `json:"authorization_endpoint"`
		TokenEndpoint                 string   `json:"token_endpoint"`
		RevocationEndpoint            string   `json:"revocation_endpoint"`
		JWKSURI                       string   `json:"jwks_uri"`
		GrantTypesSupported           []string `json:"grant_types_supported"`
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
		TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	}
	liveGETJSON(t, liveFulcrumIssuer+"/.well-known/oauth-authorization-server", &discovery)
	if discovery.Issuer != liveFulcrumIssuer {
		t.Fatalf("issuer = %q", discovery.Issuer)
	}
	wantEndpoints := map[string]string{
		"authorization": discovery.AuthorizationEndpoint,
		"token":         discovery.TokenEndpoint,
		"revocation":    discovery.RevocationEndpoint,
		"jwks":          discovery.JWKSURI,
	}
	for name, raw := range wantEndpoints {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "auth.fulcrum-labs.com" {
			t.Errorf("%s endpoint = %q", name, raw)
		}
	}
	if !contains(discovery.GrantTypesSupported, "authorization_code") || !contains(discovery.GrantTypesSupported, "refresh_token") || !contains(discovery.CodeChallengeMethodsSupported, "S256") || !contains(discovery.TokenEndpointAuthMethods, "none") || !contains(discovery.TokenEndpointAuthMethods, "client_secret_basic") {
		t.Fatalf("discovery capabilities = %#v", discovery)
	}
}

func TestLiveIssuerJWKSContractReadOnly(t *testing.T) {
	var document jwksDocument
	liveGETJSON(t, liveFulcrumIssuer+"/.well-known/jwks.json", &document)
	if len(document.Keys) == 0 {
		t.Fatal("live JWKS has no keys")
	}
	for _, key := range document.Keys {
		if key.KeyType != "EC" || key.Curve != "P-256" || key.Alg != "ES256" || key.Use != "sig" || key.KeyID == "" {
			t.Errorf("unexpected live JWK shape: kty=%q crv=%q alg=%q use=%q has_kid=%v", key.KeyType, key.Curve, key.Alg, key.Use, key.KeyID != "")
			continue
		}
		if _, err := parseP256Key(key); err != nil {
			t.Errorf("parse live JWK %q: %v", key.KeyID, err)
		}
	}
}

func liveGETJSON(t *testing.T, endpoint string, target any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Skipf("live issuer offline: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", endpoint, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxLiveContractBytes+1))
	if err != nil {
		t.Fatal(fmt.Errorf("read %s: %w", endpoint, err))
	}
	if len(body) > maxLiveContractBytes {
		t.Fatalf("GET %s: response exceeds %d bytes", endpoint, maxLiveContractBytes)
	}
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatal(fmt.Errorf("decode %s: %w", endpoint, err))
	}
}
