package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const maxJWKSBytes = 1 << 20

type jwksCache struct {
	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	Alg     string `json:"alg"`
	Use     string `json:"use"`
	KeyID   string `json:"kid"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

func (c *Client) signingKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	c.jwks.mu.Lock()
	defer c.jwks.mu.Unlock()

	now := c.config.Now()
	key, present := c.jwks.keys[kid]
	fresh := present && now.Sub(c.jwks.fetchedAt) <= c.config.JWKSCacheTTL
	if fresh {
		return key, nil
	}

	keys, err := c.fetchJWKS(ctx)
	if err == nil {
		c.jwks.keys = keys
		c.jwks.fetchedAt = now
		if key := keys[kid]; key != nil {
			return key, nil
		}
		return nil, errorf(CodeInvalidSignature, "token key ID is not published")
	}
	if present {
		return key, nil
	}
	return nil, errorf(CodeJWKSUnavailable, "fetch signing keys: %v", err)
}

func (c *Client) fetchJWKS(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.IssuerInternal+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	response, err := c.config.HTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("JWKS endpoint returned %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxJWKSBytes))
	var document jwksDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]*ecdsa.PublicKey)
	for _, value := range document.Keys {
		if value.KeyType != "EC" || value.Curve != "P-256" || value.Alg != "ES256" || (value.Use != "" && value.Use != "sig") || value.KeyID == "" {
			continue
		}
		key, err := parseP256Key(value)
		if err != nil {
			return nil, fmt.Errorf("parse JWKS key %q: %w", value.KeyID, err)
		}
		keys[value.KeyID] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no ES256 signing keys")
	}
	return keys, nil
}

func parseP256Key(value jwk) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(value.X)
	if err != nil {
		return nil, fmt.Errorf("decode x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(value.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y coordinate: %w", err)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	curve := elliptic.P256()
	if len(xBytes) == 0 || len(yBytes) == 0 || !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("coordinates are not on P-256")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
