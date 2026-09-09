package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// The issuer preserves existing UUID identities and generates uppercase ULIDs for
// new identities. Accept RFC-variant UUID versions 1–8 without normalizing their
// text: validateClaims still requires exact subject/property identity binding.
var userSubjectPattern = regexp.MustCompile(`^user:([0-7][0-9A-HJKMNP-TV-Z]{25}|(?i:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}))$`)

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type tokenClaims struct {
	Issuer     string        `json:"iss"`
	Subject    string        `json:"sub"`
	Audience   audienceClaim `json:"aud"`
	Mode       string        `json:"mode"`
	Type       string        `json:"type"`
	Roles      []string      `json:"roles"`
	IssuedAt   *int64        `json:"iat"`
	NotBefore  *int64        `json:"nbf"`
	ExpiresAt  *int64        `json:"exp"`
	Properties struct {
		UserID string `json:"userId"`
		Email  string `json:"email"`
		Name   string `json:"name"`
		Image  string `json:"image"`
	} `json:"properties"`
}

type audienceClaim []string

func (a *audienceClaim) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("aud must be a string or string array")
	}
	*a = many
	return nil
}

// Verify validates an ES256 access token and returns its typed principal.
func (c *Client) Verify(ctx context.Context, token string) (Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Principal{}, errorf(CodeInvalidToken, "JWT must contain three segments")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Principal{}, errorf(CodeInvalidToken, "decode JWT header: %v", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Algorithm != "ES256" || header.KeyID == "" {
		return Principal{}, errorf(CodeInvalidToken, "JWT header is not an ES256 keyed signature")
	}
	key, err := c.signingKey(ctx, header.KeyID)
	if err != nil {
		return Principal{}, err
	}
	if err := verifyES256(key, parts[0]+"."+parts[1], parts[2]); err != nil {
		return Principal{}, errorf(CodeInvalidSignature, "verify JWT signature: %v", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Principal{}, errorf(CodeInvalidToken, "decode JWT payload: %v", err)
	}
	var claims tokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return Principal{}, errorf(CodeInvalidToken, "decode JWT claims: %v", err)
	}
	return c.validateClaims(claims)
}

func verifyES256(key *ecdsa.PublicKey, signingInput, encodedSignature string) error {
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || len(signature) != 64 {
		return fmt.Errorf("ES256 signature must be 64 bytes")
	}
	digest := sha256.Sum256([]byte(signingInput))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func (c *Client) validateClaims(claims tokenClaims) (Principal, error) {
	if claims.Issuer != c.config.Issuer {
		return Principal{}, errorf(CodeWrongIssuer, "access token issuer does not match")
	}
	if !contains([]string(claims.Audience), c.config.Resource) {
		return Principal{}, errorf(CodeWrongAudience, "access token audience does not match")
	}
	if claims.Mode != "access" || claims.Type != "user" || claims.ExpiresAt == nil || claims.IssuedAt == nil {
		return Principal{}, errorf(CodeInvalidToken, "required access token claims are missing")
	}
	now := c.config.Now()
	skew := c.config.ClockSkew
	if now.After(time.Unix(*claims.ExpiresAt, 0).Add(skew)) {
		return Principal{}, errorf(CodeTokenExpired, "access token is expired")
	}
	if claims.NotBefore != nil && now.Add(skew).Before(time.Unix(*claims.NotBefore, 0)) {
		return Principal{}, errorf(CodeTokenNotYetValid, "access token is not active")
	}
	if now.Add(skew).Before(time.Unix(*claims.IssuedAt, 0)) {
		return Principal{}, errorf(CodeTokenIssuedInFuture, "access token was issued in the future")
	}
	match := userSubjectPattern.FindStringSubmatch(claims.Subject)
	if len(match) != 2 || match[1] != claims.Properties.UserID || claims.Properties.Email == "" {
		return Principal{}, errorf(CodeInvalidToken, "access token identity claims are inconsistent")
	}
	return Principal{
		Subject:   claims.Subject,
		UserID:    claims.Properties.UserID,
		Email:     claims.Properties.Email,
		Name:      claims.Properties.Name,
		Image:     claims.Properties.Image,
		Roles:     append([]string(nil), claims.Roles...),
		Audiences: append([]string(nil), claims.Audience...),
	}, nil
}
