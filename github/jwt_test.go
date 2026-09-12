package github

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// decodeAppJWT splits and decodes a signed App JWT's header and claims
// segments (base64url, no padding) without verifying its signature.
func decodeAppJWT(t *testing.T, token string) (header map[string]any, claims map[string]any) {
	t.Helper()
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		t.Fatalf("token has %d segments, want 3", len(segments))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		t.Fatalf("decode header segment: %v", err)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatalf("decode claims segment: %v", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return header, claims
}

func TestSignAppJWTProducesTheExactClaimsGitHubRequires(t *testing.T) {
	key, err := parsePrivateKey(testKeyPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	token, err := signAppJWT(424242, key, now)
	if err != nil {
		t.Fatalf("signAppJWT: %v", err)
	}
	header, claims := decodeAppJWT(t, token)

	if header["alg"] != "RS256" {
		t.Fatalf("alg = %v, want RS256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Fatalf("typ = %v, want JWT", header["typ"])
	}
	if got, want := claims["iss"], strconv.Itoa(424242); got != want {
		t.Fatalf("iss = %v, want %v", got, want)
	}
	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatalf("iat is not numeric: %v", claims["iat"])
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp is not numeric: %v", claims["exp"])
	}
	if got, want := int64(now.Unix())-int64(iat), int64(60); got != want {
		t.Fatalf("now - iat = %ds, want exactly %ds of clock-skew tolerance", got, want)
	}
	if got, want := int64(exp)-int64(iat), int64(600); got != want {
		t.Fatalf("exp - iat = %ds, want %ds (GitHub's 10 minute ceiling)", got, want)
	}

	// The signature must actually verify against the signing key's public
	// half -- a claim/header change without a re-sign, or a swapped
	// algorithm, must not go unnoticed by this test.
	segments := strings.Split(token, ".")
	signingInput := segments[0] + "." + segments[1]
	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		t.Fatalf("decode signature segment: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sha256Sum(signingInput), signature); err != nil {
		t.Fatalf("signature does not verify against the signing key's public half: %v", err)
	}
}

func TestSignAppJWTRejectsAnInvalidKeyAtSigningTime(t *testing.T) {
	// A key with a zero modulus cannot sign; this exercises the
	// CodeInvalidPrivateKey wrapping path in signAppJWT itself, distinct
	// from parsePrivateKey's own PEM-decoding failures already covered by
	// TestNewRejectsAMalformedPrivateKey.
	broken := &rsa.PrivateKey{}
	if _, err := signAppJWT(1, broken, time.Now()); err == nil {
		t.Fatal("signing with an unusable key was accepted")
	}
}
