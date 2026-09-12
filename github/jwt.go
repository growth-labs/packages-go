package github

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

// parsePrivateKey loads an RSA private key from PEM bytes (PKCS#1 or PKCS#8),
// the shape GitHub Apps issue their key in.
func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errorf(CodeInvalidPrivateKey, "no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errorf(CodeInvalidPrivateKey, "not a PKCS#1 or PKCS#8 RSA key: %v", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errorf(CodeInvalidPrivateKey, "PEM block did not contain an RSA key")
	}
	return key, nil
}

// signAppJWT builds and signs the RS256 App JWT GitHub's App-authentication
// flow requires: {iat, exp, iss} claims, issued a minute in the past to
// tolerate clock skew between this process and GitHub's, and expiring
// within GitHub's 10-minute ceiling.
func signAppJWT(appID int64, key *rsa.PrivateKey, now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": fmt.Sprintf("%d", appID),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", errorf(CodeInvalidConfig, "encode JWT header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", errorf(CodeInvalidConfig, "encode JWT claims: %v", err)
	}
	signingInput := b64URL(headerJSON) + "." + b64URL(claimsJSON)
	digest := sha256Sum(signingInput)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		return "", errorf(CodeInvalidPrivateKey, "sign JWT: %v", err)
	}
	return signingInput + "." + b64URL(signature), nil
}

func b64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256Sum(signingInput string) []byte {
	sum := sha256.Sum256([]byte(signingInput))
	return sum[:]
}
