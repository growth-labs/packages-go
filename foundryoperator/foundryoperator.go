// Package foundryoperator signs and validates FOUNDRY-OPERATOR-V1 operator
// proofs: the canonical-JSON, Ed25519-signed request envelope foundryd's
// operator-proof surface (onlinewire.OperatorProofValue, canonicaljson.
// Canonicalize) requires from every non-bearer caller — the operator Unix
// domain socket, and the public /mcp/token and /kb/context routes on
// foundry.fulcrum-labs.com.
//
// This is the second real use of the signer: fulcrum-labs/quarry's
// adapters/foundry package (CapabilityClient.sign and operatorHTTPClient.
// sign) carried the first, duplicated, implementation. Per this estate's
// shared-capabilities rule ("Behaviour shared by Go services... extract at
// the second real use, never copy"), this package is that extraction —
// quarry's copies are replaced with calls to Sign, not left standing beside
// it. A third, independent reimplementation (in Go or any other language)
// is the exact defect this package exists to prevent: a proof that looks
// well-formed and either fails to verify, or verifies only after
// foundryd's verifier is loosened to tolerate a second byte spelling, at
// which point the credential means something other than what it appears
// to mean. See fulcrum-labs/quarry adapters/foundry/operator_transport.go
// and olympus-control-plane .claude/hooks/shared/kb-transport.mjs (the JS
// twin of this exact wire format) for the two callers this package
// unifies with.
package foundryoperator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Protocol is the fixed protocol identifier a Proof carries.
const Protocol = "FOUNDRY-OPERATOR-V1"

// nonceCharset is the exact alphabet Sign's default nonce generator and
// foundryd's verifier both accept: unpadded base64url.
const nonceCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

// clockSkewBackdate and validityWindow match the window every existing Go
// and JS signer of this protocol uses (quarry's CapabilityClient.sign /
// operatorHTTPClient.sign; kb-transport.mjs's FOUNDRY_PROOF_WINDOW_MS).
// Backdating IssuedAt absorbs clock skew between the signer and foundryd
// without widening the acceptance window past what those callers already
// prove foundryd accepts.
const (
	clockSkewBackdate = time.Second
	validityWindow    = time.Minute
)

// PrincipalKIDPattern is the syntax a principal kid must match: quarry's
// onlineIdentifier, reused unchanged (it also bounds correlation/idempotency
// identifiers there, but principal kids are this package's concern).
var PrincipalKIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// maxSafeInteger bounds the integers canonicalMarshal accepts, matching
// canonicaljson's cross-language safe-integer rule on the Go side.
const maxSafeInteger = int64(1<<53 - 1)

// Proof is the exact JSON shape foundryd's onlinewire.OperatorProofValue
// decodes. Field order here is irrelevant — canonicalMarshal sorts keys —
// but the field set, names and omitempty on NormalizedQuery must stay
// byte-identical to the verifier's expectation.
type Proof struct {
	Protocol        string `json:"protocol"`
	PrincipalKID    string `json:"principalKid"`
	Nonce           string `json:"nonce"`
	IssuedAt        string `json:"issuedAt"`
	ExpiresAt       string `json:"expiresAt"`
	Method          string `json:"method"`
	NormalizedPath  string `json:"normalizedPath"`
	NormalizedQuery string `json:"normalizedQuery,omitempty"`
	BodySHA256      string `json:"bodySha256"`
}

// ValidNonce reports whether nonce matches the length and charset every
// existing signer/verifier of this protocol enforces.
func ValidNonce(nonce string) bool {
	return len(nonce) >= 22 && len(nonce) <= 128 && strings.Trim(nonce, nonceCharset) == ""
}

// RandomNonce returns a fresh 24-byte, base64url-encoded nonce — the
// default nonce source Sign uses when its caller supplies none.
func RandomNonce() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// canonicalMarshal is private to Sign's fixed Proof shape. It preserves
// Quarry's byte-order encoding of those ASCII field names, whose order agrees
// with foundryd's en-US collation. It is NOT a general Foundry request-body
// canonicalizer: arbitrary keys (for example "a" and "B") sort differently.
// encoding/json first applies struct tags and omitempty; the remaining pass
// emits compact JSON without HTML escaping and accepts only safe integers.
func canonicalMarshal(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := appendCanonical(&output, decoded); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func appendCanonical(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		appendJSONString(output, typed)
	case json.Number:
		integer, err := strconv.ParseInt(typed.String(), 10, 64)
		if err != nil || integer < -maxSafeInteger || integer > maxSafeInteger || strconv.FormatInt(integer, 10) != typed.String() {
			return errors.New("canonical JSON number is not a safe integer")
		}
		output.WriteString(typed.String())
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := appendCanonical(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		// This package only ever canonicalizes Proof, whose fixed ASCII
		// field names sort identically under plain codepoint order and
		// foundryd's en-US locale collation. A canonicalizer for arbitrary
		// field names would need the real collation rule instead.
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			appendJSONString(output, key)
			output.WriteByte(':')
			if err := appendCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func appendJSONString(output *bytes.Buffer, value string) {
	const hexDigits = "0123456789abcdef"
	output.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(character)
		case '\b':
			output.WriteString(`\b`)
		case '\f':
			output.WriteString(`\f`)
		case '\n':
			output.WriteString(`\n`)
		case '\r':
			output.WriteString(`\r`)
		case '\t':
			output.WriteString(`\t`)
		default:
			if character < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(hexDigits[byte(character)>>4])
				output.WriteByte(hexDigits[byte(character)&0x0f])
			} else {
				output.WriteRune(character)
			}
		}
	}
	output.WriteByte('"')
}

// Sign builds and signs a FOUNDRY-OPERATOR-V1 proof for one request line
// (method, normalizedPath, normalizedQuery — empty for none) and body
// (nil for none), using key and principalKID as the delegation identity.
// It returns the base64url-encoded canonical proof bytes and the
// base64-standard-encoded Ed25519 signature over them — exactly the
// X-Foundry-Operator-Proof / X-Foundry-Operator-Signature header pair
// foundryd's operator-proof verifier expects.
//
// now is the signing time; nonce, if non-nil, overrides RandomNonce (a
// test seam — production callers pass nil). Sign never returns a token
// past its own expiry and never falls back to an unsigned request: every
// error here is the final answer for that call.
func Sign(key ed25519.PrivateKey, principalKID, method, normalizedPath, normalizedQuery string, body []byte, now time.Time, nonce func() (string, error)) (proof, signature string, err error) {
	if !PrincipalKIDPattern.MatchString(principalKID) {
		return "", "", errors.New("foundryoperator: principal kid is invalid")
	}
	if len(key) != ed25519.PrivateKeySize {
		return "", "", errors.New("foundryoperator: signing key is invalid")
	}
	if nonce == nil {
		nonce = RandomNonce
	}
	nonceValue, err := nonce()
	if err != nil || !ValidNonce(nonceValue) {
		return "", "", errors.New("foundryoperator: nonce is unavailable")
	}
	digest := sha256.Sum256(body)
	signingTime := now.UTC()
	proofBytes, err := canonicalMarshal(Proof{
		Protocol:        Protocol,
		PrincipalKID:    principalKID,
		Nonce:           nonceValue,
		IssuedAt:        signingTime.Add(-clockSkewBackdate).Format(time.RFC3339Nano),
		ExpiresAt:       signingTime.Add(validityWindow).Format(time.RFC3339Nano),
		Method:          method,
		NormalizedPath:  normalizedPath,
		NormalizedQuery: normalizedQuery,
		BodySHA256:      hex.EncodeToString(digest[:]),
	})
	if err != nil {
		return "", "", fmt.Errorf("foundryoperator: encode proof: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(proofBytes), base64.StdEncoding.EncodeToString(ed25519.Sign(key, proofBytes)), nil
}
