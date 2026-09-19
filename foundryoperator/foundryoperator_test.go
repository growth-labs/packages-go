package foundryoperator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestCanonicalMarshalSortsKeysAndOmitsWhitespace(t *testing.T) {
	got, err := CanonicalMarshal(map[string]any{"b": 1, "a": "x", "c": true})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":"x","b":1,"c":true}` {
		t.Fatalf("got %q", got)
	}
}

func TestCanonicalMarshalEscapesControlAndPassesUnicode(t *testing.T) {
	got, err := CanonicalMarshal(map[string]any{"s": "line\nbreak\ttab\x01ctrl\"quote\\back é 日"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"s":"line\nbreak\ttab\u0001ctrl\"quote\\back é 日"}`
	if string(got) != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestCanonicalMarshalRejectsUnsafeInteger(t *testing.T) {
	// 2^53, one past the largest safe integer.
	if _, err := CanonicalMarshal(map[string]any{"n": int64(1) << 53}); err == nil {
		t.Fatal("expected an error for an unsafe integer, got nil")
	}
}

func TestCanonicalMarshalOmitsEmptyOmitemptyField(t *testing.T) {
	got, err := CanonicalMarshal(Proof{Protocol: Protocol, NormalizedQuery: ""})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "normalizedQuery") {
		t.Fatalf("empty NormalizedQuery must be omitted from the canonical bytes; got %q", got)
	}
}

func TestValidNonce(t *testing.T) {
	cases := []struct {
		name  string
		nonce string
		want  bool
	}{
		{"too short", strings.Repeat("a", 21), false},
		{"too long", strings.Repeat("a", 129), false},
		{"min length", strings.Repeat("a", 22), true},
		{"max length", strings.Repeat("a", 128), true},
		{"bad character", strings.Repeat("a", 21) + "!", false},
		{"underscore and hyphen allowed", strings.Repeat("a", 20) + "_-", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ValidNonce(c.nonce); got != c.want {
				t.Fatalf("ValidNonce(%q)=%v, want %v", c.nonce, got, c.want)
			}
		})
	}
}

func TestRandomNonceIsValid(t *testing.T) {
	nonce, err := RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidNonce(nonce) {
		t.Fatalf("RandomNonce produced an invalid nonce: %q", nonce)
	}
}

// TestSignMatchesTheExactCanonicalWireFormat is a fixed-input fixture: the
// expected canonical proof bytes are built independently (a literal string,
// not through CanonicalMarshal), so this catches any drift in field
// set/order/encoding from the format foundryd's canonicaljson.Canonicalize
// and the JS twin (kb-transport.mjs canonicalizeJson) both produce.
func TestSignMatchesTheExactCanonicalWireFormat(t *testing.T) {
	// Public test seed; the pinned signature was independently produced by
	// Node crypto.sign over the literal proof below, not by Sign.
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	body := []byte(`{"profile":"kb"}`)
	digest := sha256.Sum256(body)
	fixedNonce := "test-nonce-0123456789AB"
	now := time.Date(2026, 9, 19, 8, 0, 0, 0, time.UTC)

	proofB64, sigB64, err := Sign(priv, "cockpit-hub-test", "POST", "/mcp/token", "", body, now,
		func() (string, error) { return fixedNonce, nil })
	if err != nil {
		t.Fatal(err)
	}

	wantProof := `{"bodySha256":"` + hex.EncodeToString(digest[:]) +
		`","expiresAt":"2026-09-19T08:01:00Z","issuedAt":"2026-09-19T07:59:59Z","method":"POST",` +
		`"nonce":"` + fixedNonce + `","normalizedPath":"/mcp/token","principalKid":"cockpit-hub-test","protocol":"FOUNDRY-OPERATOR-V1"}`

	proofBytes, err := base64.RawURLEncoding.DecodeString(proofB64)
	if err != nil {
		t.Fatal(err)
	}
	if string(proofBytes) != wantProof {
		t.Fatalf("proof bytes\ngot  %s\nwant %s", proofBytes, wantProof)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, proofBytes, sigBytes) {
		t.Fatal("signature does not verify against the canonical proof bytes")
	}
	const wantSignature = "PZmsHOVK7E1tj/bKVcozDwZ3aamXgchnMKsWpslz6aXYOc/KUqRdW7l3gXcE4auaIR0cwlt+Z9sbeupv5vuIAA=="
	if sigB64 != wantSignature {
		t.Fatalf("signature header got %q, want %q", sigB64, wantSignature)
	}
}

func TestSignIncludesNormalizedQueryWhenPresent(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	proofB64, _, err := Sign(priv, "cockpit-hub-test", "GET", "/kb/context", "project=cockpit&scope=fulcrum-labs", nil,
		time.Now(), func() (string, error) { return strings.Repeat("q", 24), nil })
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, err := base64.RawURLEncoding.DecodeString(proofB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(proofBytes, []byte(`"normalizedQuery":"project=cockpit&scope=fulcrum-labs"`)) {
		t.Fatalf("expected normalizedQuery in the signed proof; got %s", proofBytes)
	}
}

func TestSignRejectsInvalidPrincipalKID(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sign(priv, "not a valid kid!", "GET", "/x", "", nil, time.Now(), nil); err == nil {
		t.Fatal("expected an error for an invalid principal kid, got nil")
	}
}

func TestSignRejectsWrongSizeKey(t *testing.T) {
	if _, _, err := Sign(make([]byte, 5), "valid-kid", "GET", "/x", "", nil, time.Now(), nil); err == nil {
		t.Fatal("expected an error for a wrong-size key, got nil")
	}
}

func TestSignRejectsUnavailableNonce(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sign(priv, "valid-kid", "GET", "/x", "", nil, time.Now(),
		func() (string, error) { return "too-short", nil }); err == nil {
		t.Fatal("expected an error for an invalid nonce, got nil")
	}
}

func TestSignDefaultsToRandomNonce(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sign(priv, "valid-kid", "GET", "/x", "", nil, time.Now(), nil); err != nil {
		t.Fatalf("Sign with a nil nonce func should fall back to RandomNonce, got error: %v", err)
	}
}
