package packaging

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestVerifyAuthenticatesTheBytesOnDiskAndNeverReMarshals pins the property
// the whole envelope rests on: Verify authenticates the manifest file's exact
// bytes, and never re-derives them.
//
// That is what makes the envelope safe across producers and across Go
// versions. A sealer in another language, or a future Go whose json package
// spaces or escapes differently, can emit different-but-valid JSON and its
// artifacts still verify, because the verifier checks the literal file rather
// than comparing against its own re-marshalling.
//
// It also means there is deliberately NO canonical-JSON specification here,
// and none is needed. If Verify is ever "tidied up" to re-marshal and
// compare, that stops being true immediately and silently: Go's encoding/json
// HTML-escapes <, > and & by default, so every manifest whose revision,
// version or attestation content contains one of those three characters would
// fail to verify, while everything else kept working. That is a miserable
// class of bug -- intermittent, content-dependent, and invisible in review --
// so this test exists to make the refactor that introduces it fail loudly.
//
// The three characters are the test's whole point. Do not "simplify" the
// fixture to a plain string.
func TestVerifyAuthenticatesTheBytesOnDiskAndNeverReMarshals(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "payload"), []byte("artifact bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Every field Go would HTML-escape, in the places a real release puts
	// free-form text.
	escapable := `a<b>c&d`
	if _, err := Seal(context.Background(), directory, Metadata{
		Version: escapable, Revision: escapable, CreatedAt: time.Now().UTC(),
		MainProof:     &MainProof{Main: escapable, Target: escapable, Status: "identical"},
		ToolingSHA256: escapable,
	}, private); err != nil {
		t.Fatalf("seal a manifest containing <>&: %v", err)
	}

	manifest, err := Verify(context.Background(), directory, public)
	if err != nil {
		t.Fatalf("a manifest containing <>& did not verify: %v", err)
	}
	for name, got := range map[string]string{
		"revision":      manifest.Revision,
		"version":       manifest.Version,
		"toolingSHA256": manifest.ToolingSHA256,
	} {
		if got != escapable {
			t.Errorf("%s round-tripped as %q, want %q", name, got, escapable)
		}
	}
	if manifest.MainProof == nil || manifest.MainProof.Main != escapable {
		t.Errorf("mainProof did not round-trip: %+v", manifest.MainProof)
	}

	// The signature must authenticate the file as written. Re-reading it and
	// verifying again is the same operation Verify performs, and it must not
	// depend on anything the caller re-derives.
	onDisk, err := os.ReadFile(filepath.Join(directory, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	signatureText, err := os.ReadFile(filepath.Join(directory, SignatureName))
	if err != nil {
		t.Fatal(err)
	}
	signature := decodeBase64(t, string(signatureText))
	if !ed25519.Verify(public, onDisk, signature) {
		t.Fatal("the detached signature does not authenticate the manifest file's own bytes")
	}

	// And a single byte changed anywhere in that file breaks it, which is
	// what "authenticates the bytes" has to mean.
	tampered := append([]byte(nil), onDisk...)
	tampered[len(tampered)/2] ^= 0x01
	if ed25519.Verify(public, tampered, signature) {
		t.Fatal("the signature authenticated modified manifest bytes")
	}
	if strings.Count(string(onDisk), "\n") > 1 {
		t.Log("note: the manifest is multi-line; nothing depends on that, but a formatting change is a signature change")
	}
}

func decodeBase64(t *testing.T, text string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
