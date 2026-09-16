package packaging_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/growth-labs/packages-go/packaging"
)

// sealOptionalFieldsArtifact seals a minimal one-file artifact, optionally
// populating the three declared-optional Manifest fields (A-09b).
func sealOptionalFieldsArtifact(t *testing.T, privateKey ed25519.PrivateKey, metadata packaging.Metadata) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "payload.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata.Version = "0.1.0-optional-fields"
	metadata.Revision = "cafebabecafebabecafebabecafebabecafebabe"
	metadata.CreatedAt = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	if _, err := packaging.Seal(context.Background(), directory, metadata, privateKey); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestSealWithOptionalFieldsVerifies(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := sealOptionalFieldsArtifact(t, privateKey, packaging.Metadata{
		MainProof: &packaging.MainProof{
			Main: "cafebabecafebabecafebabecafebabecafebabe", Target: "cafebabecafebabecafebabecafebabecafebabe", Status: "identical",
		},
		CIRunID:       424242,
		ToolingSHA256: strings.Repeat("ab", 32),
	})

	manifest, err := packaging.Verify(context.Background(), directory, publicKey)
	if err != nil {
		t.Fatalf("Verify() with optional fields set: %v", err)
	}
	if manifest.MainProof == nil || manifest.MainProof.Status != "identical" {
		t.Fatalf("manifest.MainProof = %#v, want status identical", manifest.MainProof)
	}
	if manifest.CIRunID != 424242 {
		t.Fatalf("manifest.CIRunID = %d, want 424242", manifest.CIRunID)
	}
	if manifest.ToolingSHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("manifest.ToolingSHA256 = %q", manifest.ToolingSHA256)
	}
}

func TestSealWithoutOptionalFieldsOmitsThemAndVerifies(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := sealOptionalFieldsArtifact(t, privateKey, packaging.Metadata{})

	raw, err := os.ReadFile(filepath.Join(directory, packaging.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"mainProof"`, `"ciRunId"`, `"toolingSHA256"`} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("manifest.json unexpectedly contains %s when unset: %s", key, raw)
		}
	}

	manifest, err := packaging.Verify(context.Background(), directory, publicKey)
	if err != nil {
		t.Fatalf("Verify() of a manifest sealed without the optional fields: %v", err)
	}
	if manifest.MainProof != nil || manifest.CIRunID != 0 || manifest.ToolingSHA256 != "" {
		t.Fatalf("manifest optional fields = %#v, %v, %q, want all absent",
			manifest.MainProof, manifest.CIRunID, manifest.ToolingSHA256)
	}
}

// tamperManifestField rewrites directory/manifest.json with one top-level
// field replaced, leaving the detached signature file untouched, so the
// stale signature no longer authenticates the rewritten bytes if and only if
// that field was actually part of what got signed.
func tamperManifestField(t *testing.T, directory, key string, value any) {
	t.Helper()
	path := filepath.Join(directory, packaging.ManifestName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields[key] = value
	tampered, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTamperedMainProof(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := sealOptionalFieldsArtifact(t, privateKey, packaging.Metadata{
		MainProof: &packaging.MainProof{
			Main: "cafebabecafebabecafebabecafebabecafebabe", Target: "cafebabecafebabecafebabecafebabecafebabe", Status: "identical",
		},
	})
	tamperManifestField(t, directory, "mainProof", map[string]string{
		"main": "cafebabecafebabecafebabecafebabecafebabe", "target": "cafebabecafebabecafebabecafebabecafebabe", "status": "ahead",
	})
	if _, err := packaging.Verify(context.Background(), directory, publicKey); err == nil {
		t.Fatal("Verify() accepted a manifest with a tampered mainProof")
	}
}

func TestVerifyRejectsTamperedCIRunID(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := sealOptionalFieldsArtifact(t, privateKey, packaging.Metadata{CIRunID: 111})
	tamperManifestField(t, directory, "ciRunId", 999)
	if _, err := packaging.Verify(context.Background(), directory, publicKey); err == nil {
		t.Fatal("Verify() accepted a manifest with a tampered ciRunId")
	}
}

func TestVerifyRejectsTamperedToolingSHA256(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := sealOptionalFieldsArtifact(t, privateKey, packaging.Metadata{
		ToolingSHA256: strings.Repeat("ab", 32),
	})
	tamperManifestField(t, directory, "toolingSHA256", strings.Repeat("cd", 32))
	if _, err := packaging.Verify(context.Background(), directory, publicKey); err == nil {
		t.Fatal("Verify() accepted a manifest with a tampered toolingSHA256")
	}
}
