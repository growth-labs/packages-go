package packaging_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/growth-labs/packages-go/packaging"
)

func sealTestArtifact(t *testing.T, privateKey ed25519.PrivateKey) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "payload.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := packaging.Seal(context.Background(), directory, packaging.Metadata{
		Version: "0.1.0-verify-any", Revision: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		CreatedAt: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC),
	}, privateKey); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestVerifyAnyAcceptsAnyTrustedKey(t *testing.T) {
	currentPublic, currentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	previousPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := sealTestArtifact(t, currentPrivate)

	if _, err := packaging.VerifyAny(context.Background(), directory, currentPublic); err != nil {
		t.Fatalf("VerifyAny with just the signing key: %v", err)
	}
	if _, err := packaging.VerifyAny(context.Background(), directory, previousPublic, currentPublic); err != nil {
		t.Fatalf("VerifyAny with the signing key second in the list: %v", err)
	}
	if _, err := packaging.VerifyAny(context.Background(), directory, currentPublic, previousPublic); err != nil {
		t.Fatalf("VerifyAny with the signing key first in the list: %v", err)
	}
	if _, err := packaging.VerifyAny(context.Background(), directory, unrelatedPublic, previousPublic); err == nil {
		t.Fatal("VerifyAny accepted an artifact with no trusted key in the list")
	}
	if _, err := packaging.VerifyAny(context.Background(), directory); err == nil {
		t.Fatal("VerifyAny accepted an empty key list")
	}
}

func TestVerifyStillAcceptsExactlyOneKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := sealTestArtifact(t, privateKey)

	if _, err := packaging.Verify(context.Background(), directory, publicKey); err != nil {
		t.Fatalf("Verify with the signing key: %v", err)
	}
	if _, err := packaging.Verify(context.Background(), directory, otherPublicKey); err == nil {
		t.Fatal("Verify accepted the wrong key")
	}
}
