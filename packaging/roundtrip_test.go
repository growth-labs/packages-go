package packaging_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/growth-labs/packages-go/packaging"
	"github.com/growth-labs/packages-go/packaging/provenance"
)

func TestArtifactBuildSealCopyAndVerifyRoundTrip(t *testing.T) {
	dist := filepath.Join(t.TempDir(), "dist")
	target := runtime.GOOS + "-" + runtime.GOARCH
	const version = "0.1.0-roundtrip"
	const revision = "4e7f1f4e7b89fd03d85e59b7fd8e4c73a55a87cc"

	command := exec.Command("bash", "scripts/build.sh")
	command.Env = append(os.Environ(),
		"BUILD_TARGETS="+target,
		"DIST_DIR="+dist,
		"PACKAGE_MAIN=./testdata/cmd/sample",
		"PACKAGE_NAME=sample",
		"PACKAGE_VERSION="+version,
		"PACKAGE_REVISION="+revision,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build.sh: %v\n%s", err, output)
	}

	binaryName := "sample-" + target
	binaryPath := filepath.Join(dist, binaryName)
	output, err := exec.Command(binaryPath).Output()
	if err != nil {
		t.Fatal(err)
	}
	var build provenance.Build
	if err := json.Unmarshal(output, &build); err != nil {
		t.Fatal(err)
	}
	if build.Version != version || build.Revision != revision {
		t.Fatalf("provenance = %#v, want version %q revision %q", build, version, revision)
	}
	binaryBytes, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(binaryBytes, []byte(revision)) {
		t.Fatalf("binary does not contain stamped revision %q", revision)
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		fileOutput, err := exec.Command("file", binaryPath).Output()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(fileOutput, []byte("statically linked")) {
			t.Fatalf("file output = %q, want statically linked ELF", fileOutput)
		}
	}
	if bad := verifyChecksumFile(t, dist); bad != 0 {
		t.Fatalf("SHA256SUMS bad files = %d, want 0", bad)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	if _, err := packaging.Seal(context.Background(), dist, packaging.Metadata{
		Version: version, Revision: revision, CreatedAt: createdAt,
	}, privateKey); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{packaging.ManifestName, packaging.SignatureName} {
		info, err := os.Stat(filepath.Join(dist, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", name, info.Mode().Perm())
		}
	}

	roundTrip := filepath.Join(t.TempDir(), "copied")
	copyDirectory(t, dist, roundTrip)
	manifest, err := packaging.Verify(context.Background(), roundTrip, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != version || manifest.Revision != revision || len(manifest.Files) != 2 {
		t.Fatalf("verified manifest = %#v", manifest)
	}
	if bad := verifyChecksumFile(t, roundTrip); bad != 0 {
		t.Fatalf("round-trip SHA256SUMS bad files = %d, want 0", bad)
	}

	if err := os.WriteFile(filepath.Join(roundTrip, binaryName), []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := packaging.Verify(context.Background(), roundTrip, publicKey); err == nil {
		t.Fatal("Verify() accepted a tampered artifact")
	}
}

func verifyChecksumFile(t *testing.T, directory string) int {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("invalid SHA256SUMS line %q", line)
		}
		payload, err := os.ReadFile(filepath.Join(directory, fields[1]))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		if hex.EncodeToString(digest[:]) != fields[0] {
			bad++
		}
	}
	return bad
}

func copyDirectory(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected directory %q in flat artifact", entry.Name())
		}
		sourcePath := filepath.Join(source, entry.Name())
		destinationPath := filepath.Join(destination, entry.Name())
		input, err := os.Open(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		info, err := input.Stat()
		if err != nil {
			input.Close()
			t.Fatal(err)
		}
		output, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			input.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(output, input)
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		if err := firstError(copyErr, closeOutputErr, closeInputErr); err != nil {
			t.Fatal(err)
		}
	}
}

func firstError(errors ...error) error {
	for _, err := range errors {
		if err != nil {
			return fmt.Errorf("copy artifact: %w", err)
		}
	}
	return nil
}
