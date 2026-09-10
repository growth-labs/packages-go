package email

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTokenFile(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fastmail.token")
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadTokenFile(t *testing.T) {
	path := writeTokenFile(t, "fm1-abc123\n", 0o600)
	token, err := LoadTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if token != "fm1-abc123" {
		t.Fatalf("token = %q", token)
	}
}

func TestLoadTokenFileRejectsWrongMode(t *testing.T) {
	path := writeTokenFile(t, "fm1-abc123\n", 0o644)
	if _, err := LoadTokenFile(path); err == nil {
		t.Fatal("LoadTokenFile accepted a 0644 file")
	}
}

func TestLoadTokenFileRejectsMultipleLines(t *testing.T) {
	path := writeTokenFile(t, "fm1-abc123\nextra\n", 0o600)
	if _, err := LoadTokenFile(path); err == nil {
		t.Fatal("LoadTokenFile accepted a multi-line file")
	}
}

func TestLoadTokenFileRejectsEmptyFile(t *testing.T) {
	path := writeTokenFile(t, "\n", 0o600)
	if _, err := LoadTokenFile(path); err == nil {
		t.Fatal("LoadTokenFile accepted an empty file")
	}
}

func TestLoadTokenFileRejectsEmptyPathAndMissingFile(t *testing.T) {
	if _, err := LoadTokenFile(""); err == nil {
		t.Fatal("LoadTokenFile accepted an empty path")
	}
	if _, err := LoadTokenFile(filepath.Join(t.TempDir(), "absent.token")); err == nil {
		t.Fatal("LoadTokenFile accepted a missing file")
	}
}

func TestLoadTokenFileRejectsSymlinkToAWorldReadableFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.token")
	if err := os.WriteFile(target, []byte("fm1-abc123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.token")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := LoadTokenFile(link); err == nil {
		t.Fatal("LoadTokenFile followed a symlink instead of refusing a non-regular path")
	}
}
