package email

import (
	"fmt"
	"os"
	"strings"
)

// LoadTokenFile reads a Cloudflare Email Sending API token from a
// mode-0600 file holding exactly one non-empty line -- the estate's
// convention for a single-value operational secret on a service host
// (for example /etc/myservice/secrets/cloudflare-email.token).
//
// The mode check is a guard, not a formality: a token readable by every
// account on the host is the same failure as a token in the repository.
// It is proven falsifiable in guards_test.go.
func LoadTokenFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("email: secret file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("email: inspect secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("email: secret file %s is not a regular file", path)
	}
	if info.Mode().Perm() != 0o600 {
		return "", fmt.Errorf("email: secret file %s mode is %04o, want 0600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("email: read secret file: %w", err)
	}
	value := strings.TrimRight(string(raw), "\r\n")
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("email: secret file %s must contain exactly one non-empty line", path)
	}
	return value, nil
}
