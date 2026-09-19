package email

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bannedPublicContentPatterns are operational values that must never
// appear in this PUBLIC package: real account identifiers and real
// deployment domains, however they got here (a copy-pasted example, a
// fixture, a comment). Reviewer finding PG-37-4: this repo is public, and
// a real Cloudflare account id plus real deployment addresses were
// committed in an example, the README, and test fixtures. New entries in
// this list are deliberately generic account/domain SHAPES, not a list of
// every value ever seen -- anyone adding a real deployment value back
// should extend the list here rather than working around it.
var bannedPublicContentPatterns = []*regexp.Regexp{
	// A bare 32-hex-character string is exactly the shape of a real
	// Cloudflare account id. The one synthetic id this package's own
	// fixtures use ("deadbeef" repeated) is explicitly allowed below.
	regexp.MustCompile(`\b[0-9a-f]{32}\b`),
}

// allowedHexLiterals are 32-hex-character strings this package's own
// fixtures use that are obviously synthetic, not real account ids.
var allowedHexLiterals = map[string]bool{
	"deadbeefdeadbeefdeadbeefdeadbeef": true,
}

func TestPublicSourceCarriesNoOperationalConfiguration(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".md")) {
			continue
		}
		if name == "publiccontent_test.go" {
			continue // this file names the patterns; it is not a source of them
		}
		raw, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		for _, pattern := range bannedPublicContentPatterns {
			for _, match := range pattern.FindAllString(content, -1) {
				if allowedHexLiterals[strings.ToLower(match)] {
					continue
				}
				t.Errorf("%s: %q matches a real-account-id-shaped pattern; use a synthetic placeholder (e.g. the repeated \"deadbeef\" literal) instead", name, match)
			}
		}
		for _, domain := range []string{"fulcrum-labs.com", "fulcrum-portal.com"} {
			if strings.Contains(content, domain) {
				t.Errorf("%s: contains the real deployment domain %q; use example.org/example.net instead", name, domain)
			}
		}
	}
}
