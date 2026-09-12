package github

import "time"

// Permissions narrows an installation token grant to exactly the scopes an
// operation needs (GitHub's installation-token endpoint otherwise grants the
// full installation permission set). Keys are GitHub's permission names
// ("contents", "pull_requests", "issues", "checks", ...); values are "read"
// or "write".
type Permissions map[string]string

// clone returns an independent copy so a caller's map cannot be mutated out
// from under a cached Token.
func (p Permissions) clone() Permissions {
	if p == nil {
		return nil
	}
	out := make(Permissions, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// key returns a stable, order-independent identity for p, used as part of
// the token cache key.
func (p Permissions) key() string {
	if len(p) == 0 {
		return ""
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := ""
	for _, k := range keys {
		out += k + "=" + p[k] + ";"
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// Token is a short-lived GitHub installation access token. Its value is
// never reachable through fmt's default verbs (String/GoString redact it) --
// callers read it only through Value, and only to hand it to a child
// process's environment or an HTTP client, never to a log line or a
// capability_runs receipt.
type Token struct {
	value       string
	Repo        string
	Permissions Permissions
	Installation int64
	MintedAt    time.Time
	ExpiresAt   time.Time
}

// Value returns the token's bearer value.
func (t Token) Value() string { return t.value }

// Expired reports whether t is expired (or within skew of expiring) as of now.
func (t Token) Expired(now time.Time, skew time.Duration) bool {
	return !now.Before(t.ExpiresAt.Add(-skew))
}

func (t Token) String() string   { return "github.Token{REDACTED}" }
func (t Token) GoString() string { return t.String() }
