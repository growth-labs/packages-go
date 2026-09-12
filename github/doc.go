// Package github mints short-lived, narrowly-scoped GitHub App installation
// tokens for Go services. It signs the App JWT, exchanges it for an
// installation access token scoped to exactly the repository and permissions
// an operation needs, caches the result for its remaining lifetime, and
// budgets outbound GitHub API calls (a call cap, duplicate-read rejection,
// and a rate_limit preflight) so a runaway caller cannot exhaust the
// installation's rate limit.
//
// This package is authority-only by design: the App private key is loaded
// once by the caller (from a vault-delivered file, never a GitHub Actions
// secret) and never leaves the process holding it. Token values are never
// logged, printed, or reachable through fmt's default verbs — Token's
// String/GoString methods redact the value; callers read it only through
// Token.Value.
package github
