# github

Go client for minting short-lived, narrowly-scoped GitHub App installation
tokens. It signs the App JWT, exchanges it for an installation access token
scoped to exactly the repository and permissions the caller asked for, caches
the result for its remaining lifetime, and budgets outbound GitHub API calls
so a runaway or looping caller cannot exhaust the installation's rate limit.

This module is authority-only by design (WH-05b, `fulcrum-labs/foundry`'s
maintenance control loop): the App private key is loaded once, from a
vault-delivered file, by the process that holds the authority role, and never
leaves it. A runner or an interactive shim never holds the key -- it receives
a minted token through the existing secret handoff / the operator API, not
this package directly.

## Install

```sh
go get github.com/growth-labs/packages-go/github
```

## Use

```go
client, err := github.New(github.Config{
    AppID:         appID,
    PrivateKeyPEM: privateKeyPEM, // loaded from vault, never a repo secret
})
if err != nil {
    // CodeInvalidConfig or CodeInvalidPrivateKey -- a setup error, not transient.
}

token, err := client.MintInstallationToken(ctx, installationID, "platform-foundations", github.Permissions{
    "contents":      "write",
    "pull_requests": "write",
})
if err != nil {
    switch {
    case github.IsCode(err, github.CodeRateLimited):
        // back off; do not retry immediately
    case github.IsCode(err, github.CodeDuplicateRead):
        // an identical mint was already attempted inside the dedupe window
        // and no live token is cached for it (a cache hit is served before
        // this check ever runs) -- wait out the window rather than
        // retrying immediately; a failed attempt clears its own dedupe
        // entry, so this fires only for a caller's own repeated/looping
        // request, never as a side effect of a prior transient failure
    }
    return err
}
// token.Value() goes into the child process's environment (e.g. GITHUB_TOKEN)
// or an HTTP client's Authorization header. It is never logged, printed, or
// placed in a capability_runs receipt -- Token's String/GoString redact it.
defer useToken(token.Value())
```

## Design

- **Permissions are mandatory and narrow.** `MintInstallationToken` refuses an
  empty `Permissions` map (`CodeInvalidPermissions`) rather than falling back
  to GitHub's default of granting the installation's full permission set.
- **A budgeted client, not an unbounded one.** `Config.CallBudget` bounds
  total outbound calls per `Client` (default 500); `Config.DedupeWindow`
  rejects an identical mint (same installation, repo, permission set) made
  again within the window (default 5 minutes, `CodeDuplicateRead`); a
  `rate_limit` preflight refuses a call outright once the last observed
  `X-RateLimit-Remaining` drops below `Config.RateLimitFloor` (default 50,
  `CodeRateLimited`) rather than spending an installation's last headroom.
  This shape is not hypothetical: the equivalent duplicate-read guard on a
  GitHub-reads budget was hit live in production during the WH-05b PHASE 0
  research, on an unrelated PR.
- **Two-class error taxonomy.** Every error is a `*github.Error` carrying a
  stable `Code`; `Code.Class()` reports `"configuration"` (a setup problem,
  never retryable without a config change: bad key, bad app id, unknown
  installation, missing permissions) or `"transport"` (the call itself
  failed: network error, rate limit, budget exhaustion, an unexpected
  response -- retryable through a controlled remint, never papered over with
  an ambient token fallback).
- **Tokens never leak into observability.** `Token.String()`/`GoString()`
  redact the value; the only way to read it is `Token.Value()`, an explicit
  accessor a caller has to reach for on purpose.
- **No third-party dependencies.** The App JWT (RS256) is signed with
  `crypto/rsa`/`crypto/x509` from the standard library, matching this
  repo's other modules' zero-dependency posture (`auth` ships its own ES256
  verification the same way).

## Not this package's job

Minting a token for a runner's own use (rather than the authority's) --
WH-05b's design keeps the App private key on the authority only; a runner
receives a minted token through the runner protocol's existing secret
handoff or the operator API's `POST /github/installation-token` route
(EdDSA-proof-gated, per-principal owner allowlist), never this package
directly. Building that route and the runner-side handoff is the
consuming PR's job, not this module's.
