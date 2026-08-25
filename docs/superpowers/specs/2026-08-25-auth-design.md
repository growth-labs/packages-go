# Go OpenAuth Consumer Design

## Goal

Add `github.com/growth-labs/packages-go/auth`, the app-agnostic Go consumer for
the Growth Labs OpenAuth issuer. It must construct the same OAuth requests,
enforce the same token and session boundaries, and expose the same fail-closed
behavior as `@growth-labs/auth` without carrying over Astro-specific machinery.

## Verified contract

- The package repository is private, uses one Go module per top-level directory,
  and declares Go 1.26.0 with toolchain 1.26.6. Hermes currently runs 1.26.7.
- `auth.fulcrum-labs.com` currently publishes OAuth discovery and four parseable
  P-256 ES256 signing keys.
- Identity-platform PR #159 publishes consumer fixtures at commit
  `75b4960f97cd2a5b65bd17a890be973ca555b3c7`; the fixture set is not on issuer
  `main` yet, despite the lane brief implying it may already have landed.
- `fulcrum-projects` is a public PKCE client. Migration 0031 exact-matches two
  callbacks and permits two resources: `https://projects.fulcrum-labs.com` and
  `http://localhost:4321`.
- Access tokens are ES256 JWTs with `mode=access`, a resource-backed `aud`, a
  `user:<ULID>` subject, roles, and identity fields under `properties.*`.
- Access tokens live 900 seconds, refresh tokens 2,592,000 seconds, and refresh
  reuse is accepted through 600 seconds. Reuse after that boundary returns
  `invalid_grant` without invalidating the successor chain.

## Public API

`New(Config) (*Client, error)` validates immutable client configuration. Config
contains browser and optional internal issuer URLs, client ID, optional
`SecretSource`, resource, callback path, cookie prefix/domain, providers, gated
paths, login/logout destinations, HTTP transport, clock, clock skew, and JWKS
cache TTL.

The callback URI and original transaction expiry are stored in host-only
transaction cookies so HTTP localhost callbacks preserve the exact authorized
redirect URI and callback reconstruction cannot silently renew an expired
transaction. Session-cookie domain sharing never widens transaction-cookie
scope. Middleware bypasses login, callback, and logout routes so logout cannot
rotate a token immediately before revoking it.

`Client.Authorize(origin, provider, redirectPath)` returns the browser redirect
URL plus a `Transaction` containing the PKCE verifier, state, provider, redirect
path, callback URI, and expiry. `email-code` is translated to issuer provider
`code`. The request always carries PKCE S256 and RFC 8707 `resource`.

`Client.Exchange(ctx, ExchangeRequest)` verifies callback state at the public
wiring point, resolves any confidential secret before issuer I/O, sends the
authorization-code form, uses `client_secret_basic` when configured, verifies
the returned access token, and returns `Tokens` plus `Principal`.

`Client.Verify(ctx, token)` verifies ES256 signatures against a cached JWKS. An
unknown `kid` or expired cache causes a refetch; a transient refetch failure may
use a previous cache. Verification requires `iss`, exact `aud`, `mode=access`,
`exp`, bounded `nbf`/`iat`, and a consistent `sub`/`properties.userId` pair.

`Client.Refresh`, `Client.Revoke`, cookie helpers, callback/logout handlers, and
`Client.Middleware` complete the HTTP surface. Middleware resolves a principal,
silently refreshes once, redirects unauthenticated gated paths, serves public
paths anonymously on ordinary issuer/JWKS failure, and returns a fixed no-store
503 if a configured secret cannot be resolved before refresh/revocation I/O.

`Principal` exposes raw `Subject`, stripped `UserID`, email, optional name/image,
roles, and audiences. `PrincipalFromContext` is the consumer boundary.

Errors use a bounded `Error` with stable `Code` values so consumers can test or
map failures without inspecting issuer text. No secret value is included in an
error, response, log, fixture, or example.

## Package boundaries

- `config.go`, `errors.go`, and `types.go`: public configuration and values.
- `authorize.go`: random state, PKCE, and authorization URL construction.
- `tokens.go`: exchange, refresh, revoke, OAuth error parsing, and secret use.
- `verify.go` and `jwks.go`: JWT parsing/validation and cached P-256 JWKS.
- `cookies.go`: transaction/session cookie read, write, and clearing.
- `http.go`: callback, logout, middleware, gating, and context principal.
- `conformance_test.go`: versioned issuer fixture runner through `testkit`.
- `contract_test.go`: read-only live discovery/JWKS probes that skip offline.
- `roundtrip_test.go`: fake-issuer authorize/callback/verify/refresh/reuse/logout.
- `cmd/example`: minimal standard-library server using the public API.

The implementation uses the standard library for HTTP, JSON, SHA-256, ECDSA,
and cookies. `testkit` is the only module dependency and is test-only.

## Error and failure behavior

Invalid or missing state, missing PKCE verifier, token endpoint refusal,
signature failure, wrong issuer/audience, expiry, future `nbf`/`iat`, and
inconsistent subject claims return bounded errors. The callback handler clears
transaction cookies on terminal success and redirects to the stored local path.
Logout always clears local cookies; secret failure prevents remote revocation
and returns 503, while ordinary revocation network failure is returned to the
direct API and ignored by the logout handler after local cleanup.

Redirect paths are restricted to same-origin path references. Absolute or
scheme-relative values collapse to `/` to avoid open redirects.

## Test strategy

Each behavior is introduced red-green. Guard proofs use `testkit.ProveGuard` at
the public wiring point. The mutation branch changes only the named guard input
or fake-issuer guard, proving unrelated failures cannot make the test green.
The fixture runner embeds the exact PR #159 JSON snapshot and validates request,
response, claim, and reuse invariants. Live tests perform only GET requests.

Local execution follows the fleet convention: run only the one explicit test
file currently being edited. The managed CI fleet runs vet, race tests, and
cross-builds for the complete workspace.

## Self-review

The design contains no placeholders. It keeps issuer-side refresh and PKCE
guards in the fake issuer rather than pretending the consumer can enforce them,
and keeps Astro renderers, analytics, password UI, and identity cookies out of
the Go module because the brief explicitly excludes TypeScript-only machinery.
