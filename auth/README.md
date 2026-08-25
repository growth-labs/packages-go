# auth

Go consumer for the Growth Labs OpenAuth issuer. It constructs authorization
requests, exchanges and refreshes tokens, verifies ES256 JWTs, manages secure
session cookies, and resolves an optional principal in `net/http` middleware.

This module is identity plumbing, not application authorization. Consumers own
membership walls, local roles, entitlements, and product access decisions.

## Install

This repository is private:

```sh
go env -w GOPRIVATE=github.com/growth-labs/*
go get github.com/growth-labs/packages-go/auth@v0.1.0
```

## Configure

Fulcrum Projects production configuration:

```go
client, err := auth.New(auth.Config{
    Issuer:       "https://auth.fulcrum-labs.com",
    ClientID:     "fulcrum-projects",
    Resource:     "https://projects.fulcrum-labs.com",
    CallbackPath: "/api/auth/callback",
    CookiePrefix: "fulcrum_projects",
    Providers:    []string{"google", "password", "email-code"},
    GatedPaths:   []string{"/app/*", "/api/v2/*"},
    LoginPath:    "/login",
    LogoutPath:   "/logout",
})
if err != nil {
    log.Fatal(err)
}
```

The registered local callback is
`http://localhost:4321/api/auth/callback` and its registered local resource is
`http://localhost:4321`. Resource and callback values are exact matches, so use
the environment's pair together.

`IssuerInternal` may name a back-channel issuer address. Browser authorization
still uses `Issuer`; token, JWKS, refresh, and revocation requests use
`IssuerInternal`. JWT `iss` always matches the browser-facing `Issuer`.

Confidential consumers provide a request-time resolver:

```go
ClientSecret: auth.SecretSourceFunc(func(ctx context.Context) (string, error) {
    return secrets.Resolve(ctx, "AUTH_CLIENT_SECRET")
}),
```

The resolver runs before issuer/JWKS I/O on a request carrying a refresh token.
An empty or failed resolution returns the fixed `auth_service_unavailable`
failure and never reflects the secret or resolver error.

## OAuth Flow Summary

1. The login handler calls `Authorize`. The module creates 32 random bytes each
   for state and PKCE verifier, derives the S256 challenge, includes the provider
   and RFC 8707 `resource`, and returns the issuer redirect plus a transaction.
2. The handler persists the transaction with `SetTransactionCookies` and sends
   the browser to the returned URL.
3. The callback route calls `Callback`. It reads the transaction, compares state
   in constant time, sends the code, verifier, callback, client ID, and resource
   to `/token`, and uses `client_secret_basic` when a secret source is configured.
4. Every returned access token is verified against cached issuer JWKS before
   session cookies are written. The handler clears transaction cookies and
   redirects only to the stored local path.
5. `Middleware` reads `{cookiePrefix}_at` and `{cookiePrefix}_rt`, verifies the
   access token, silently refreshes once when needed, puts `Principal` in the
   request context, and gates configured paths.
6. `Logout` clears all local cookies, attempts refresh-token revocation, and
   redirects to `LogoutRedirect`.

Minimal login route:

```go
func login(client *auth.Client) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        scheme := "https"
        if r.TLS == nil {
            scheme = "http"
        }
        origin := &url.URL{Scheme: scheme, Host: r.Host}
        target, transaction, err := client.Authorize(
            origin,
            r.URL.Query().Get("provider"),
            r.URL.Query().Get("redirect"),
        )
        if err != nil {
            http.Error(w, "Invalid login request", http.StatusBadRequest)
            return
        }
        client.SetTransactionCookies(w, transaction)
        http.Redirect(w, r, target.String(), http.StatusFound)
    }
}
```

Routes and middleware:

```go
mux.HandleFunc("/login", login(client))
mux.HandleFunc("/api/auth/callback", client.Callback)
mux.HandleFunc("/logout", client.Logout)
mux.Handle("/api/v2/projects", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    principal, ok := auth.PrincipalFromContext(r.Context())
    if !ok {
        http.Error(w, "unauthenticated", http.StatusUnauthorized)
        return
    }
    fmt.Fprintln(w, principal.UserID)
}))

http.ListenAndServe(":8080", client.Middleware(mux))
```

## Principal

`Principal` contains:

- `Subject`: the raw `user:<ULID>` issuer subject.
- `UserID`: the stripped ULID used at application storage boundaries.
- `Email`, `Name`, and `Image`: identity claims from `properties.*`.
- `Roles`: issuer roles. Applications still enforce their own wall and roles.
- `Audiences`: verified JWT audiences; the configured resource must be present.

## Issuer Unreachable

JWKS are cached for ten minutes by default. An unknown `kid` or expired cache
causes a refetch; a previously cached matching key remains usable during a
transient refetch failure.

- Non-gated path: ordinary token/JWKS/refresh failure serves the request as an
  anonymous user.
- Gated path: ordinary failure redirects to `LoginPath`.
- Configured secret-resolution failure: any path carrying a refresh token
  returns a fixed no-store 503 before issuer or JWKS I/O.
- Logout always clears local cookies. A secret-resolution failure returns the
  same fixed 503 and skips remote revocation; an ordinary revocation outage does
  not prevent local logout.

## Key Patterns

- Cookie names: `{cookiePrefix}_at`, `{cookiePrefix}_rt`,
  `{cookiePrefix}_pkce`, `{cookiePrefix}_state`,
  `{cookiePrefix}_redirect`, `{cookiePrefix}_provider`, plus host-only
  `{cookiePrefix}_callback` and `{cookiePrefix}_expires` transaction metadata.
- Every cookie is `HttpOnly; Secure; SameSite=Lax`. Session cookies use `Path=/`;
  the PKCE verifier and callback metadata are scoped to `CallbackPath`.
  `SessionCookieDomain` applies only to access/refresh cookies; authorization
  transaction cookies remain host-only.
- PKCE uses `code_verifier` / `code_challenge` with S256.
- `resource` is sent on authorize, code exchange, and refresh.
- `email-code` is a consumer alias for issuer provider `code`.
- Public clients send `client_id` and no secret. Confidential clients add OAuth
  `client_secret_basic` with form-encoded client ID and secret components.
- Verification accepts only ES256 signatures, requires exact `iss` and resource
  audience, and enforces `exp`, `nbf`, and `iat` with bounded skew.
- Identity claims come from `properties.*`; `sub` must equal
  `user:` plus `properties.userId`.
- Refresh reuse is issuer-owned: the current contract accepts reuse through 600
  seconds and returns the same successor. Later reuse returns `invalid_grant`
  while the current successor chain survives.

## Conformance and contract tests

`testdata/conformance/v1` is pinned byte-for-byte to identity-platform PR #159
head `75b4960f97cd2a5b65bd17a890be973ca555b3c7`. The fixture runner loads it via
`testkit` and executes request construction, token/claim matchers, first refresh,
same-successor reuse, late reuse with successor survival, membership removal,
TTL invariants, and interactive/API refusal handling.

Live contract tests issue GET requests only to discovery and JWKS. They skip on
network failure and never call authorize, token, refresh, or revoke.
