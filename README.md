# Growth Labs Go packages

Shared, app-agnostic Go modules for Growth Labs and Fulcrum services.

## Modules and imports

Each directory is an independent Go module imported as
`github.com/growth-labs/packages-go/<module>`. Names mirror the npm scope:
`auth` corresponds to `@growth-labs/auth`, `health` to `@growth-labs/health`,
and `conformance` to `@growth-labs/conformance`.

Current modules:

- `auth` — OpenAuth authorization-code flow, ES256 JWKS verification, refresh,
  secure session cookies, and `net/http` middleware.
- `testkit` — JSON fixture runners, falsifiable-guard mutation helpers, and a
  disposable real-PostgreSQL harness.
- `pg` — ordered PostgreSQL migrations, export gating, a version ledger, and
  pgx transaction helpers.
- `packaging` — static cross-builds, provenance, checksums, signed manifests,
  systemd, and health-checked symlink-swap deployment.

The repository and its tagged modules are public. Standard Go module resolution
uses the public module proxy (`proxy.golang.org`) by default:

```sh
go get github.com/growth-labs/packages-go/pg@v0.1.0
```

Consumers that prefer direct GitHub resolution can opt into it without a
repository token or Git URL rewrite:

```sh
GOPROXY=direct go get github.com/growth-labs/packages-go/pg@v0.1.0
```

## Releases

Modules version independently. Tag a release as `<module>/vX.Y.Z`, for example
`pg/v0.1.0`.

## Extraction rule

Build app-agnostic behavior in a shared package from the start when a second
consumer is already known. Otherwise extract it at the second real use.
Never copy an implementation between applications.

See [CONVENTIONS.md](CONVENTIONS.md) for the falsifiable-guards rule.
