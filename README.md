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
- `email` — Fastmail JMAP transactional email: estate identity selection,
  send, and sender-side delivery proof.
- `foundryoperator` — dependency-free signer for FOUNDRY-OPERATOR-V1 operator
  proofs: canonical-JSON encoding and Ed25519 signing for foundryd's
  operator-proof surface.
- `testkit` — JSON fixture runners, falsifiable-guard mutation helpers, and a
  disposable real-PostgreSQL harness.
- `pg` — ordered PostgreSQL migrations, export gating, a version ledger, and
  pgx transaction helpers.
- `packaging` — static cross-builds, provenance, checksums, signed manifests,
  systemd, and health-checked symlink-swap deployment.
- `s3` — dependency-free SigV4 client for one S3-compatible bucket
  (path-style or virtual-hosted): streamed Range-forwarding Get,
  prefix-scoped List/Delete, small-payload Put, and PutStream (automatic
  multipart with read-back verification).
- `sidecar` — dependency-free reader/validator for the WH-08 sidecar cut
  record (`component-cut.json`): store, kind, cut identity, capturedAt,
  schema version, writer generation, control-log sequence/hash, cross-store
  cursors, and the encrypted-owner-cut ciphertext identity/recipients.
- `synthetictraffic` — stdlib-only Go counterpart of
  `@growth-labs/monitoring`'s `createSyntheticTrafficIdentity`: the synthetic
  traffic user agent, the six `X-Fulcrum-*` headers, and the
  `trafficClass`/`runId` pair, mirrored field for field from
  `packages/monitoring/src/canary/traffic.ts` and pinned by a fixture shared
  with that TypeScript suite.

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

## Package catalog

`docs/agent/package-catalog.yaml` is the machine-readable index an agent reads
before writing a shared helper: what each module is for, when not to use it,
its worked example, and its common mistakes. `scripts/check-package-catalog.sh`
fails CI when it drifts from `go.work` in either direction, when a worked
example does not exist, or when a `related_packages` name does not resolve.
platform-foundations renders it into the estate-wide shared-capability index.

## Extraction rule

Build app-agnostic behavior in a shared package from the start when a second
consumer is already known. Otherwise extract it at the second real use.
Never copy an implementation between applications.

See [CONVENTIONS.md](CONVENTIONS.md) for the falsifiable-guards rule.
