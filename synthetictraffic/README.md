# synthetictraffic

Stdlib-only Go counterpart of `@growth-labs/monitoring`'s
`createSyntheticTrafficIdentity`: builds the same synthetic-traffic identity
— user agent, six `X-Fulcrum-*` headers, and the `trafficClass`/`runId` pair
— for a Go probe or canary that a TypeScript one gets on the Workers
runtime.

```sh
go get github.com/growth-labs/packages-go/synthetictraffic
```

## Source of truth

The contract is `growth-labs/packages`,
`packages/monitoring/src/canary/traffic.ts`. This package is not a port of
that implementation; it mirrors the identity it emits, field for field. Any
field added to `SyntheticTrafficIdentityInput` or `SyntheticTrafficIdentity`
in `traffic.ts` must be added to `Input` or `Identity` here in the same
change.

`testdata/synthetic-traffic-identity.json` is the single fixture both
suites read:

- Go: `identity_test.go` reads it directly out of `testdata/`.
- TypeScript: `packages/monitoring/__tests__/canary/traffic.fixture.test.ts`
  in `growth-labs/packages` reads this same file across the repo boundary,
  from a sibling checkout of `packages-go` (override the root with the
  `PACKAGES_GO_ROOT` environment variable if the sibling checkout lives
  somewhere else). The two test suites failing independently on a
  fixture-vs-implementation mismatch is the point: there is exactly one copy
  of the expected bytes, and whichever side drifts from it fails its own
  build.

## Use

```go
identity := synthetictraffic.New(synthetictraffic.Input{
	Tool:        "authenticated-browser-canary",
	Version:     "1.2.3",
	Realm:       "fulcrum-labs",
	Site:        "fronts",
	Environment: "production",
	Surface:     "media.video-playback",
	RunID:       runID,
	// Owner is optional; it defaults to "olympus", matching traffic.ts.
})

req.Header.Set("User-Agent", identity.UserAgent)
for name, value := range identity.Headers {
	req.Header.Set(name, value)
}
```

Send both `UserAgent` and every entry in `Headers`. `UserAgent` alone earns
CSP-report suppression by prefix match; the headers are what downstream
attribution, filtering, and correlation of synthetic traffic actually key
off, and dropping them is the shortcut this package exists to make
unnecessary.

## Do not use it for

- Anything the identity is attached to (issuing the HTTP request, running the
  probe, recording a result): this package only builds the identity value.
- A second, independent definition of the `FulcrumInternal/` user-agent
  prefix or the header names: they are defined once, here, in
  `identity.go`.
