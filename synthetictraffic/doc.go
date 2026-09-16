// Package synthetictraffic is the Go counterpart of the
// @growth-labs/monitoring package's createSyntheticTrafficIdentity.
//
// Source of truth: growth-labs/packages,
// packages/monitoring/src/canary/traffic.ts. That TypeScript function's
// emitted identity — the exact userAgent string, the six X-Fulcrum-* headers,
// and the trafficClass/runId pair — is a language-neutral contract, not a
// library to port. This package mirrors that contract field for field so a
// Go-plane probe gets exactly the same attribution the Workers-runtime
// probes get: CSP-report suppression by user-agent prefix, plus every field
// downstream tooling uses to filter and correlate synthetic traffic.
//
// Any field traffic.ts adds to SyntheticTrafficIdentityInput or
// SyntheticTrafficIdentity must be added to Input or Identity here in the
// same change. testdata/synthetic-traffic-identity.json is the single
// fixture both the TypeScript and Go test suites read, so a change to either
// implementation's output that is not mirrored on both sides fails both
// suites.
package synthetictraffic
