# Shared capabilities — extend what exists, build capabilities not one-offs

This estate is one system built by several operators' agents. A concept exists once. A second implementation of it is a defect whether it lives in another repo or three directories away, and the better-argued the duplicate, the more expensive it is to unwind.

## Before you add a mechanism

A mechanism is anything another part of the system could call or depend on: a table or migration, a domain package or module, a component, a worker, a queue or scheduler, a client for an external service, an auth or delivery path, a shared helper.

1. Read this repo's mechanism index, `docs/agent/mechanisms.md` (generated; drift fails CI). Find the closest existing mechanism.
2. Read the estate index, `docs/agent/shared-capabilities.md` (generated from the package catalogs, the platform manifests and the Go-plane capability catalog). Find the package, service or capability that already serves the need.
3. Extend the closest match. Name it and the smallest extension in the spec section "Existing mechanisms considered" and in the PR body.
4. Only when nothing serves the need, build it in its home (table below), never as a private copy.

## Where new behaviour lives

| Class of work | Home |
|---|---|
| Automated, scheduled, cross-site or media work; anything that should inherit the scheduler, receipts and monitoring | Go plane: a `fulcrum-labs/foundry` capability (host record + package + migrations + receipts + tripwire) |
| Behaviour shared by Workers-runtime sites and apps | `@growth-labs/<pkg>` in `growth-labs/packages` |
| Behaviour shared by Go services | `growth-labs/packages-go/<module>`; extract at the second real use, never copy |
| Identity, sessions, sign-in | identity-platform (OpenAuth issuer) through `@growth-labs/auth` or `packages-go/auth`; never a standalone auth path |
| Email | Workers: `@growth-labs/email` (transactional) and `@growth-labs/mailer` (campaigns); Go: `packages-go/email` (Fastmail JMAP) |
| UI | Astro sites: StarwindUI Pro (`components/starwind/`); React/SPA apps: the Growth Labs tokens (see the estate index for the current package state) |
| Domain logic only this app has | this app, until a second consumer appears; then extract |

No home for a need is an escalation, never a reason to build a local shim or to stop: decide it inside the task when you own the stream, otherwise file a `platform-request`; record the decision in the KB either way.

## Declare the exception

Every PR that adds a mechanism-shaped path carries a `Reuse:` line in its body; the `pr-metadata` check fails without one:

- `Reuse: extends <mechanism or path>`
- `Reuse: new capability in <home> — <why nothing existing serves this>`
- `Reuse: parallel — rejected <existing mechanism> because <reason>`

A declared parallel is allowed. An undeclared parallel is a defect.

## Reviewing

Compare the change against both indexes. A second implementation of an existing concept is a `parallel-implementation` finding whether or not the code is good. A missing or false `Reuse:` line is a blocking finding.

## Upstream, never per-site

A bug or feature in a shared package or capability is fixed once in its home (release + version bump) and then adopted; never patched in a consumer, never vendored. If the home is outside your stream, file `platform-request` or `foundry-request`; the close is the callback.
