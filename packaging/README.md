# packaging

Reusable build, provenance, artifact-signing, systemd, and deployment
conventions for fleet Go services.

## Verified donor

The static build and checksum mechanics are adapted from
`fulcrum-labs/foundry` main commit
`e9a312008010218b06dabafca6cb33fdcb897cb0`. At that commit,
`scripts/package/build.sh` is Git blob
`dcc78581d82ee6b370ca70fe93b29f42ad06860d`.

That pin verifies `CGO_ENABLED=0`, provenance ldflags, portable
`SHA256SUMS`, signed backup manifests, a hardened systemd unit, and health
checks. It does not contain a Linux symlink-swap deployment script: its Linux
installer copies binaries directly. `scripts/deploy.sh` therefore implements
the governing fleet specification’s symlink swap and health rollback while
retaining the pin’s verified mechanics.

## Build

`scripts/build.sh` requires `PACKAGE_MAIN` and `PACKAGE_NAME`. Optional
`PACKAGE_VERSION`, `PACKAGE_REVISION`, `BUILD_TARGETS`, and `DIST_DIR` select
the stamp and output. The default targets are `darwin-arm64 linux-amd64`.
Each binary contains `provenance.Version` and `provenance.Revision`, and every
build emits `SHA256SUMS`.

## Sign and verify

`Seal` hashes a complete regular-file payload, writes deterministic
`manifest.json`, and signs those bytes into detached `manifest.ed25519` with
an Ed25519 private key. `Verify` authenticates the signature, rejects unsafe
or extra paths, and re-hashes every payload file after transport. Applications
wrap these functions in their operational signer/verifier so private keys stay
in the service’s approved secret home rather than shell arguments or this repo.

## Deploy

`scripts/deploy.sh ARTIFACT_DIRECTORY` requires `RELEASE_ROOT`,
`SYSTEMD_UNIT`, `HEALTH_URL`, `EXPECTED_REVISION`, and an executable
`VERIFY_COMMAND`. Verification runs before state changes. The script copies to
an immutable revision directory, atomically swaps `CURRENT_LINK` (default
`$RELEASE_ROOT/current`), restarts the unit, and requires the health body to
contain the expected revision. Failed restart or health rolls the symlink back
and restarts the prior release.

Adapt `systemd/package.service.example` with the service user, paths, and unit
name. Keep its hardening and `Restart=always` posture.
