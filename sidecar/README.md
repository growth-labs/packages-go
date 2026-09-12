# sidecar

Dependency-free reader and validator for the WH-08 sidecar cut record
(`component-cut.json`): the plaintext identity a store owner's cut writes
beside its (possibly encrypted) payload, and the identity the authority's
own non-handoff captures write directly.

```sh
go get github.com/growth-labs/packages-go/sidecar
```

## Use it for

- Reading a store's own cut record off disk to check its freshness against
  a recovery-point objective (a sidecar owner's freshness tripwire).
- Reading back a shipped or handed-off cut's record to verify what it
  claims about itself (store, kind, schema version, writer generation,
  cursors) before trusting or importing it.
- Any second Go consumer of this exact JSON shape, so it is decoded and
  validated once, not reimplemented per consumer.

## Do not use it for

- Capturing a sidecar (VACUUM INTO, control-log copy, encryption, handoff
  directory management): that capture/write side stays in
  `fulcrum-labs/foundry`'s `backup` package, which owns the store-reading
  and encryption logic this package has no opinion on.
- A general backup-manifest or product-backup-vector type: this package is
  scoped to one sidecar store's cut record, not the wider manifest that
  names every backup vector.

## Extracted at the second real use

`fulcrum-labs/foundry`'s `backup.ComponentCut` (`backup/v2_manifest.go`,
produced and consumed by `backup/sidecar.go` and `backup/handoff.go`) and
`fulcrum-labs/quarry`'s `sidecarfreshness` package, which had reimplemented
a narrow, read-only subset of this exact JSON shape because Quarry does not
otherwise depend on the foundry Go module. Both are separately deployed
artifacts; adopting this package removes that duplication from Quarry now,
and from foundry the next time a writer touches `backup.ComponentCut`.
