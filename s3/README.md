# s3

Dependency-free SigV4 client for one S3-compatible, path-style bucket: no
SDK, no vendor lock-in beyond the standard library.

```sh
go get github.com/growth-labs/packages-go/s3
```

## Use it for

- Streaming an object's bytes through an app server (e.g. proxying a
  `<video>` tag's `Range` requests to a private bucket) without holding the
  whole file in memory or handing the browser a credential of its own
  (`Get`).
- Prefix-scoped listing and deletion for operator-driven cleanup (`List`,
  `Delete`).
- Uploading a small, fully-buffered payload — a JSON receipt, a manifest
  (`Put`; SigV4 header auth signs the exact payload hash up front, so it
  needs the complete body anyway).

## Do not use it for

- Multipart/large-object upload, or a general `ArtifactStore` abstraction
  (source/target references, publish/inspect semantics): this package is
  the narrow signed-request primitive, not that layer. `fulcrum-labs/foundry`'s
  `capabilityplane/object.go` is a fuller client with multipart support that
  predates this extraction; if that capability is needed here too, extend
  this package rather than building a second implementation.
- Anything that isn't path-style addressing (virtual-hosted-style buckets
  are rejected by `NewClient`).

## Minimal setup

```go
client, err := s3.NewClient(s3.Config{
    Endpoint: "https://objectstore.internal:9000", Region: "estate-1",
    Bucket: "media", PathStyle: true,
    AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey,
}, httpClient)

response, err := client.Get(ctx, "outputs/render/clip.mp4", rangeHeader)
```

See `example_test.go` for the full worked shape.

## Common mistakes

- Reading a whole `Get` response into memory instead of streaming
  `response.Body` — defeats the reason this package exists over a bare
  SDK call.
- Passing an absolute key (a leading `/`) — every method requires a
  bucket-relative path and rejects one that isn't.
- Treating `Delete` as failing on an already-absent key: S3-compatible
  `DELETE` is idempotent, and this client treats 404 as success to match.
- Building an app-local SigV4 client instead of using this package: a
  second implementation of the same signing logic is a defect.
