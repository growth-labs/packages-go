# s3

Dependency-free AWS SigV4 client for one S3-compatible bucket (path-style or
virtual-hosted addressing; AWS S3 and Cloudflare R2 alike): no SDK, no
vendor lock-in beyond the standard library.

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
- Uploading a large, streamed payload that must survive a dropped
  connection without re-sending the whole object (`PutStream`: automatic
  real S3 multipart upload above `MultipartThreshold`, per-part retry,
  server-side abort on an unrecoverable failure, and a read-back identity
  check via `Inspect` after every upload).

## Do not use it for

- A general `ArtifactStore` abstraction (opaque `object://` reference
  resolution, capability-dispatch-shaped source/target types): that
  domain layer belongs in the consumer, built on top of this package's
  plain bucket-relative-key API, not inside it.

## Minimal setup

```go
client, err := s3.NewClient(s3.Config{
    Endpoint: "https://objectstore.internal:9000", Region: "estate-1",
    Bucket: "media", PathStyle: true,
    AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey,
}, httpClient)

response, err := client.Get(ctx, "outputs/render/clip.mp4", rangeHeader)

err = client.PutStream(ctx, "outputs/render/clip.mp4", reader, size, sha256Hex)
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
- Building an app-local SigV4 client, multipart uploader, or
  `ArtifactStore`-shaped wrapper instead of using/extending this package:
  a second implementation of the same signing logic is a defect.
