package s3_test

import (
	"context"
	"log"
	"net/http"

	"github.com/growth-labs/packages-go/s3"
)

// Example is the whole working shape of a service that streams one
// object's bytes through to an HTTP response — e.g. an app server
// proxying a <video> tag's GET (Range header and all) to a private
// bucket without ever holding the whole file in memory or handing the
// browser a credential of its own.
//
// Credentials are never literals and never environment variables in a
// real deployment: read them from a mode-0600 file or an injected
// provider whose value's home is Vaultwarden. This example inlines
// them only to keep the shape visible.
//
// It has no "Output:" section on purpose — running it would make a
// real request — so the toolchain compiles it on every build without
// executing it. The behaviour it shows is covered against an httptest
// server in s3_test.go.
func Example() {
	client, err := s3.NewClient(s3.Config{
		Endpoint: "https://objectstore.internal:9000", Region: "estate-1", Bucket: "media",
		PathStyle: true, AccessKeyID: "access-key-id", SecretAccessKey: "secret-access-key",
	}, &http.Client{})
	if err != nil {
		log.Fatalf("build object store client: %v", err)
	}

	ctx := context.Background()
	// rangeHeader is forwarded from the caller's own incoming request —
	// "" for a full-object GET, or the exact Range header value to pass
	// a video seek through unmodified.
	response, err := client.Get(ctx, "outputs/render/clip.mp4", "")
	if err != nil {
		log.Fatalf("get object: %v", err)
	}
	defer response.Body.Close()
	// Stream response.Body to the caller (e.g. io.Copy into an
	// http.ResponseWriter) rather than reading it fully into memory.
}
