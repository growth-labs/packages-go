package github_test

import (
	"context"
	"log"
	"os"

	"github.com/growth-labs/packages-go/github"
)

// Example is the whole working shape of a service that mints a
// narrowly-scoped installation token and hands it to a child process (the
// WH-05b maintenance control loop's own use: a runner-executed platform-
// foundations CLI reading GITHUB_TOKEN from its environment).
//
// The private key is never a literal and never a GitHub Actions secret in a
// real deployment: it is loaded from a vault-delivered, mode-0600 file on
// the authority, the only place this package's caller should ever run. This
// example inlines a path only to keep the shape visible.
//
// It has no "Output:" section on purpose — running it would make a real
// request — so the toolchain compiles it on every build without executing
// it. The behaviour it shows is covered against an httptest server in
// client_test.go.
func Example() {
	privateKeyPEM, err := os.ReadFile("/var/lib/foundry/secrets/fulcrum-platform-automation.pem")
	if err != nil {
		log.Fatalf("read App private key: %v", err)
	}

	client, err := github.New(github.Config{
		AppID:         4528171,
		PrivateKeyPEM: privateKeyPEM,
	})
	if err != nil {
		log.Fatalf("build github client: %v", err)
	}

	ctx := context.Background()
	token, err := client.MintInstallationToken(ctx, 987654, "platform-foundations", github.Permissions{
		"contents":      "write",
		"pull_requests": "write",
	})
	if err != nil {
		log.Fatalf("mint installation token: %v", err)
	}
	// token.Value() goes into the child process's environment as
	// GITHUB_TOKEN. It is never logged or placed in a capability_runs
	// receipt -- only Token.Value() reaches it, on purpose.
	_ = token.Value()
}
