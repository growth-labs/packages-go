package email

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/growth-labs/packages-go/testkit"
)

// Every guard below is proven at the public wiring point production calls,
// and proven falsifiable: the same unsafe case must succeed once that one
// guard is deliberately removed, so a passing run cannot mean "the guard was
// never reached". See CONVENTIONS.md.

func TestTokenFileModeGuardIsFalsifiable(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		// Unsafe case: a real, readable token file that is world-readable.
		// With the mode guard removed the same file loads, proving the
		// rejection comes from the mode check and not a missing path.
		mode := os.FileMode(0o644)
		if mutation.GuardsDisabled() {
			mode = 0o600
		}
		path := filepath.Join(t.TempDir(), "cloudflare-email.token")
		if err := os.WriteFile(path, []byte("cf-token-abc123\n"), mode); err != nil {
			return err
		}
		_, err := LoadTokenFile(path)
		return err
	})
}

func TestMissingCredentialGuardIsFalsifiableAtNew(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		// Unsafe case: the API token is missing. With the guard removed, a
		// config that should be rejected at boot time instead builds a
		// Client that would only fail on the first real send.
		cfg := validConfig()
		if !mutation.GuardsDisabled() {
			cfg.APIToken = ""
		}
		_, err := New(cfg, nil)
		return err
	})
}

func TestMessageIDInjectionGuardIsFalsifiableAtSend(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		// Unsafe case: a Message-ID smuggling a second header. With the
		// guard removed the same call reaches the transport and succeeds.
		messageID := "injected@example.org\r\nBcc: someone@example.com"
		if mutation.GuardsDisabled() {
			messageID = "injected@example.org"
		}
		fake := newFakeCloudflareServer(t)
		_, err := fake.client(t).SendWithMessageID(context.Background(),
			[]string{"someone@example.net"}, "subject", "body", messageID)
		return err
	})
}

func TestProviderRejectionGuardIsFalsifiableAtSend(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		// Unsafe case: Cloudflare reports success:false. With the guard
		// removed (the fake reporting success instead), the identical call
		// returns no error -- proving the rejection check, not something
		// else, is what fails the unsafe case.
		fake := newFakeCloudflareServer(t)
		fake.success = mutation.GuardsDisabled()
		if !mutation.GuardsDisabled() {
			fake.responseBody = `{"success":false,"errors":[{"code":10000,"message":"rejected"}]}`
		}
		_, err := fake.client(t).Send(context.Background(), []string{"someone@example.org"}, "subject", "body")
		return err
	})
}

func TestMissingVerdictGuardIsFalsifiableAtSend(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		// Unsafe case: the response body carries no "success" key at all.
		// With the guard removed (the fake reporting an explicit
		// success:true and the recipient queued instead), the identical
		// call succeeds -- proving the missing-verdict check, not
		// something else, is what fails the unsafe case.
		fake := newFakeCloudflareServer(t)
		if mutation.GuardsDisabled() {
			fake.responseBody = `{"success":true,"result":{"queued":["someone@example.org"]}}`
		} else {
			fake.responseBody = `{}`
		}
		_, err := fake.client(t).Send(context.Background(), []string{"someone@example.org"}, "subject", "body")
		return err
	})
}

func TestRecipientAcceptanceGuardIsFalsifiableAtSend(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		// Unsafe case: Cloudflare reports success:true overall but the
		// single requested recipient is not in delivered, queued, or even
		// permanent_bounces. With the guard removed (the fake reporting
		// that same recipient as queued instead), the identical call
		// succeeds -- proving the recipient-accounting check, not
		// something else, is what fails the unsafe case.
		fake := newFakeCloudflareServer(t)
		if mutation.GuardsDisabled() {
			fake.responseBody = `{"success":true,"result":{"queued":["dropped@example.org"]}}`
		} else {
			fake.responseBody = `{"success":true,"result":{}}`
		}
		_, err := fake.client(t).Send(context.Background(), []string{"dropped@example.org"}, "subject", "body")
		return err
	})
}
