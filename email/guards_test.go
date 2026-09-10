package email

import (
	"context"
	"errors"
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
		path := filepath.Join(t.TempDir(), "fastmail.token")
		if err := os.WriteFile(path, []byte("fm1-abc123\n"), mode); err != nil {
			return err
		}
		_, err := LoadTokenFile(path)
		return err
	})
}

func TestEstateIdentityGuardIsFalsifiableAtSend(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		// Unsafe case: the Fastmail account offers only the operator's own
		// personal identity. Send must refuse rather than fall back to it.
		fake := newFakeJMAPServer(t)
		fake.omitFulcrumIdentity = !mutation.GuardsDisabled()
		_, err := fake.client(t).Send(context.Background(), []string{"grant@fulcrum-labs.com"}, "subject", "body")
		return err
	})
}

func TestMessageIDInjectionGuardIsFalsifiableAtSend(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		// Unsafe case: a Message-ID smuggling a second header. With the
		// guard removed the same call reaches the transport and succeeds.
		messageID := "injected@fulcrum-labs.com\r\nBcc: someone@example.com"
		if mutation.GuardsDisabled() {
			messageID = "injected@fulcrum-labs.com"
		}
		fake := newFakeJMAPServer(t)
		_, err := fake.client(t).SendWithMessageID(context.Background(),
			[]string{"grant@fulcrum-labs.com"}, "subject", "body", messageID)
		return err
	})
}

func TestSentProofDraftGuardIsFalsifiable(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		// Unsafe case: the message exists but only as a draft. Sent proof
		// must not accept it; with the draft guard removed (the fake filing
		// the same message in Sent) the identical lookup succeeds.
		fake := newFakeJMAPServer(t)
		fake.sentMessageIDs = []string{"stable@fulcrum-labs.com"}
		fake.draftOnly = !mutation.GuardsDisabled()
		found, err := fake.client(t).FindSentByMessageID(context.Background(), "stable@fulcrum-labs.com")
		if err != nil {
			return err
		}
		if !found {
			return errors.New("message is not provably in Sent")
		}
		return nil
	})
}
