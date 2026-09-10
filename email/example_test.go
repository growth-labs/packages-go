package email_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/growth-labs/packages-go/email"
)

// Example is the whole working shape of a service that sends one
// transactional message and then proves the account accepted it.
//
// The token is never a literal and never an environment variable: it is read
// from a mode-0600 file placed on the host (Vaultwarden holds the value; the
// file holds a copy the service user alone can read). LoadTokenFile refuses a
// file with any wider mode, so a misplaced secret fails at start-up instead of
// leaking.
//
// It has no "Output:" section on purpose -- running it would send real mail --
// so the toolchain compiles it on every build without executing it. The
// behaviour it shows is covered against a JMAP stub in client_test.go.
func Example() {
	token, err := email.LoadTokenFile("/etc/foundry/secrets/fastmail.token")
	if err != nil {
		log.Fatalf("load fastmail token: %v", err)
	}

	client, err := email.New(token, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		log.Fatalf("build fastmail client: %v", err)
	}

	ctx := context.Background()
	messageID, err := client.Send(ctx,
		[]string{"someone@fulcrum-labs.com"},
		"Deploy finished",
		"foundryd reached revision abc1234 on CT240.",
	)
	if err != nil {
		// Only an Unsubmitted error proves nothing was sent, so only it is
		// safe to retry automatically. Anything else may already be in the
		// recipient's mailbox.
		if email.IsUnsubmitted(err) {
			log.Printf("nothing was submitted, safe to retry: %v", err)
			return
		}
		log.Fatalf("send outcome unknown, do not retry blindly: %v", err)
	}

	// Send returning is acceptance by the API, not proof the message left
	// the account. VerifyDelivered polls the Sent mailbox for this exact
	// Message-ID, which is the strongest sender-side evidence available.
	delivered, err := client.VerifyDelivered(ctx, messageID, 2*time.Minute)
	if err != nil {
		log.Fatalf("verify delivery: %v", err)
	}
	fmt.Println(messageID, delivered)
}
