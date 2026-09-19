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
// transactional message through Cloudflare Email Sending.
//
// The API token is never a literal and never an environment variable: it is
// read from a mode-0600 file placed on the host (Vaultwarden holds the
// value; the file holds a copy the service user alone can read).
// LoadTokenFile refuses a file with any wider mode, so a misplaced secret
// fails at start-up instead of leaking. AccountID and From are not secret.
//
// It has no "Output:" section on purpose -- running it would send real mail
// -- so the toolchain compiles it on every build without executing it. The
// behaviour it shows is covered against a fake Cloudflare API in
// client_test.go.
func Example() {
	token, err := email.LoadTokenFile("/etc/foundry/secrets/cloudflare-email.token")
	if err != nil {
		log.Fatalf("load Cloudflare Email Sending token: %v", err)
	}

	client, err := email.New(email.Config{
		AccountID: "b8fd8daf73edd8fe6b6bd18eeaacf2bb",
		APIToken:  token,
		From:      "foundry-alerts@fulcrum-portal.com",
	}, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		log.Fatalf("build email client: %v", err)
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

	// Cloudflare's response is the only delivery evidence there is: unlike
	// JMAP, there is no Sent mailbox to poll afterward.
	fmt.Println(messageID)
}
