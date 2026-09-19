package foundryoperator_test

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/growth-labs/packages-go/foundryoperator"
)

// Example is the whole working shape of a consumer that signs one request
// to foundryd's operator-proof surface: build the proof and signature,
// then attach them as the two headers foundryd's verifier expects.
func Example() {
	// A real caller loads its enrolled Ed25519 delegation key from disk
	// (mode 0600, owned by the running user) instead of generating one.
	_, principalKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("generate key:", err)
		return
	}

	body := []byte(`{"profile":"kb"}`)
	fixedTime := time.Date(2026, 9, 19, 8, 0, 0, 0, time.UTC) // fixed, for a reproducible example
	fixedNonce := func() (string, error) { return "example-nonce-0123456789AB", nil }

	proof, signature, err := foundryoperator.Sign(
		principalKey, "cockpit-hub-example", "POST", "/mcp/token", "", body, fixedTime, fixedNonce,
	)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}

	fmt.Printf("proof header set: %t, signature header set: %t\n", proof != "", signature != "")

	// Output:
	// proof header set: true, signature header set: true
}
