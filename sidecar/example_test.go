package sidecar_test

import (
	"fmt"
	"os"
	"time"

	"github.com/growth-labs/packages-go/sidecar"
)

// Example is the whole working shape of a consumer that reads a store's
// newest complete cut off disk and checks it is within a recovery-point
// objective — e.g. a store owner's own freshness tripwire, checking the
// same handoff directory its cut unit publishes into.
func Example() {
	payload, err := os.ReadFile("testdata/component-cut.golden.json")
	if err != nil {
		fmt.Println("read cut record:", err)
		return
	}

	record, err := sidecar.Parse(payload)
	if err != nil {
		fmt.Println("parse cut record:", err)
		return
	}

	capturedAt, err := record.CapturedAtTime()
	if err != nil {
		fmt.Println("cut record has no usable capturedAt:", err)
		return
	}

	objective := 15 * time.Minute
	now := capturedAt.Add(5 * time.Minute) // a fixed instant, for a reproducible example
	age := now.Sub(capturedAt)
	fmt.Printf("store=%s kind=%s withinObjective=%t\n", record.Store, record.Kind, age <= objective)

	// Output:
	// store=quarry kind=handoff withinObjective=true
}
