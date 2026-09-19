package seatpolicy_test

import (
	"fmt"
	"time"

	"github.com/growth-labs/packages-go/seatpolicy"
)

// ExampleRank shows observed quota policy over public seats. The caller still
// reserves the selected seat atomically against its own occupancy store.
func ExampleRank() {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	used := func(value float64) *float64 { return &value }
	observed := now.Add(-time.Minute)
	result := seatpolicy.Rank(now, []seatpolicy.Candidate{
		{
			Client: seatpolicy.Claude, Seat: "grizzle",
			Windows: []seatpolicy.Window{
				{Kind: seatpolicy.Session, UsedPercent: used(25), ObservedAt: observed},
				{Kind: seatpolicy.Weekly, UsedPercent: used(50), ObservedAt: observed},
			},
		},
		{
			Client: seatpolicy.Codex, Seat: "codex",
			Windows: []seatpolicy.Window{
				{Kind: seatpolicy.Weekly, UsedPercent: used(20), ObservedAt: observed},
			},
		},
	})
	for _, candidate := range result.Eligible {
		fmt.Printf("%s/%s %.0f%% observed headroom\n", candidate.Client, candidate.Seat, *candidate.Assessment.HeadroomPercent)
	}
	// Output:
	// claude/grizzle 50% observed headroom
	// codex/codex 80% observed headroom
}
