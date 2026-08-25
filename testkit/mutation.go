package testkit

import (
	"fmt"
	"testing"
)

// Mutation is passed only by guard-proof tests. Production callers receive
// the zero value, which leaves guards enabled.
type Mutation struct {
	guardsDisabled bool
}

// GuardsDisabled reports whether the proof run deliberately removed the
// guard under test.
func (m Mutation) GuardsDisabled() bool {
	return m.guardsDisabled
}

// CheckGuard proves that an unsafe input is rejected by the wired guard and
// accepted when that guard alone is deliberately removed.
func CheckGuard(runUnsafe func(Mutation) error) error {
	if err := runUnsafe(Mutation{}); err == nil {
		return fmt.Errorf("deleted guard: unsafe input was accepted with guards enabled")
	}
	if err := runUnsafe(Mutation{guardsDisabled: true}); err != nil {
		return fmt.Errorf("wrong reason: unsafe input still failed with guard disabled: %w", err)
	}
	return nil
}

// ProveGuard exposes CheckGuard as a one-call testing helper.
func ProveGuard(t testing.TB, runUnsafe func(Mutation) error) {
	t.Helper()
	if err := CheckGuard(runUnsafe); err != nil {
		t.Fatal(err)
	}
}
