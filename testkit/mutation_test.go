package testkit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/growth-labs/packages-go/testkit"
)

func TestCheckGuardRequiresRejectionAndMutationAcceptance(t *testing.T) {
	guarded := func(mutation testkit.Mutation) error {
		if !mutation.GuardsDisabled() {
			return errors.New("unsafe input rejected")
		}
		return nil
	}
	if err := testkit.CheckGuard(guarded); err != nil {
		t.Fatalf("CheckGuard(valid proof) = %v", err)
	}

	for name, run := range map[string]func(testkit.Mutation) error{
		"deleted guard": func(testkit.Mutation) error { return nil },
		"wrong reason":  func(testkit.Mutation) error { return errors.New("unrelated failure") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := testkit.CheckGuard(run); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("CheckGuard(%s) error = %v", name, err)
			}
		})
	}
}
