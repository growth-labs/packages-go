package examples_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/growth-labs/packages-go/testkit"
)

func TestSigningKeyModeGuardFailsForItsIntendedReason(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(keyPath, []byte("throwaway"), 0o644); err != nil {
		t.Fatal(err)
	}

	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		return loadSigningKey(keyPath, mutation)
	})
}

func loadSigningKey(path string, mutation testkit.Mutation) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !mutation.GuardsDisabled() && info.Mode().Perm() != 0o600 {
		return errors.New("signing key mode must be 0600")
	}
	_, err = os.ReadFile(path)
	return err
}

func TestPayloadCeilingDeletionCannotLeaveThePackageGreen(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		return handlePayload([]byte("over-ceiling"), mutation)
	})
}

func handlePayload(payload []byte, mutation testkit.Mutation) error {
	if !mutation.GuardsDisabled() && len(payload) > 8 {
		return errors.New("payload exceeds ceiling")
	}
	return nil
}

func TestCollectionCapIsProvenAtThePublicWiringPoint(t *testing.T) {
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		return serveNames([]string{"one", "two", "three"}, mutation)
	})
}

func serveNames(names []string, mutation testkit.Mutation) error {
	return validateNames(names, mutation)
}

func validateNames(names []string, mutation testkit.Mutation) error {
	if !mutation.GuardsDisabled() && len(names) > 2 {
		return errors.New("name count exceeds cap")
	}
	return nil
}
