package packaging_test

import (
	"os/exec"
	"testing"
)

func TestDeployScriptSwapsAndRollsBack(t *testing.T) {
	output, err := exec.Command("bash", "scripts/deploy_test.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("deploy_test.sh: %v\n%s", err, output)
	}
}
