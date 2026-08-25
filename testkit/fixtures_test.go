package testkit_test

import (
	"embed"
	"reflect"
	"strings"
	"testing"

	"github.com/growth-labs/packages-go/testkit"
)

//go:embed testdata/*.json testdata_invalid/*.json
var fixtureFiles embed.FS

type doublingFixture struct {
	Name     string `json:"name"`
	Input    int    `json:"input"`
	Expected int    `json:"expected"`
}

func TestLoadJSONRejectsUnknownFields(t *testing.T) {
	_, err := testkit.LoadJSON[doublingFixture](fixtureFiles, "testdata_invalid/*.json")
	if err == nil || !strings.Contains(err.Error(), `unknown field "surprise"`) {
		t.Fatalf("LoadJSON() error = %v, want unknown-field rejection", err)
	}
}

func TestLoadAndRunFixturesUsesJSONNamesInStableOrder(t *testing.T) {
	fixtures, err := testkit.LoadJSON[doublingFixture](fixtureFiles, "testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}

	var ran []string
	testkit.RunFixtures(t, fixtures, func(fixture doublingFixture) string {
		return fixture.Name
	}, func(t *testing.T, fixture doublingFixture) {
		ran = append(ran, fixture.Name)
		if got := fixture.Input * 2; got != fixture.Expected {
			t.Fatalf("double(%d) = %d, want %d", fixture.Input, got, fixture.Expected)
		}
	})

	if want := []string{"alpha", "beta"}; !reflect.DeepEqual(ran, want) {
		t.Fatalf("run order = %v, want %v", ran, want)
	}
}
