package synthetictraffic_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/growth-labs/packages-go/synthetictraffic"
)

// fixtureCase is one entry in testdata/synthetic-traffic-identity.json. Its
// field names and nested shapes are the JSON contract shared with the
// TypeScript suite, not a Go-only convenience type.
type fixtureCase struct {
	Name     string                    `json:"name"`
	Input    synthetictraffic.Input    `json:"input"`
	Expected synthetictraffic.Identity `json:"expected"`
}

type fixtureFile struct {
	Comment string        `json:"$comment"`
	Cases   []fixtureCase `json:"cases"`
}

// loadFixture decodes the fixture both language suites read. Strict
// decoding (DisallowUnknownFields) means a field traffic.ts adds to the
// contract that has not yet been added to Input or Identity here fails this
// test loudly instead of silently dropping the field, per the package doc's
// "any field added there must be added here" rule.
func loadFixture(t *testing.T) fixtureFile {
	t.Helper()

	data, err := os.ReadFile("testdata/synthetic-traffic-identity.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var fixture fixtureFile
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("fixture has no cases")
	}
	return fixture
}

func TestNewMatchesSharedFixture(t *testing.T) {
	fixture := loadFixture(t)

	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := synthetictraffic.New(tc.Input)
			if !reflect.DeepEqual(got, tc.Expected) {
				t.Fatalf("New(%+v) =\n  %+v\nwant\n  %+v", tc.Input, got, tc.Expected)
			}
		})
	}
}

func TestNewDefaultsOwnerToOlympus(t *testing.T) {
	identity := synthetictraffic.New(synthetictraffic.Input{
		Tool:        "probe",
		Version:     "0.0.1",
		Realm:       "realm",
		Site:        "site",
		Environment: "env",
		Surface:     "surface",
		RunID:       "run-id",
	})

	if want := "FulcrumInternal/probe/0.0.1 (+https://fulcrum-labs.com/ops/monitoring; owner=olympus; realm=realm; site=site; env=env; surface=surface)"; identity.UserAgent != want {
		t.Fatalf("UserAgent = %q, want %q", identity.UserAgent, want)
	}
	if identity.TrafficClass != "synthetic" {
		t.Fatalf("TrafficClass = %q, want %q", identity.TrafficClass, "synthetic")
	}
	if len(identity.Headers) != 6 {
		t.Fatalf("len(Headers) = %d, want 6", len(identity.Headers))
	}
}
