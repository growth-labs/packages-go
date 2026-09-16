package synthetictraffic_test

import (
	"fmt"

	"github.com/growth-labs/packages-go/synthetictraffic"
)

// Example builds a synthetic-traffic identity for one canary run and shows
// where its two halves go: UserAgent on the outgoing request's User-Agent
// header, and Headers merged onto the same request so downstream tooling can
// attribute, filter, and correlate the run without parsing the user agent.
func Example() {
	identity := synthetictraffic.New(synthetictraffic.Input{
		Tool:        "authenticated-browser-canary",
		Version:     "1.2.3",
		Realm:       "fulcrum-labs",
		Site:        "fronts",
		Environment: "production",
		Surface:     "media.video-playback",
		RunID:       "d6be7f13-5418-431d-bc3c-8f74d22131b6",
	})

	fmt.Println(identity.UserAgent)
	fmt.Println(identity.Headers["X-Fulcrum-Monitor-Run-Id"])

	// Output:
	// FulcrumInternal/authenticated-browser-canary/1.2.3 (+https://fulcrum-labs.com/ops/monitoring; owner=olympus; realm=fulcrum-labs; site=fronts; env=production; surface=media.video-playback)
	// d6be7f13-5418-431d-bc3c-8f74d22131b6
}
