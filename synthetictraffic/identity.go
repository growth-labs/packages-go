package synthetictraffic

import "fmt"

// product is the package's single definition of the synthetic-traffic
// user-agent namespace token. traffic.ts defines the same literal once, in
// its own template string; this is the only place in this package (and it
// must be the only place in this module) that spells it out. Everything
// downstream builds the user agent by formatting around this constant, never
// by repeating the literal.
const product = "FulcrumInternal"

// contactURL is the fixed operator contact URL traffic.ts embeds in every
// synthetic user agent.
const contactURL = "https://fulcrum-labs.com/ops/monitoring"

// defaultOwner is the owner traffic.ts substitutes when Input.Owner is
// empty: `input.owner ?? 'olympus'`.
const defaultOwner = "olympus"

// trafficClass is the one value traffic.ts ever emits for TrafficClass and
// the X-Fulcrum-Traffic-Class header.
const trafficClass = "synthetic"

// Input is one synthetic-traffic run's caller-supplied identity. It mirrors
// traffic.ts's SyntheticTrafficIdentityInput field for field, including its
// JSON field names: the shared fixture in testdata decodes directly into
// this shape.
type Input struct {
	Tool        string `json:"tool"`
	Version     string `json:"version"`
	Realm       string `json:"realm"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	Surface     string `json:"surface"`
	RunID       string `json:"runId"`

	// Owner defaults to "olympus" when empty, matching traffic.ts's
	// `input.owner ?? 'olympus'`.
	Owner string `json:"owner,omitempty"`
}

// Identity is the emitted synthetic-traffic identity: it mirrors
// traffic.ts's SyntheticTrafficIdentity field for field.
type Identity struct {
	TrafficClass string            `json:"trafficClass"`
	RunID        string            `json:"runId"`
	UserAgent    string            `json:"userAgent"`
	Headers      map[string]string `json:"headers"`
}

// New builds the synthetic-traffic identity for input. It reproduces
// createSyntheticTrafficIdentity in traffic.ts exactly: the same six
// X-Fulcrum-* headers, the same user-agent template (including the fixed
// contact URL and the "olympus" default owner), and the same
// trafficClass/runId pair. See the package doc for the source-of-truth
// contract and testdata/synthetic-traffic-identity.json for the fixture both
// languages' test suites verify against.
func New(input Input) Identity {
	owner := input.Owner
	if owner == "" {
		owner = defaultOwner
	}

	userAgent := fmt.Sprintf(
		"%s/%s/%s (+%s; owner=%s; realm=%s; site=%s; env=%s; surface=%s)",
		product, input.Tool, input.Version, contactURL, owner,
		input.Realm, input.Site, input.Environment, input.Surface,
	)

	return Identity{
		TrafficClass: trafficClass,
		RunID:        input.RunID,
		UserAgent:    userAgent,
		Headers: map[string]string{
			"X-Fulcrum-Internal-Tool":   input.Tool,
			"X-Fulcrum-Traffic-Class":   trafficClass,
			"X-Fulcrum-Monitor-Site":    input.Site,
			"X-Fulcrum-Monitor-Env":     input.Environment,
			"X-Fulcrum-Monitor-Surface": input.Surface,
			"X-Fulcrum-Monitor-Run-Id":  input.RunID,
		},
	}
}
