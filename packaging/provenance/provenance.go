// Package provenance exposes version and revision values stamped by build.sh.
package provenance

// Version and Revision are set with Go linker -X flags for release builds.
var (
	Version  = "development"
	Revision = "unknown"
)

// Build is the machine-readable provenance carried by a binary.
type Build struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
}

// Info returns the stamped build provenance.
func Info() Build {
	return Build{Version: Version, Revision: Revision}
}
