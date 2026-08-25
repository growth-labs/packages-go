// Package testkit supplies fixture runners and mutation helpers shared by
// conformance and parity suites.
package testkit

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"testing"
)

// LoadJSON decodes one strict JSON fixture from every file matching pattern.
// Files are returned in lexical path order so suite output is deterministic.
func LoadJSON[T any](files fs.FS, pattern string) ([]T, error) {
	matches, err := fs.Glob(files, pattern)
	if err != nil {
		return nil, fmt.Errorf("glob fixtures: %w", err)
	}
	sort.Strings(matches)

	fixtures := make([]T, 0, len(matches))
	for _, match := range matches {
		file, err := files.Open(match)
		if err != nil {
			return nil, fmt.Errorf("open fixture %q: %w", match, err)
		}

		var fixture T
		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&fixture)
		closeErr := file.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("decode fixture %q: %w", match, decodeErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close fixture %q: %w", match, closeErr)
		}
		fixtures = append(fixtures, fixture)
	}
	return fixtures, nil
}

// RunFixtures runs each fixture as a named subtest.
func RunFixtures[T any](t *testing.T, fixtures []T, name func(T) string, run func(*testing.T, T)) {
	t.Helper()
	for _, fixture := range fixtures {
		fixtureName := name(fixture)
		t.Run(fixtureName, func(t *testing.T) {
			run(t, fixture)
		})
	}
}
