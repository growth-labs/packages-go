// Package sidecar reads and validates the WH-08 sidecar cut record
// (component-cut.json): the plaintext identity a store owner's cut writes
// beside its (possibly encrypted) payload, and the identity the authority's
// own non-handoff captures write directly.
//
// Extracted at the second real use: fulcrum-labs/foundry's
// backup.ComponentCut (backup/v2_manifest.go, produced and consumed by
// backup/sidecar.go and backup/handoff.go) and fulcrum-labs/quarry's
// sidecarfreshness package, which had reimplemented a narrow, read-only
// subset of this exact JSON shape because Quarry does not otherwise depend
// on the foundry Go module. Both are separately deployed artifacts; a
// shared, dependency-free type avoids a third independent reimplementation
// the next consumer would otherwise be tempted to write.
package sidecar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// File is one payload file's identity inside a capture: its path relative
// to the capture directory, size and content hash.
type File struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Kind is how a sidecar's bytes are read (fulcrum-labs/foundry
// backup.SidecarKind): "sqlite" and "custody" are owner captures of a live
// store; "handoff" is the authority's import of an owner's already
// encrypted capture.
type Kind string

const (
	// KindSQLite is one SQLite database file plus its control log.
	KindSQLite Kind = "sqlite"
	// KindCustody is a directory tree copied verbatim.
	KindCustody Kind = "custody"
	// KindHandoff is the authority's import of an owner-written encrypted
	// cut; the owner already captured, recorded and encrypted it.
	KindHandoff Kind = "handoff"
)

// CutRecord is one sidecar store's cut identity: what was read, when, at
// which schema and writer generation, and where its cursors into the other
// stores stood — the exact plaintext contents of a capture's
// component-cut.json. Restore reconciliation compares Cursors against the
// authority's own head to decide which snapshot is newer.
type CutRecord struct {
	Store            string            `json:"store"`
	Kind             Kind              `json:"kind"`
	Cut              string            `json:"cut"`
	CapturedAt       string            `json:"capturedAt"`
	SchemaVersion    int64             `json:"schemaVersion"`
	WriterGeneration uint64            `json:"writerGeneration"`
	ControlLogSHA256 string            `json:"controlLogSha256,omitempty"`
	ControlLogSeq    uint64            `json:"controlLogSeq"`
	Cursors          map[string]uint64 `json:"cursors,omitempty"`
	// Encrypted marks an owner cut: the payload is one envelope addressed
	// to Recipients (their KIDs, sorted), its bytes and SHA-256 recorded
	// so a reader that cannot decrypt the payload can still check the
	// ciphertext it received; PlaintextFiles is the owner's inventory of
	// the capture inside it, what a restore verifies after decryption.
	Encrypted        bool     `json:"encrypted,omitempty"`
	CiphertextSHA256 string   `json:"ciphertextSha256,omitempty"`
	CiphertextBytes  int64    `json:"ciphertextBytes,omitempty"`
	Recipients       []string `json:"recipients,omitempty"`
	PlaintextFiles   []File   `json:"plaintextFiles,omitempty"`
}

// CapturedAtTime parses CapturedAt as RFC3339 (the format every writer of
// this record uses). It returns an error rather than a zero time on a
// malformed or empty value, so a caller measuring freshness never treats a
// parse failure as "captured at the Unix epoch."
func (r CutRecord) CapturedAtTime() (time.Time, error) {
	if r.CapturedAt == "" {
		return time.Time{}, fmt.Errorf("sidecar: cut record for store %q has no capturedAt", r.Store)
	}
	parsed, err := time.Parse(time.RFC3339, r.CapturedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("sidecar: cut record for store %q has an unparseable capturedAt %q: %w", r.Store, r.CapturedAt, err)
	}
	return parsed, nil
}

// Validate checks the record's shape without touching the filesystem or
// any network: required fields are present, Kind is one of the three known
// values, an encrypted record carries its ciphertext identity and at least
// one recipient, and a non-encrypted record carries none of that — an
// owner-cut record is exactly one or the other, never both.
func (r CutRecord) Validate() error {
	if r.Store == "" {
		return fmt.Errorf("sidecar: cut record store is required")
	}
	switch r.Kind {
	case KindSQLite, KindCustody, KindHandoff:
	default:
		return fmt.Errorf("sidecar: cut record for store %q has an unknown kind %q", r.Store, r.Kind)
	}
	if r.Cut == "" {
		return fmt.Errorf("sidecar: cut record for store %q has no cut identity", r.Store)
	}
	if _, err := r.CapturedAtTime(); err != nil {
		return err
	}
	if r.Encrypted {
		if r.CiphertextSHA256 == "" || r.CiphertextBytes <= 0 || len(r.Recipients) == 0 {
			return fmt.Errorf("sidecar: encrypted cut record for store %q is missing ciphertext identity or recipients", r.Store)
		}
	} else if r.CiphertextSHA256 != "" || r.CiphertextBytes != 0 || len(r.Recipients) != 0 {
		return fmt.Errorf("sidecar: cut record for store %q carries ciphertext identity but is not marked encrypted", r.Store)
	}
	return nil
}

// Parse decodes and validates one component-cut.json payload. Unknown
// fields are rejected: a cut record this package cannot fully account for
// is a shape it does not yet understand, not one to admit silently
// truncated.
func Parse(payload []byte) (CutRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var record CutRecord
	if err := decoder.Decode(&record); err != nil {
		return CutRecord{}, fmt.Errorf("sidecar: parse cut record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return CutRecord{}, err
	}
	return record, nil
}
