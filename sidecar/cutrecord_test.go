package sidecar_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/growth-labs/packages-go/sidecar"
)

func TestParse_GoldenFixture(t *testing.T) {
	payload, err := os.ReadFile("testdata/component-cut.golden.json")
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	record, err := sidecar.Parse(payload)
	if err != nil {
		t.Fatalf("Parse golden fixture: %v", err)
	}

	want := sidecar.CutRecord{
		Store:            "quarry",
		Kind:             sidecar.KindHandoff,
		Cut:              "cut-3f9a1b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
		CapturedAt:       "2026-09-12T07:05:00Z",
		SchemaVersion:    11,
		WriterGeneration: 4,
		ControlLogSHA256: "8843d7f92416211de9ebb963ff4ce28125932878d7b3da6f533f1ffe4a1a6bc",
		ControlLogSeq:    128,
		Cursors: map[string]uint64{
			"writer_generation":                       4,
			"authority.capability_terminals_observed": 512,
		},
		Encrypted:        true,
		CiphertextSHA256: "1220e5c9b0f7d5c3f8b6c1e2a9d4f7b3c5e8a1d6f9b2c4e7a0d3f6b9c2e5a8d1",
		CiphertextBytes:  4718592,
		Recipients:       []string{"recipient-key-01", "recipient-key-02"},
		PlaintextFiles: []sidecar.File{
			{Path: "store.sqlite", Bytes: 4194304, SHA256: "2b6b5a1c8e3f704192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80"},
			{Path: "control-log.jsonl", Bytes: 524288, SHA256: "9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d"},
			{Path: "cursors.json", Bytes: 64, SHA256: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"},
		},
	}

	gotJSON, _ := json.Marshal(record)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("parsed record does not match the golden fixture:\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}

func TestParse_RoundTripsThroughMarshal(t *testing.T) {
	payload, err := os.ReadFile("testdata/component-cut.golden.json")
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	record, err := sidecar.Parse(payload)
	if err != nil {
		t.Fatalf("Parse golden fixture: %v", err)
	}
	reMarshaled, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal parsed record: %v", err)
	}
	again, err := sidecar.Parse(reMarshaled)
	if err != nil {
		t.Fatalf("Parse re-marshaled record: %v", err)
	}
	// CutRecord holds a map and slices, so it isn't comparable with ==;
	// compare both records' own JSON encodings instead.
	firstJSON, _ := json.Marshal(record)
	secondJSON, _ := json.Marshal(again)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("round trip changed the record:\n first: %s\nsecond: %s", firstJSON, secondJSON)
	}
}

func TestParse_RejectsUnknownFields(t *testing.T) {
	_, err := sidecar.Parse([]byte(`{"store":"quarry","kind":"sqlite","cut":"cut-1","capturedAt":"2026-09-12T07:00:00Z","unexpected":"field"}`))
	if err == nil {
		t.Fatal("expected an error for an unknown field")
	}
}

func TestParse_RejectsMalformedJSON(t *testing.T) {
	_, err := sidecar.Parse([]byte("not json"))
	if err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}

func TestValidate(t *testing.T) {
	base := func() sidecar.CutRecord {
		return sidecar.CutRecord{
			Store:      "quarry",
			Kind:       sidecar.KindSQLite,
			Cut:        "cut-1",
			CapturedAt: "2026-09-12T07:00:00Z",
		}
	}

	t.Run("valid minimal sqlite record", func(t *testing.T) {
		if err := base().Validate(); err != nil {
			t.Fatalf("expected a valid record, got %v", err)
		}
	})

	t.Run("missing store", func(t *testing.T) {
		record := base()
		record.Store = ""
		if err := record.Validate(); err == nil {
			t.Fatal("expected an error for a missing store")
		}
	})

	t.Run("unknown kind", func(t *testing.T) {
		record := base()
		record.Kind = "unknown"
		if err := record.Validate(); err == nil {
			t.Fatal("expected an error for an unknown kind")
		}
	})

	t.Run("missing cut identity", func(t *testing.T) {
		record := base()
		record.Cut = ""
		if err := record.Validate(); err == nil {
			t.Fatal("expected an error for a missing cut identity")
		}
	})

	t.Run("missing capturedAt", func(t *testing.T) {
		record := base()
		record.CapturedAt = ""
		if err := record.Validate(); err == nil {
			t.Fatal("expected an error for a missing capturedAt")
		}
	})

	t.Run("malformed capturedAt", func(t *testing.T) {
		record := base()
		record.CapturedAt = "not-a-timestamp"
		if err := record.Validate(); err == nil {
			t.Fatal("expected an error for a malformed capturedAt")
		}
	})

	t.Run("encrypted but missing ciphertext identity", func(t *testing.T) {
		record := base()
		record.Encrypted = true
		if err := record.Validate(); err == nil {
			t.Fatal("expected an error for an encrypted record with no ciphertext identity")
		}
	})

	t.Run("encrypted but no recipients", func(t *testing.T) {
		record := base()
		record.Encrypted = true
		record.CiphertextSHA256 = "abc"
		record.CiphertextBytes = 10
		if err := record.Validate(); err == nil {
			t.Fatal("expected an error for an encrypted record with no recipients")
		}
	})

	t.Run("not encrypted but carries ciphertext identity", func(t *testing.T) {
		record := base()
		record.CiphertextSHA256 = "abc"
		if err := record.Validate(); err == nil {
			t.Fatal("expected an error for a non-encrypted record carrying ciphertext identity")
		}
	})

	t.Run("valid encrypted record", func(t *testing.T) {
		record := base()
		record.Kind = sidecar.KindHandoff
		record.Encrypted = true
		record.CiphertextSHA256 = "abc"
		record.CiphertextBytes = 10
		record.Recipients = []string{"kid-1"}
		if err := record.Validate(); err != nil {
			t.Fatalf("expected a valid record, got %v", err)
		}
	})
}

func TestCapturedAtTime(t *testing.T) {
	record := sidecar.CutRecord{Store: "quarry", CapturedAt: "2026-09-12T07:05:00Z"}
	parsed, err := record.CapturedAtTime()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2026, 9, 12, 7, 5, 0, 0, time.UTC)
	if !parsed.Equal(want) {
		t.Fatalf("got %v, want %v", parsed, want)
	}

	if _, err := (sidecar.CutRecord{Store: "quarry"}).CapturedAtTime(); err == nil {
		t.Fatal("expected an error for an empty capturedAt")
	}
	if _, err := (sidecar.CutRecord{Store: "quarry", CapturedAt: "nope"}).CapturedAtTime(); err == nil {
		t.Fatal("expected an error for an unparseable capturedAt")
	}
}
