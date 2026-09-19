package seatpolicy_test

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/growth-labs/packages-go/seatpolicy"
)

var now = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func pct(v float64) *float64 { return &v }

func window(kind seatpolicy.WindowKind, used float64) seatpolicy.Window {
	return seatpolicy.Window{Kind: kind, UsedPercent: pct(used), ObservedAt: now.Add(-time.Minute)}
}

func TestAssessRejectsInvalidWindows(t *testing.T) {
	// Each literal unsafe input catches removal of a separate public guard.
	valid := window(seatpolicy.Weekly, 20)
	tests := []struct {
		name    string
		windows []seatpolicy.Window
		state   seatpolicy.State
		reason  seatpolicy.Reason
	}{
		{"empty", nil, seatpolicy.Unavailable, seatpolicy.NoWindows},
		{"unknown kind", []seatpolicy.Window{{Kind: "monthly", UsedPercent: pct(10), ObservedAt: now}}, seatpolicy.Unavailable, seatpolicy.UnknownWindow},
		{"duplicate kind", []seatpolicy.Window{valid, valid}, seatpolicy.Unavailable, seatpolicy.DuplicateWindow},
		{"missing usage", []seatpolicy.Window{{Kind: seatpolicy.Weekly, ObservedAt: now}}, seatpolicy.Unavailable, seatpolicy.MissingUsage},
		{"negative usage", []seatpolicy.Window{window(seatpolicy.Weekly, -0.1)}, seatpolicy.Unavailable, seatpolicy.InvalidUsage},
		{"above 100", []seatpolicy.Window{window(seatpolicy.Weekly, 100.1)}, seatpolicy.Unavailable, seatpolicy.InvalidUsage},
		{"NaN", []seatpolicy.Window{window(seatpolicy.Weekly, math.NaN())}, seatpolicy.Unavailable, seatpolicy.InvalidUsage},
		{"positive infinity", []seatpolicy.Window{window(seatpolicy.Weekly, math.Inf(1))}, seatpolicy.Unavailable, seatpolicy.InvalidUsage},
		{"negative infinity", []seatpolicy.Window{window(seatpolicy.Weekly, math.Inf(-1))}, seatpolicy.Unavailable, seatpolicy.InvalidUsage},
		{"missing observation", []seatpolicy.Window{{Kind: seatpolicy.Weekly, UsedPercent: pct(10)}}, seatpolicy.Unavailable, seatpolicy.MissingObservation},
		{"future observation", []seatpolicy.Window{{Kind: seatpolicy.Weekly, UsedPercent: pct(10), ObservedAt: now.Add(time.Nanosecond)}}, seatpolicy.Unavailable, seatpolicy.FutureObservation},
		{"exactly 30 minutes old", []seatpolicy.Window{{Kind: seatpolicy.Weekly, UsedPercent: pct(10), ObservedAt: now.Add(-30 * time.Minute)}}, seatpolicy.Stale, seatpolicy.StaleObservation},
		{"reset at now", []seatpolicy.Window{{Kind: seatpolicy.Weekly, UsedPercent: pct(10), ObservedAt: now, ResetAt: now}}, seatpolicy.Stale, seatpolicy.PassedReset},
		{"reset before now", []seatpolicy.Window{{Kind: seatpolicy.Weekly, UsedPercent: pct(10), ObservedAt: now, ResetAt: now.Add(-time.Second)}}, seatpolicy.Stale, seatpolicy.PassedReset},
		{"one stale window among fresh windows", []seatpolicy.Window{valid, {Kind: seatpolicy.Session, UsedPercent: pct(10), ObservedAt: now.Add(-30 * time.Minute)}}, seatpolicy.Stale, seatpolicy.StaleObservation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := seatpolicy.Assess(now, tt.windows)
			if got.State != tt.state || got.Reason != tt.reason || got.HeadroomPercent != nil {
				t.Fatalf("Assess() = %+v; want state %q, reason %q, nil headroom", got, tt.state, tt.reason)
			}
		})
	}
}

func TestAssessUnknownWindowDoesNotEchoSourceText(t *testing.T) {
	got := seatpolicy.Assess(now, []seatpolicy.Window{{
		Kind: "untrusted source fragment", UsedPercent: pct(10), ObservedAt: now,
	}})
	if got.Reason != seatpolicy.UnknownWindow || got.ProblemWindow != "" {
		t.Fatalf("unknown-window diagnostic leaked caller text: %+v", got)
	}
}

func TestAssessReturnsLimitingWindowAndHonestObservation(t *testing.T) {
	reset := now.Add(time.Hour)
	windows := []seatpolicy.Window{
		{Kind: seatpolicy.Weekly, UsedPercent: pct(40), ObservedAt: now.Add(-29*time.Minute - 59*time.Second), ResetAt: now.Add(7 * 24 * time.Hour)},
		{Kind: seatpolicy.Daily, UsedPercent: pct(65), ObservedAt: now.Add(-2 * time.Minute), ResetAt: reset},
		{Kind: seatpolicy.Session, UsedPercent: pct(10), ObservedAt: now.Add(-time.Minute)},
	}
	got := seatpolicy.Assess(now, windows)
	if got.State != seatpolicy.Fresh || got.Reason != seatpolicy.NoReason || got.HeadroomPercent == nil || *got.HeadroomPercent != 35 || got.LimitingWindow != seatpolicy.Daily || !got.ResetAt.Equal(reset) {
		t.Fatalf("Assess() = %+v; want fresh daily 35 with its reset", got)
	}
	if !got.ObservedAt.Equal(now.Add(-29*time.Minute-59*time.Second)) || !got.LimitingObservedAt.Equal(now.Add(-2*time.Minute)) {
		t.Fatalf("observations = %v and %v; want oldest and limiting observations", got.ObservedAt, got.LimitingObservedAt)
	}
	// A fresh exhausted window is known numeric zero, not missing evidence.
	exhausted := seatpolicy.Assess(now, []seatpolicy.Window{window(seatpolicy.Weekly, 100)})
	if exhausted.State != seatpolicy.Fresh || exhausted.HeadroomPercent == nil || *exhausted.HeadroomPercent != 0 {
		t.Fatalf("exhausted Assess() = %+v; want fresh numeric zero", exhausted)
	}
}

func TestAssessTieIsIndependentOfWindowOrderAndDoesNotAlias(t *testing.T) {
	used := 70.0
	windows := []seatpolicy.Window{
		{Kind: seatpolicy.Weekly, UsedPercent: &used, ObservedAt: now.Add(-4 * time.Minute), ResetAt: now.Add(7 * 24 * time.Hour)},
		{Kind: seatpolicy.Session, UsedPercent: pct(70), ObservedAt: now.Add(-3 * time.Minute), ResetAt: now.Add(time.Hour)},
	}
	before := []seatpolicy.Window{windows[0], windows[1]}
	got := seatpolicy.Assess(now, windows)
	reversed := seatpolicy.Assess(now, []seatpolicy.Window{windows[1], windows[0]})
	if !reflect.DeepEqual(got, reversed) || got.LimitingWindow != seatpolicy.Session || !got.ResetAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("tie results: %+v and %+v; want session independent of input order", got, reversed)
	}
	if !reflect.DeepEqual(windows, before) || got.HeadroomPercent == windows[0].UsedPercent || got.HeadroomPercent == windows[1].UsedPercent {
		t.Fatalf("Assess mutated inputs or aliased a usage pointer")
	}
	*got.HeadroomPercent = 999
	if used != 70 || *windows[1].UsedPercent != 70 {
		t.Fatal("returned headroom aliases caller usage")
	}
}

func candidate(client seatpolicy.Client, seat string, busy bool, windows ...seatpolicy.Window) seatpolicy.Candidate {
	return seatpolicy.Candidate{Client: client, Seat: seat, Busy: busy, Windows: windows}
}

func eligibleNames(got seatpolicy.Ranking) []string {
	out := make([]string, len(got.Eligible))
	for i, c := range got.Eligible {
		out[i] = string(c.Client) + "/" + c.Seat
	}
	return out
}

func reasonFor(got seatpolicy.Ranking, client seatpolicy.Client, seat string) seatpolicy.IneligibilityReason {
	for _, c := range got.Ineligible {
		if c.Client == client && c.Seat == seat {
			return c.Reason
		}
	}
	return ""
}

func TestRankPrefersClaudeThenHeadroomAndDeterministicTies(t *testing.T) {
	candidates := []seatpolicy.Candidate{
		candidate(seatpolicy.Codex, "codex", false, window(seatpolicy.Weekly, 1)),
		candidate(seatpolicy.Claude, "growthlabs", false, window(seatpolicy.Session, 30), window(seatpolicy.Weekly, 40)),
		candidate(seatpolicy.Claude, "pinball", false, window(seatpolicy.Session, 30), window(seatpolicy.Weekly, 20)),
		candidate(seatpolicy.Claude, "grizzle", false, window(seatpolicy.Session, 20), window(seatpolicy.Weekly, 30)),
		candidate(seatpolicy.Claude, "fulcrum", false, window(seatpolicy.Session, 20), window(seatpolicy.Weekly, 30)),
	}
	want := []string{"claude/pinball", "claude/fulcrum", "claude/grizzle", "claude/growthlabs", "codex/codex"}
	got := seatpolicy.Rank(now, candidates)
	if !reflect.DeepEqual(eligibleNames(got), want) {
		t.Fatalf("eligible order = %v; want %v", eligibleNames(got), want)
	}
	reversed := make([]seatpolicy.Candidate, len(candidates))
	for i := range candidates {
		reversed[i] = candidates[len(candidates)-1-i]
	}
	if !reflect.DeepEqual(got, seatpolicy.Rank(now, reversed)) {
		t.Fatalf("Rank changes under candidate permutation")
	}
}

func TestRankCodexPrimaryBeforeReserveAndUsesReserveWhenNeeded(t *testing.T) {
	primary := candidate(seatpolicy.Codex, "codex", false, window(seatpolicy.Weekly, 80))
	reserve := candidate(seatpolicy.Codex, "codex-fulcrum", false, window(seatpolicy.Weekly, 10))
	if got := eligibleNames(seatpolicy.Rank(now, []seatpolicy.Candidate{reserve, primary})); !reflect.DeepEqual(got, []string{"codex/codex", "codex/codex-fulcrum"}) {
		t.Fatalf("Codex order = %v", got)
	}
	primary.Busy = true
	got := seatpolicy.Rank(now, []seatpolicy.Candidate{reserve, primary})
	if !reflect.DeepEqual(eligibleNames(got), []string{"codex/codex-fulcrum"}) || reasonFor(got, seatpolicy.Codex, "codex") != seatpolicy.Busy {
		t.Fatalf("busy primary result = %+v", got)
	}
	primary.Busy = false
	primary.Windows = []seatpolicy.Window{window(seatpolicy.Weekly, 91)}
	got = seatpolicy.Rank(now, []seatpolicy.Candidate{reserve, primary})
	if !reflect.DeepEqual(eligibleNames(got), []string{"codex/codex-fulcrum"}) || reasonFor(got, seatpolicy.Codex, "codex") != seatpolicy.WeeklyCeiling {
		t.Fatalf("ineligible primary result = %+v", got)
	}
}

func TestRankRequiresFreshWeeklyAndClaudeSession(t *testing.T) {
	tests := []struct {
		name      string
		candidate seatpolicy.Candidate
		reason    seatpolicy.IneligibilityReason
	}{
		{"codex missing weekly", candidate(seatpolicy.Codex, "codex", false, window(seatpolicy.Session, 20)), seatpolicy.MissingWeekly},
		{"claude missing weekly", candidate(seatpolicy.Claude, "grizzle", false, window(seatpolicy.Session, 20)), seatpolicy.MissingWeekly},
		{"claude missing session", candidate(seatpolicy.Claude, "grizzle", false, window(seatpolicy.Weekly, 20)), seatpolicy.MissingSession},
		{"stale weekly", candidate(seatpolicy.Codex, "codex", false, seatpolicy.Window{Kind: seatpolicy.Weekly, UsedPercent: pct(20), ObservedAt: now.Add(-30 * time.Minute)}), seatpolicy.QuotaUnavailable},
		{"invalid weekly", candidate(seatpolicy.Codex, "codex", false, window(seatpolicy.Weekly, math.NaN())), seatpolicy.QuotaUnavailable},
		{"exhausted session", candidate(seatpolicy.Claude, "grizzle", false, window(seatpolicy.Weekly, 20), window(seatpolicy.Session, 100)), seatpolicy.Exhausted},
		{"exhausted daily", candidate(seatpolicy.Codex, "codex", false, window(seatpolicy.Weekly, 20), window(seatpolicy.Daily, 100)), seatpolicy.Exhausted},
		{"weekly above 90", candidate(seatpolicy.Codex, "codex", false, window(seatpolicy.Weekly, 90.0001)), seatpolicy.WeeklyCeiling},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := seatpolicy.Rank(now, []seatpolicy.Candidate{tt.candidate})
			if len(got.Eligible) != 0 || len(got.Ineligible) != 1 || got.Ineligible[0].Reason != tt.reason {
				t.Fatalf("Rank() = %+v; want one %q ineligible result", got, tt.reason)
			}
			if tt.reason == seatpolicy.QuotaUnavailable && (got.Ineligible[0].Assessment.HeadroomPercent != nil || got.Ineligible[0].Assessment.Reason == seatpolicy.NoReason) {
				t.Fatalf("missing typed assessment diagnostic: %+v", got.Ineligible[0])
			}
		})
	}
	for _, client := range []seatpolicy.Client{seatpolicy.Claude, seatpolicy.Codex} {
		seat := "codex"
		windows := []seatpolicy.Window{window(seatpolicy.Weekly, 90)}
		if client == seatpolicy.Claude {
			seat = "grizzle"
			windows = append(windows, window(seatpolicy.Session, 40))
		}
		got := seatpolicy.Rank(now, []seatpolicy.Candidate{candidate(client, seat, false, windows...)})
		if len(got.Eligible) != 1 {
			t.Fatalf("%s exactly 90%% weekly = %+v; want eligible", client, got)
		}
	}
}

func TestRankRejectsUnknownAndDuplicatePublicIdentities(t *testing.T) {
	valid := []seatpolicy.Window{window(seatpolicy.Weekly, 10), window(seatpolicy.Session, 10)}
	candidates := []seatpolicy.Candidate{
		candidate(seatpolicy.Claude, "grizzle", false, valid...),
		candidate(seatpolicy.Claude, "grizzle", true, valid...),
		candidate(seatpolicy.Claude, "custom", false, valid...),
		candidate(seatpolicy.Codex, "grizzle", false, valid...),
		candidate("other", "pinball", false, valid...),
		candidate(seatpolicy.Codex, "codex-fulcrum", false, window(seatpolicy.Weekly, 10)),
	}
	got := seatpolicy.Rank(now, candidates)
	if !reflect.DeepEqual(eligibleNames(got), []string{"codex/codex-fulcrum"}) || len(got.Ineligible) != 5 {
		t.Fatalf("Rank() = %+v; want only known unique reserve eligible", got)
	}
	duplicateCount := 0
	for _, c := range got.Ineligible {
		if c.Client == seatpolicy.Claude && c.Seat == "grizzle" && c.Reason == seatpolicy.DuplicateIdentity {
			duplicateCount++
		}
	}
	if duplicateCount != 2 || reasonFor(got, seatpolicy.Claude, "custom") != seatpolicy.UnknownIdentity || reasonFor(got, seatpolicy.Codex, "grizzle") != seatpolicy.UnknownIdentity || reasonFor(got, "other", "pinball") != seatpolicy.UnknownIdentity {
		t.Fatalf("identity diagnostics = %+v", got.Ineligible)
	}
	reversed := make([]seatpolicy.Candidate, len(candidates))
	for i := range candidates {
		reversed[i] = candidates[len(candidates)-1-i]
	}
	if !reflect.DeepEqual(got, seatpolicy.Rank(now, reversed)) {
		t.Fatal("identity diagnostics depend on candidate order")
	}
}

func TestRankDoesNotMutateOrAliasCandidateInputs(t *testing.T) {
	windows := []seatpolicy.Window{window(seatpolicy.Weekly, 10)}
	candidates := []seatpolicy.Candidate{candidate(seatpolicy.Codex, "codex", false, windows...)}
	before := []seatpolicy.Candidate{candidate(seatpolicy.Codex, "codex", false, windows...)}
	got := seatpolicy.Rank(now, candidates)
	if !reflect.DeepEqual(candidates, before) || len(got.Eligible) != 1 || got.Eligible[0].Assessment.HeadroomPercent == windows[0].UsedPercent {
		t.Fatalf("Rank mutated or aliased input: %+v", got)
	}
	*got.Eligible[0].Assessment.HeadroomPercent = 999
	if *windows[0].UsedPercent != 10 {
		t.Fatal("Rank result aliases caller usage")
	}
}
