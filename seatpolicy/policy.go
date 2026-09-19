// Package seatpolicy assesses observed quota windows and ranks known public
// coding-seat candidates. It neither reads observations nor reserves seats.
package seatpolicy

import (
	"math"
	"sort"
	"time"
)

// MaxObservationAge matches the cockpit's local allowance freshness contract.
// An observation exactly this old is stale.
const MaxObservationAge = 30 * time.Minute

type WindowKind string

const (
	Session WindowKind = "session"
	Daily   WindowKind = "daily"
	Weekly  WindowKind = "weekly"
)

// Window is one independently observed quota limit. A zero ResetAt means the
// source did not supply a reset, which is allowed. UsedPercent nil is unknown.
type Window struct {
	Kind        WindowKind
	UsedPercent *float64
	ObservedAt  time.Time
	ResetAt     time.Time
}

type State string

const (
	Fresh       State = "fresh"
	Unavailable State = "unavailable"
	Stale       State = "stale"
)

// Reason is a static diagnostic. It never contains source content.
type Reason string

const (
	NoReason           Reason = ""
	NoWindows          Reason = "no_windows"
	UnknownWindow      Reason = "unknown_window"
	DuplicateWindow    Reason = "duplicate_window"
	MissingUsage       Reason = "missing_usage"
	InvalidUsage       Reason = "invalid_usage"
	MissingObservation Reason = "missing_observation"
	FutureObservation  Reason = "future_observation"
	StaleObservation   Reason = "stale_observation"
	PassedReset        Reason = "passed_reset"
)

// Assessment reports the smallest remaining percentage, never a sum.
// ObservedAt is the oldest supplied observation, suitable for a conservative
// display timestamp. LimitingObservedAt belongs to LimitingWindow; ResetAt
// belongs to that same window. An invalid assessment has nil HeadroomPercent.
type Assessment struct {
	State              State
	Reason             Reason
	ProblemWindow      WindowKind
	HeadroomPercent    *float64
	LimitingWindow     WindowKind
	ResetAt            time.Time
	ObservedAt         time.Time
	LimitingObservedAt time.Time
}

// Assess validates every supplied window at now. It does not impose a set of
// required kinds or a native-admission ceiling. Equal headroom is resolved in
// session, daily, weekly order, independent of input order.
func Assess(now time.Time, windows []Window) Assessment {
	if len(windows) == 0 {
		return invalid(Unavailable, NoWindows, "")
	}
	ordered := append([]Window(nil), windows...)
	sort.Slice(ordered, func(i, j int) bool {
		left, right := kindOrder(ordered[i].Kind), kindOrder(ordered[j].Kind)
		if left != right {
			return left < right
		}
		return ordered[i].Kind < ordered[j].Kind
	})
	seen := make(map[WindowKind]bool, len(ordered))
	for _, w := range ordered {
		if kindOrder(w.Kind) == 3 {
			return invalid(Unavailable, UnknownWindow, "")
		}
		if seen[w.Kind] {
			return invalid(Unavailable, DuplicateWindow, w.Kind)
		}
		seen[w.Kind] = true
	}
	result := Assessment{State: Fresh}
	for _, w := range ordered {
		if w.UsedPercent == nil {
			return invalid(Unavailable, MissingUsage, w.Kind)
		}
		used := *w.UsedPercent
		if math.IsNaN(used) || math.IsInf(used, 0) || used < 0 || used > 100 {
			return invalid(Unavailable, InvalidUsage, w.Kind)
		}
		if w.ObservedAt.IsZero() {
			return invalid(Unavailable, MissingObservation, w.Kind)
		}
		if w.ObservedAt.After(now) {
			return invalid(Unavailable, FutureObservation, w.Kind)
		}
		if now.Sub(w.ObservedAt) >= MaxObservationAge {
			return invalid(Stale, StaleObservation, w.Kind)
		}
		if !w.ResetAt.IsZero() && !w.ResetAt.After(now) {
			return invalid(Stale, PassedReset, w.Kind)
		}
		if result.ObservedAt.IsZero() || w.ObservedAt.Before(result.ObservedAt) {
			result.ObservedAt = w.ObservedAt
		}
		headroom := 100 - used
		if result.HeadroomPercent == nil || headroom < *result.HeadroomPercent {
			result.HeadroomPercent = &headroom
			result.LimitingWindow = w.Kind
			result.ResetAt = w.ResetAt
			result.LimitingObservedAt = w.ObservedAt
		}
	}
	return result
}

func invalid(state State, reason Reason, kind WindowKind) Assessment {
	return Assessment{State: state, Reason: reason, ProblemWindow: kind}
}

func kindOrder(kind WindowKind) int {
	switch kind {
	case Session:
		return 0
	case Daily:
		return 1
	case Weekly:
		return 2
	default:
		return 3
	}
}

type Client string

const (
	Claude Client = "claude"
	Codex  Client = "codex"
)

// Candidate names one of the estate's public client/seat pairs. Busy is
// caller-supplied advisory occupancy; the caller must recheck it atomically
// when reserving actual capacity.
type Candidate struct {
	Client  Client
	Seat    string
	Windows []Window
	Busy    bool
}

type IneligibilityReason string

const (
	UnknownIdentity   IneligibilityReason = "unknown_identity"
	DuplicateIdentity IneligibilityReason = "duplicate_identity"
	MissingWeekly     IneligibilityReason = "missing_weekly"
	MissingSession    IneligibilityReason = "missing_session"
	QuotaUnavailable  IneligibilityReason = "quota_unavailable"
	Exhausted         IneligibilityReason = "exhausted"
	WeeklyCeiling     IneligibilityReason = "weekly_ceiling"
	Busy              IneligibilityReason = "busy"
)

// CandidateResult deliberately copies only public identity and assessment,
// not the caller's mutable Windows slice.
type CandidateResult struct {
	Client     Client
	Seat       string
	Assessment Assessment
	Reason     IneligibilityReason
}

type Ranking struct {
	Eligible   []CandidateResult
	Ineligible []CandidateResult
}

// Rank assesses and orders known candidates. Claude comes first by limiting
// headroom, weekly headroom, then lexical seat. Codex's primary "codex" comes
// before "codex-fulcrum" regardless of headroom. Empty Eligible is a normal
// no-capacity result; this function never claims a durable reservation.
func Rank(now time.Time, candidates []Candidate) Ranking {
	type identity struct {
		client Client
		seat   string
	}
	counts := make(map[identity]int, len(candidates))
	for _, c := range candidates {
		counts[identity{c.Client, c.Seat}]++
	}
	var result Ranking
	for _, c := range candidates {
		item := CandidateResult{Client: c.Client, Seat: c.Seat}
		switch {
		case !knownIdentity(c.Client, c.Seat):
			item.Reason = UnknownIdentity
		case counts[identity{c.Client, c.Seat}] > 1:
			item.Reason = DuplicateIdentity
		case !hasKind(c.Windows, Weekly):
			item.Reason = MissingWeekly
		case c.Client == Claude && !hasKind(c.Windows, Session):
			item.Reason = MissingSession
		default:
			item.Assessment = Assess(now, c.Windows)
			switch {
			case item.Assessment.State != Fresh:
				item.Reason = QuotaUnavailable
			case *item.Assessment.HeadroomPercent <= 0:
				item.Reason = Exhausted
			case weeklyUsed(c.Windows) > 90:
				item.Reason = WeeklyCeiling
			case c.Busy:
				item.Reason = Busy
			}
		}
		if item.Reason == "" {
			result.Eligible = append(result.Eligible, item)
		} else {
			result.Ineligible = append(result.Ineligible, item)
		}
	}
	sort.Slice(result.Eligible, func(i, j int) bool {
		a, b := result.Eligible[i], result.Eligible[j]
		if a.Client != b.Client {
			return a.Client == Claude
		}
		if a.Client == Codex {
			return a.Seat == "codex"
		}
		if *a.Assessment.HeadroomPercent != *b.Assessment.HeadroomPercent {
			return *a.Assessment.HeadroomPercent > *b.Assessment.HeadroomPercent
		}
		aWeekly, bWeekly := weeklyHeadroom(candidates, a.Seat), weeklyHeadroom(candidates, b.Seat)
		if aWeekly != bWeekly {
			return aWeekly > bWeekly
		}
		return a.Seat < b.Seat
	})
	sort.Slice(result.Ineligible, func(i, j int) bool {
		a, b := result.Ineligible[i], result.Ineligible[j]
		if a.Client != b.Client {
			return a.Client < b.Client
		}
		if a.Seat != b.Seat {
			return a.Seat < b.Seat
		}
		return a.Reason < b.Reason
	})
	return result
}

func knownIdentity(client Client, seat string) bool {
	switch client {
	case Claude:
		return seat == "grizzle" || seat == "growthlabs" || seat == "fulcrum" || seat == "pinball"
	case Codex:
		return seat == "codex" || seat == "codex-fulcrum"
	default:
		return false
	}
}

func hasKind(windows []Window, kind WindowKind) bool {
	for _, w := range windows {
		if w.Kind == kind {
			return true
		}
	}
	return false
}

func weeklyUsed(windows []Window) float64 {
	for _, w := range windows {
		if w.Kind == Weekly {
			return *w.UsedPercent
		}
	}
	return 0 // Rank checked that the weekly kind exists before assessment.
}

func weeklyHeadroom(candidates []Candidate, seat string) float64 {
	for _, c := range candidates {
		if c.Client == Claude && c.Seat == seat {
			return 100 - weeklyUsed(c.Windows)
		}
	}
	return 0 // Only unique eligible Claude candidates reach this comparison.
}
