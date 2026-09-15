// Package fulcrumprojects is the Go client for Fulcrum Projects' /api/v2
// surface: the snapshot and changes reads and the epoch-aware mutations
// envelope. Fulcrum Projects is the only task store (Golem ruling 7); a
// consumer such as golemd never keeps a task table of its own, it reads the
// snapshot, applies changes since its cursor, and sends mutations under the
// sync epoch it last saw. A stale epoch is a 409 sync_epoch_mismatch the
// client surfaces as a typed error; the caller refreshes and retries once.
//
// The client holds a service principal's credential by pointer and never
// logs it. Every request carries a caller-supplied correlation so a write
// can be traced to the utterance or mission that caused it.
package fulcrumprojects
