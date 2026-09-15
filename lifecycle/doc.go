// Package lifecycle gives Go daemons a shared shutdown harness: waiting for
// an OS shutdown signal with an explicit force-exit on a repeated one, and
// draining a set of named components concurrently against a shutdown
// deadline.
//
// It generalizes the shape every hand-rolled daemon main in this estate
// converged on independently — foundryd's drainTarget/drainIntakes plus its
// second-signal force-exit (internal/daemon/run.go), and foundry-runner's
// near-identical signal goroutine (cmd/foundry-runner/main.go), both in
// fulcrum-labs/foundry — into one implementation instead of N copies.
//
// This package is stdlib-only and holds no opinion on what a daemon does
// before or after shutdown: it does not run schedulers, does not define
// receipts, does not touch observability, and does not sign anything. Those
// stay daemon-specific, or their own future extraction, until a second real
// use of each exists independently of this one.
package lifecycle
