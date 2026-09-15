package lifecycle

import (
	"context"
	"sync"
)

// Target is a named component with a graceful shutdown function: the shape
// every hand-rolled "drain these servers" list in this estate's daemons
// converged on independently (foundryd's drainTarget, golemd's per-listener
// Shutdown calls).
type Target struct {
	// Name identifies the target for reporting; it never affects ordering
	// or concurrency — every target drains at the same time regardless of
	// position in the slice.
	Name string
	// Shutdown is called once, with the Drain call's context. It must
	// return once the target has stopped accepting new work and finished
	// or abandoned what it had in flight. A nil Shutdown is a caller
	// programming error and panics when Drain reaches it, the same as
	// invoking a nil function directly would.
	Shutdown func(context.Context) error
}

// Drain calls every target's Shutdown concurrently against ctx and blocks
// until all of them have returned, regardless of individual failures — one
// hung or failing target never blocks or skips the others. report, when
// non-nil, is called exactly once per target, synchronously from that
// target's own goroutine, with its Shutdown error (nil on success); callers
// use it to log or collect failures. Give ctx a deadline (context.WithTimeout)
// to bound how long Drain can block; Shutdown implementations are expected
// to honor ctx and return once it is done rather than run unbounded.
func Drain(ctx context.Context, report func(Target, error), targets ...Target) {
	var drains sync.WaitGroup
	drains.Add(len(targets))
	for _, target := range targets {
		target := target
		go func() {
			defer drains.Done()
			err := target.Shutdown(ctx)
			if report != nil {
				report(target, err)
			}
		}()
	}
	drains.Wait()
}
