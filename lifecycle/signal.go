package lifecycle

import "os"

// WaitForSignal blocks until signals delivers a value (typically SIGTERM or
// SIGINT registered by the caller through signal.Notify), then arms a
// background watcher for a second signal on the same channel — see
// ArmSecondSignal — and returns the first signal received.
//
// Call this when your daemon's own control flow does nothing else while
// waiting for shutdown: a single goroutine that blocks for the first
// signal, reacts (log, cancel a context), and stands ready to force-exit on
// a repeated one.
func WaitForSignal(signals <-chan os.Signal, forceExit func(os.Signal)) os.Signal {
	received := <-signals
	ArmSecondSignal(signals, forceExit)
	return received
}

// ArmSecondSignal spawns a goroutine that waits for the next value on
// signals and calls forceExit with it, exactly once. forceExit is expected
// to terminate the process (os.Exit and similar) so that a graceful
// shutdown which hangs cannot block a repeated Ctrl-C/SIGTERM forever. A nil
// forceExit arms nothing.
//
// Call this after your own signal handling has already consumed the first
// delivered signal — for example inside the signal branch of a select
// against other channels (an error channel, a done channel) — so a second
// signal still forces the process down while graceful shutdown proceeds on
// the caller's own goroutine.
func ArmSecondSignal(signals <-chan os.Signal, forceExit func(os.Signal)) {
	if forceExit == nil {
		return
	}
	go func() {
		second, ok := <-signals
		if !ok {
			return
		}
		forceExit(second)
	}()
}
