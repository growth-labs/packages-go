package lifecycle_test

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/growth-labs/packages-go/lifecycle"
)

// Example is the whole shape of a resident daemon's shutdown path: consume
// a signal, log it, arm a second-signal force-exit, then drain a set of
// named components against a shared deadline. It has no "Output:" section
// on purpose — running it would block on a real signal — so the toolchain
// compiles it on every build without executing it. Both halves are covered
// with synthetic channels in signal_test.go and drain_test.go.
func Example() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)

	received := lifecycle.WaitForSignal(signals, func(os.Signal) {
		logger.Error("second shutdown signal; exiting immediately")
		os.Exit(1)
	})
	logger.Info("shutdown signal received", "signal", received.String())

	drainCtx, cancelDrain := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelDrain()
	lifecycle.Drain(drainCtx, func(target lifecycle.Target, err error) {
		if err != nil {
			logger.Error(target.Name+" drain failed", "error", err)
		}
	},
		lifecycle.Target{Name: "intake", Shutdown: func(ctx context.Context) error { return nil }},
		lifecycle.Target{Name: "runner intake", Shutdown: func(ctx context.Context) error { return nil }},
	)
}
