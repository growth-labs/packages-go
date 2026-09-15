# lifecycle

Stdlib-only daemon signal + graceful-shutdown harness: wait for an OS
shutdown signal with an explicit force-exit on a repeated one, and drain a
set of named components concurrently against a shutdown deadline.

```sh
go get github.com/growth-labs/packages-go/lifecycle
```

## Use

Signal handling, inside a `select` against other channels (an error
channel, a done channel) — arm the second-signal watcher only after your own
select has consumed the first signal:

```go
select {
case err := <-serveErr:
    return err
case received := <-signals:
    logger.Info("shutdown signal received", "signal", received.String())
    lifecycle.ArmSecondSignal(signals, func(os.Signal) {
        logger.Error("second shutdown signal; exiting immediately")
        os.Exit(1)
    })
}
```

Signal handling, when nothing else runs while waiting:

```go
go func() {
    received := lifecycle.WaitForSignal(signals, func(os.Signal) {
        logger.Error("second shutdown signal; exiting immediately")
        os.Exit(1)
    })
    logger.Info("shutdown signal received", "signal", received.String())
    cancel()
}()
```

Draining named components concurrently, with a shared deadline:

```go
drainCtx, cancelDrain := context.WithTimeout(context.Background(), shutdownGrace)
defer cancelDrain()
lifecycle.Drain(drainCtx, func(target lifecycle.Target, err error) {
    if err != nil {
        logger.Error(target.Name+" drain failed", "error", err)
    }
}, lifecycle.Target{Name: "intake", Shutdown: intake.Shutdown},
   lifecycle.Target{Name: "runner intake", Shutdown: runnerIntake.Shutdown})
```

## Do not use it for

- Scheduling primitives (tickers, cadence, retry/backoff loops): those stay
  daemon-specific until they have their own second real use.
- Receipt interfaces, the observability client, or the signed-release
  envelope: unrelated concerns, deliberately not folded into this package.
- Anything that needs to call back into a specific daemon's domain logic:
  this package must stay importable without pulling in
  `fulcrum-labs/foundry` or any other consumer.

## Extracted at the second real use

`fulcrum-labs/foundry`'s `internal/daemon/run.go` (foundryd) hand-rolled the
select-on-signal-chan-with-second-signal-force-exit shape and the
`drainTarget`/`drainIntakes` named-component drain group. `cmd/foundry-runner`
hand-rolled the same signal shape again, independently, in its own `main.go`.
Both are rewired onto this package in the same change that adds it.
