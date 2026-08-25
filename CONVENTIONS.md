# Conventions

## Falsifiable guards

A guard without a test that can fail it is not a guard. Test every guard at
the wiring point where production calls it, not only as an isolated helper.

`testkit.ProveGuard` runs an unsafe case twice. With guards enabled the wiring
must reject it. With the named guard deliberately disabled the same case must
succeed. If both runs fail, the test passed for the wrong reason; if both
succeed, the guard is missing or unwired.

The runnable examples in `testkit/examples/guards_test.go` record the first
three failure modes:

1. A signing-key mode check uses a real existing 0644 file, proving that the
   0600 guard—not a missing path or read failure—rejects it.
2. A payload over the ceiling exercises the public handler, so deleting the
   ceiling cannot leave the package green.
3. A collection over the cap enters through the public wiring point and
   reaches the validator, so an isolated validator test cannot hide missing
   production wiring.

Use literal unsafe fixtures and assert consumer-visible rejection. Do not
grep source code for a guard or assert only that an internal helper was called.
