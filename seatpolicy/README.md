# seatpolicy

Stdlib-only assessment of observed coding-seat quota windows and deterministic
ranking of the estate's public native candidates. Import
`github.com/growth-labs/packages-go/seatpolicy`.

`Assess(now, windows)` validates each supplied session, daily, or weekly
window independently. Usage must be finite and in `[0,100]`; every observation
must be at least as recent as 30 minutes ago, with the exact 30-minute boundary
stale. An optional reset must be strictly after `now`. Unknown, missing, or
stale evidence has nil numeric headroom; a fresh fully used window has numeric
zero. The result gives the smallest remaining percentage, its window and reset,
the oldest observation for a conservative display, and the limiting window's
own observation. Equal headroom chooses session, then daily, then weekly.

`Assess` has no client-specific required-window set. A cockpit reader remains
responsible for its existing Claude session and weekly source checks and Codex
primary-present/secondary-optional check. It maps its source observation to
each parsed window; it does not sum windows or impose native admission rules.

`Rank(now, candidates)` requires fresh weekly evidence on every candidate and
session evidence on Claude, then assesses every supplied window. It rejects
unknown or duplicate public identities, exhausted windows, weekly usage over
90%, and caller-supplied `Busy` candidates. Exactly 90% weekly use is eligible
if all known windows have headroom. It orders eligible Claude seats before Codex;
Claude order is highest limiting headroom, then weekly headroom, then lexical
seat. Codex `codex` is preferred before `codex-fulcrum` regardless of headroom.
The known names are Claude `grizzle`, `growthlabs`, `fulcrum`, `pinball` and Codex
`codex`, `codex-fulcrum`; matching is exact.

The policy ranks observed allowance, not predicted availability. It does not
read a source, launch a process, map paths, hold a seat, or fence an interactive
client. `Busy` is advisory; a native caller must recheck durable occupancy
atomically with its call-budget reservation. It can try the next ranked seat
when the preferred one is busy. See the runnable `ExampleRank` in
`example_test.go`.
