# pg

`pg` provides forward-only PostgreSQL migrations and pgx transaction helpers.

`Runner.Apply` validates a strictly increasing migration list, creates the
`packages_go_schema_migrations` ledger, detects version/name drift, and applies
each pending migration in its own transaction. It calls the configured
`ExportGate` once before the first pending migration and refuses zero, future,
stale, or non-SHA-256 receipts. The default maximum export age is 24 hours;
services can set `Runner.MaxExportAge` to a tighter policy.

An operator may set `ApplyOptions.WaiveExport` only with a non-empty
`WaiverReason`. The reason is recorded beside every applied version. A run with
no pending migrations does not call the gate or require a waiver.

Use `WithTx` when an application operation—not a migration—needs one owned pgx
transaction with commit-on-success and rollback-on-error behavior.
