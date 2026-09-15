# fulcrumprojects

Go client for Fulcrum Projects' `/api/v2` surface: the snapshot and changes
reads and the epoch-aware mutations envelope. Fulcrum Projects is the only
task store for the Golem program (ruling 7 of 2026-09-15); a consumer reads
the snapshot, follows the change feed from its cursor, and writes through
mutation batches under the epoch it last saw.

```go
client, err := fulcrumprojects.New(fulcrumprojects.Config{
    BaseURL:  "https://projects.fulcrum-labs.com",
    Token:    token,            // a pre-provisioned device credential, by pointer
    ClientID: "golemd@grant",   // the writer every batch names
})
snapshot, results, err := client.Retry(ctx, func(s fulcrumprojects.Snapshot) ([]fulcrumprojects.Mutation, error) {
    task, err := fulcrumprojects.ProjectTaskCreate("hosting", "Follow up with unpaid hosting customers", fulcrumprojects.PriorityHigh, fulcrumprojects.StatusNext, &ownerMemberID, nil)
    if err != nil { return nil, err }
    return []fulcrumprojects.Mutation{task}, nil
})
```

## Contract facts the client encodes

- **Epoch.** `Batch.Epoch` is the workspace visibility epoch from the last
  snapshot or changes read. It moves only on an admin import or rollback. A
  stale epoch is `409 {"error":"sync_epoch_mismatch"}` → `CodeEpochMismatch`;
  `Retry` re-snapshots and runs the builder exactly once more.
- **Idempotency.** The receipt key is `(workspace, member, clientId,
  mutationId)` and the epoch is folded into the request hash, so a retry
  under a new epoch must carry fresh mutation ids. Every builder mints one;
  `NewMutationID` is the v4 UUID source.
- **Results** come back one per mutation, same order, as a union on
  `status` (`applied`, `answered`, `conflict`, `duplicate`, `rejected`,
  `retryable`). `Results.Applied` reads one applied entity or a typed error.
- **Statuses.** Project tasks admit `Next`, `Waiting`, `Decision`, `Setup`,
  `Blocked`, `Someday` and `Scheduled` (the last two since the G-02
  migration of fulcrum-projects; `AdmitsStatus` is the one place that says
  so). Delegations use `open`, `in-progress`, `waiting`, `done`.
- **Identities.** Members are integers on the wire (`assigneeMemberId`),
  `member:<id>` as entity ids, and a numeric string in
  `delegation.create.assignee`. Projects are referenced by slug as
  `project:<slug>`.
- **Bounds.** 1..32 mutations per batch, 1 MiB body, ids and kinds ≤240
  bytes; the client refuses a batch outside them before sending.

## Fixtures

`testdata/*.json` are schema-derived recordings of the v2 bodies (shapes per
`contracts/sync/*.schema.json` in fulcrum-labs/fulcrum-projects, verified
against the server code on 2026-09-15). The round-trip test replays them
behind an epoch-enforcing fixture server and proves the stale-epoch dance.
No live writes are made by any test.
