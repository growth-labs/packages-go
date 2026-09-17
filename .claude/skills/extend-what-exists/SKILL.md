---
name: extend-what-exists
description: Before creating any mechanism (table, migration, module, component, worker, client, delivery or auth path) — find the existing one to extend or the home a new capability belongs in, then write the Reuse declaration
---

1. State the need in one sentence.
2. Read `docs/agent/mechanisms.md`; list the candidates in this repo.
3. Read `docs/agent/shared-capabilities.md`; list the packages, services and capabilities that serve the need.
4. Decide: extend `<X>` | new capability in `<home>` | parallel, rejected `<X>` because `<reason>`. Write it in the spec section "Existing mechanisms considered" and as the PR body `Reuse:` line.
5. No home exists: decide it in-task when you own the stream (record a KB decision) or file `platform-request`. Never shim, never stop.
