# Execution checklist: client retrieval and token efficiency

**Created:** 2026-11-17

**Status:** Implementation and local testing complete (2026-11-17); external host/hardware qualification and release remain pending.

Evidence: [local test record](../docs/testing/client-queries-2026-11-17.md).
Implementation commits: `05c58a9`, `af23f3b`.

The authoritative specification, task acceptance criteria, file scopes, test
matrix and release budgets are in [plan.md](plan.md). Do not mark a task complete
without its verification evidence. Preserve legacy public output and exhaustive
internal/write-helper behavior.

## Foundation

- [x] T01 — Deterministic synthetic fixtures and reproducible baseline benchmark.
- [x] T02 — Client metadata/full/projected schemas and public-contract fixtures.
- [x] Checkpoint A — Current behavior characterized; new API contract reviewed;
      fixtures have no real identifiers; no unsupported public flags exposed.

## Bounded retrieval

- [x] T03 — Incremental read-only source scanner; compatibility adapters preserved.
- [x] T04 — Scoped actual-request budget, including retries/session recovery.
- [x] T05 — Compatible unfiltered-list fast path and streaming get_client.
- [x] Checkpoint B — One-GET standard Admin first-page/early-lookup cases;
      complete-fixture semantics preserved; write safety regression suite passes.

## Navigation and filtering

- [x] T06 — Scope-bound, replay-safe, expiring and memory-bounded cursor store.
- [x] T07 — Public unfiltered pageSize/cursor API and 10,000-client traversal.
- [x] T08 — Wi-Fi/wired filter-before-limit paged traversal.
- [x] T09 — Active/inactive search merge and Viewer source/fallback correctness.
- [x] T10 — Honest totals, missing-field/source warnings and failure reporting.
- [x] Checkpoint C — Budget/expiry/fork/anomaly cases proven; no false completeness
      or not-found claim; native page 20 is not a global navigation ceiling.

## Token-efficient results

- [x] T11 — Optional allowlisted fields; mac retained; full default unchanged.
- [x] T12 — Opt-in envelope whose text parses to exactly structuredContent.
- [x] Checkpoint D — Sparse/full schemas validate; legacy arrays/notes unchanged;
      13-/50-client token reductions measured without suppressing safety metadata.

## Public qualification and release

- [ ] T13 — MCP SDK slim/full validation and layered token measurements pass; actual installed assistant-host reload/adapter qualification remains unverified.
- [x] T14 — Deterministic request/state/byte/token budgets and CI artifacts.
- [x] T15 — Public query guide, README/reference/changelog and schema-cache migration.
- [ ] T16 — GET-only Omada 6.2.14.11 Owner/Viewer lab qualification passes; 5.x/hardware qualification, remote CI and release actions remain pending.
- [x] Checkpoint E — Full suite, lint/types, docs generation, package/protocol
      checks and declared efficiency gates pass; supported/untested targets labeled.

## Working rules

- Keep changes in small, reviewable PRs using the repository workflow.
- Use GPT-6 Luna at high for small, independent fixture/doc/consistency checks.
- Keep architecture, cursor/security boundaries and merge semantics with the
  primary agent; avoid concurrent edits of shared handler/descriptor files.
- Never use the maintainer's home/controller env as an automatic test fallback.
- Record failures/skips and resource/consistency limitations as carefully as passes.
- Add dated evidence and commit references when marking tasks/checkpoints complete.
