# Execution checklist: client retrieval and token efficiency

**Created:** 2026-11-17

**Status:** Planned only; implementation not started.

The authoritative specification, task acceptance criteria, file scopes, test
matrix and release budgets are in [plan.md](plan.md). Do not mark a task complete
without its verification evidence. Preserve legacy public output and exhaustive
internal/write-helper behavior.

## Foundation

- [ ] T01 — Deterministic synthetic fixtures and reproducible baseline benchmark.
- [ ] T02 — Client metadata/full/projected schemas and public-contract fixtures.
- [ ] Checkpoint A — Current behavior characterized; new API contract reviewed;
      fixtures have no real identifiers; no unsupported public flags exposed.

## Bounded retrieval

- [ ] T03 — Incremental read-only source scanner; compatibility adapters preserved.
- [ ] T04 — Scoped actual-request budget, including retries/session recovery.
- [ ] T05 — Compatible unfiltered-list fast path and streaming get_client.
- [ ] Checkpoint B — One-GET standard Admin first-page/early-lookup cases;
      complete-fixture semantics preserved; write safety regression suite passes.

## Navigation and filtering

- [ ] T06 — Scope-bound, replay-safe, expiring and memory-bounded cursor store.
- [ ] T07 — Public unfiltered pageSize/cursor API and 10,000-client traversal.
- [ ] T08 — Wi-Fi/wired filter-before-limit paged traversal.
- [ ] T09 — Active/inactive search merge and Viewer source/fallback correctness.
- [ ] T10 — Honest totals, missing-field/source warnings and failure reporting.
- [ ] Checkpoint C — Budget/expiry/fork/anomaly cases proven; no false completeness
      or not-found claim; native page 20 is not a global navigation ceiling.

## Token-efficient results

- [ ] T11 — Optional allowlisted fields; mac retained; full default unchanged.
- [ ] T12 — Opt-in envelope whose text parses to exactly structuredContent.
- [ ] Checkpoint D — Sparse/full schemas validate; legacy arrays/notes unchanged;
      13-/50-client token reductions measured without suppressing safety metadata.

## Public qualification and release

- [ ] T13 — Actual MCP client/host interoperability and layered token measurements.
- [ ] T14 — Deterministic request/state/byte/token budgets and CI artifacts.
- [ ] T15 — Public query guide, README/reference/changelog and schema-cache migration.
- [ ] T16 — GET-only disposable-controller qualification and release readiness.
- [ ] Checkpoint E — Full suite, lint/types, docs generation, package/protocol
      checks and declared efficiency gates pass; supported/untested targets labeled.

## Working rules

- Keep changes in small, reviewable PRs using the repository workflow.
- Use GPT Luna at xhigh for small, independent fixture/doc/consistency checks.
- Keep architecture, cursor/security boundaries and merge semantics with the
  primary agent; avoid concurrent edits of shared handler/descriptor files.
- Never use the maintainer's home/controller env as an automatic test fallback.
- Record failures/skips and resource/consistency limitations as carefully as passes.
- Add dated evidence and commit references when marking tasks/checkpoints complete.
