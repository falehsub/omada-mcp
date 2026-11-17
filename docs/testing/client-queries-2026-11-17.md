# Client query implementation and local verification — 2026-11-17

Status: implemented and locally tested on `feat/client-read-efficiency`.
Nothing was pushed, deployed to a user's controller, or published as a release.
Package metadata remains 2.3.0; these changes are recorded under Unreleased.

Implementation commits: `05c58a9` (HTTP budgets and checkpoint store), `af23f3b`
(paging, fields, envelope, compatibility adapters and regression coverage).
Qualification and automated budgets are saved in `171999e`.
GPT-6 Luna agents at high assisted with bounded components, adversarial tests,
benchmarking, and independent review. The primary agent integrated and verified
the combined result.

## What changed

- The four client collection tools accept opt-in `pageSize`, `cursor`, `fields`,
  and `resultFormat`. Existing full fields and text arrays remain the defaults.
- Small unfiltered lists and early lookups stop reading once their answer is
  available. Legacy filtered queries still scan their bounded sources for exact
  match counts when possible.
- Paged reads filter before limiting, deduplicate MACs, preserve active search
  precedence, pin Viewer fallback, and retain safe projected suffixes.
- Checkpoints are immutable, scope-bound, expiring, and bounded by count and
  serialized size. HTTP budgets count retries and session recovery.
- Completeness, unknown totals, absent filter fields, anomalous source pages,
  exhausted budgets, and failed continuation remain explicit.

The [public guide](../client-queries.md) describes the contract and limits.

## Verification results

| Check | Result |
| --- | --- |
| Windows / CPython 3.10.11, complete stdlib suite | **312 passed**, 10.105 seconds |
| Linux / Python 3.12 container, read-only source mount, external networking disabled | **312 passed**, 11.565 seconds |
| Ruff 0.17.5 | Passed for `src`, `tests`, `scripts` |
| Mypy 2.4.1 | Passed for all 55 source files and 9 scripts |
| Byte compilation and generated documentation drift check | Passed; inventory unchanged at **54 read / 78 write / 132 total** |
| Wheel and sdist builds | Passed with isolated setuptools 84.2.1 |
| Clean wheel install with `--no-deps` | Passed; wheel metadata has **zero runtime dependencies** |
| Installed-wheel CLI and stdio | Version, 54/132 tool counts, two complete LF-only JSON-RPC frames passed |
| Local container build and CLI | Passed; non-root UID **10001**, 54 read tools, networking disabled |
| Official MCP Python SDK 2.3.0 / jsonschema 4.26.0 | **8 successful calls**, slim and full schema modes, protocol `2025-06-18`, 54 read tools |
| Disposable Omada 6.2.14.11, Owner/Admin account | **12/12** query format checks passed |
| Same disposable controller, confirmed Viewer account | **12/12** checks passed |
| Deterministic efficiency gates with tiktoken 0.14.0 / `o200k_base` | **24/24 gates passed**, tokenizer required |

SDK calls covered full rows, sparse rows, cursor continuation, and envelope
equality. The SDK validated actual output schemas. Text-array and structured
consumers were both exercised. The mock saw zero non-auth mutations.

The disposable controller had no adopted hardware or clients. Both roles allowed
the rich endpoint on this build, so the lab did not exercise a real permission
denial. Synthetic tests separately prove rich denial, fallback pinning, missing
insight fields, and source/role changes after a cursor has emitted data. Lab
query transport permitted only GET and session login. Initial throwaway lab
setup created its own site/accounts. The maintainer's home controller and user
dotenv file were not used. The disposable controller was stopped after testing.

## Measured efficiency

Fixtures contain generated documentation-range addresses and synthetic MACs;
they do not represent the maintainer's network. Request figures exclude initial
authentication. Timings exclude real HTTP latency and controller pacing.

| Operation | Reference | Current result |
| --- | --- | --- |
| Return first 50 of 2,000 clients | 20 collection requests | **1** request, **95% fewer** |
| Controller response bytes for that operation | 980,877 | **48,464**, about **95% fewer** |
| First matching client lookup in a 2,000-row source | 20 requests | **1** request |
| Legacy small-list traced allocation peak | 6,391,063 bytes | About **564 KB**, about **91% lower** in this local sample |
| Stable 10,000-client traversal, pages of 500 | Previously bounded full collector could stop at 2,000 | **10,000 unique rows**, 20 calls, 100 collection requests, no duplicates/omissions |
| Cursor state during that traversal | Limit: 32 entries / 8 MiB serialized | Peak **19 entries / 3,877,725 bytes** |
| Total traced allocation peak during traversal | Includes Python objects and benchmark bookkeeping | **8,620,267 bytes**; serialized-state limit is not an RSS limit |

One local traversal sample took about 1.09 seconds. These timing/allocation
observations are published evidence, not universal speed guarantees or CI timing
thresholds. The archived v2.3.0 reference was remeasured with the same page source;
its unused new fixture budget/store imports were shimmed for compatibility.

| Token layer, fixed fixture | 13 clients | 50 clients |
| --- | ---: | ---: |
| Full 25-field item array | 2,070 | 8,022 |
| Five-field item array | **499** | **1,920** |
| Reduction for item text | **75.9%** | **76.1%** |
| Sparse envelope including completion/projection metadata | **599** | **2,020** |
| Modeled host forwarding legacy text and structured data | 4,292 | 16,196 |
| Modeled host recognizing equal envelope representations | **599** | **2,020** |
| Actual RPC frame bytes: full legacy → sparse envelope | 13,205 → **3,333** | 49,111 → **10,239** |

The five fields are `mac`, `ip`, `wireless`, `active`, and `vlan` (canonical
schema order). Tokens are exact tokenizer counts of these representations,
not actual provider billing. RPC frames still carry both text and structured
representations. The modeled host path counts both when they differ and one
when the parsed envelope equals structured content; an installed Hermes/model
session has not been measured in this run.

The 54-tool function-schema proxy grows from **3,782 to 4,371 tokens**
(**+589 / 15.57%**) to advertise the options. This remains below the 5,200-token
gate. Both counts use the same compact JSON and `mcp__omada__` name prefix. The
plan's earlier 4,108-token schema and 2,072/7,970-token item references used a
different serialization/fixture, so they are not silently treated as this
benchmark's baseline. The new catalog overhead is a real tradeoff; savings
depend on selecting fields and on the host's result handling.

## Review findings and fixes

Independent review and tests found and corrected:

1. Missing, empty, short, overlapping, repeated, or cyclic pages could appear
   complete. Source shape, identity fingerprints, unique coverage and known
   totals now prevent those false completion claims.
2. A missing later `totalRows` erased earlier count evidence. The reader now
   retains the known count and detects a short traversal.
3. Legacy search discarded source truncation metadata. It now propagates
   incompleteness and omits an unverified exact filtered total.
4. Fallback could retain mislabelled rich rows when no page budget remained, or
   lose the count of rows scanned before permission failure. It now discards
   abandoned rows and keeps shared scan accounting, including mid-source failure.
5. Nested request-budget entry could omit its own reauthentication traffic.
   Nested scopes now charge that traffic to both active budgets.
6. Lookup absence could be asserted after a bounded or field-limited scan. Such
   lookups now fail explicitly as incomplete.
7. The disposable lab wrote an obsolete CA setting and selected CN=localhost
   despite SAN=Omada. It now writes `OMADA_CA_BUNDLE`, trusts the captured leaf,
   selects SAN, and keeps certificate/hostname verification enabled.

The final independent source review reported no remaining high-severity finding.
Existing write-helper collection paths were not shortened or projected.
The write safety, gates, session recovery, rollback and anti-stranding suites pass.

The actual HTTP-budget regression injects one `-1600` response per native page:
the first two calls each stop after **24 HTTP attempts / 12 native pages**,
then continue beyond native page 20 and complete the 3,000-row scan without
replaying writes or skipping a native page.

## Artifacts and reproduction

- [Current benchmark JSON](client-efficiency-2026-11-17.json)
- [Archived v2.3.0 reference observations](client-efficiency-v2.3-reference-2026-11-17.json)
- [MCP SDK report](client-interop-2026-11-17.json)
- [Admin lab report](client-lab-admin-2026-11-17.json)
- [Viewer lab report](client-lab-viewer-2026-11-17.json)

```bash
python -m unittest discover -s tests -q
python -m ruff check src tests scripts
python -m mypy src
python -m mypy scripts
python scripts/generate_docs.py --check
python scripts/benchmark_clients.py --check --require-tokens --output reports/client-efficiency.json
python scripts/check_client_interop.py
python scripts/qualify_client_queries.py --env-file /path/to/disposable/viewer.env
python -m build
```

Use an isolated developer environment for ruff, mypy, build, mcp, jsonschema and
tiktoken. CI now records a benchmark artifact and the optional Docker compatibility
workflow exercises the new formats for both accounts. The edited hosted workflows
have not been run remotely in this local-only task.

## Remaining external qualification

- Installed Hermes and another assistant host: actual cached-schema reload and
  model-facing adapter behavior; actual paid-provider token usage if desired.
- 5.x, OC200/OC300 and hardware-populated fleets: not qualified by this empty
  6.2.14.11 lab. The existing compatibility workflow can test available images.
- Additional Python/OS matrix versions remain for hosted CI; local evidence is
  Windows 3.10 and Linux 3.12.
- PR review, remote CI, version bump, publishing and staged user rollout remain
  separate release actions. No claim of production-wide qualification is made.
