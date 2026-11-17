# Implementation plan: scalable client retrieval and token-efficient results

**Created:** 2026-11-17

**Status:** Proposed implementation plan; no runtime changes implemented.

**Audience:** Public omada-mcp users across supported controller builds, account roles, MCP hosts and site sizes.

**Baseline:** omada-mcp 2.3.0; source evaluated at `ffe33e1`, with local validation documentation committed as `655ede9`.

**Proposed release:** 2.4.0, subject to completing the release gates below.

## 1. Objective and boundaries

This plan implements priorities **#2: client retrieval and pagination** and
**#3: result token efficiency** from the public-beta recommendation. It makes
client queries bounded, navigable beyond the current collection cap, and capable
of returning less data without changing existing callers' default output.

The compatibility-workflow refresh (priority #1), recruiting independent beta
users, new controller families, HTTP MCP transport, generic API discovery and
additional write tools are separate work. This plan may consume their evidence;
it does not claim to implement them.

The plan follows the repository's zero-runtime-dependency, Web API v2,
read-only-default and explicit-projection rules. No production/home-network
mutations are part of implementation or validation.

### Success criteria

- A first page of 50 distinct, unfiltered clients from a stable 2,000-client
  Admin fixture requires one successful collection GET after authentication,
  rather than the measured 20. A Viewer may require an initial denied rich GET
  plus one insight GET; continuation must reuse the established source.
- A client at the beginning of a collection can be resolved without collecting
  the remainder. An incomplete search must never claim definitive absence.
- A stable 10,000-client fixture can be traversed through bounded calls without
  increasing the per-call scan limit to the entire inventory.
- Existing no-option calls preserve their default row fields, text-array shape,
  collection ordering and legacy merge rules where results were complete.
  Corrections to false completeness are explicitly documented bug fixes.
- Optional five-field output reduces text-item tokens by at least 70% on the
  existing synthetic 13- and 50-client fixtures, measured with a pinned tokenizer.
- An optional object-envelope format makes text and structured output semantically
  identical, allowing compatible hosts to avoid forwarding duplicate rows.
- Existing tests, new regression tests, static checks and generated-doc checks pass.
  Resource/count budgets are deterministic; wall-clock timings remain observations.

## 2. Baseline evidence and limits

| Observed behavior in 2.3.0 | Measured baseline or source evidence |
|---|---|
| `list_clients(limit=50)`, 2,000 synthetic clients | 20 collection requests; 2,470,427 controller-body bytes |
| Same query with 13 synthetic clients | One collection request |
| `get_client` for the first client in the 2,000-row fixture | 20 collection requests |
| Request 5,000 clients from a 5,000-row fixture | 2,000 returned, 20 pages, `truncated=true` |
| Full client projection | 25 public fields; search may add three conditional fields |
| Text containing 13 / 50 / 500 clients | 2,072 / 7,970 / 79,614 o200k tokens |
| Hypothetical five-field text, 13 / 50 clients | 512 / 1,970 o200k tokens |
| 54 read-only slim function-schema proxy | 4,108 o200k tokens |
| Current list wire representation | Bare array in text; object containing `items`, `count` and metadata in structuredContent |
| Simulated upstream Hermes rendering, 13-client list | 4,828 tokens versus 2,072 in text alone, before further host truncation |
| Separate local regression suite | 250 passed; not a substitute for controller/host qualification |

Token counts are exact for the synthetic strings and `o200k_base` tokenizer,
not observed billing on the operator's active model. Request/body measurements
used mocks; loopback socket tests did not contact a controller. A hypothetical
projection is an implementation target, not an existing feature.

Preserve the raw benchmark methodology when moving it into the repository.
The previous mock constructs full row collections while serving pages; do not
mistake its response-generation cost for application or real-controller latency.
Use an efficient page-serving benchmark fixture and report transport/mock time
separately.

## 3. Current implementation map

| Area | Current behavior and planning implication |
|---|---|
| [clients_read.py](../src/omada_mcp/domains/clients_read.py) | Collection paging at lines 56–142; projection/limit at 157–189; Wi-Fi/wired filtering at 197–240; lookup at 243–258; search at 261–349; output schemas at 352–398. |
| [\_write_fetchers.py](../src/omada_mcp/domains/_write_fetchers.py) | Client helpers at 32–58 discard pagination metadata. Combined search merges inactive then active rows so active values win. Helpers also serve client and wireless write validation. |
| [\_common.py](../src/omada_mcp/domains/_common.py) | `PaginatedList` carries optional counts, pages and truncation metadata. Unknown totals can already be omitted. |
| [\_tool_model.py](../src/omada_mcp/domains/_tool_model.py) | Generic list output schema declares only items/count. Slim schemas retain validation constraints. Extend client schemas deliberately rather than weakening every tool. |
| [tool_specs_read.py](../src/omada_mcp/domains/tool_specs_read.py) | Input/output descriptors for list, Wi-Fi, wired, search and lookup. Public `limit` defaults to 500, minimum 1, maximum 5,000. |
| [server.py](../src/omada_mcp/server.py) | Lines 384–413 render text, structured rows and truncation notes. Preserve the legacy path and introduce opt-in client envelope rendering. |
| [client.py](../src/omada_mcp/client.py) | Auth recovery, pacing, scoped cache, pagination, transport counts and lifecycle cleanup. Request-budget enforcement must be scoped to these reads, not global. |
| [test_phase3_hardening.py](../tests/test_phase3_hardening.py) | Existing tests assert bare text arrays and exact totals for complete small fixtures. |
| [test_review_regressions.py](../tests/test_review_regressions.py) | Existing filter-before-limit and repeated-page protections must continue to hold. |
| [test_tools_and_diagnostics.py](../tests/test_tools_and_diagnostics.py) | Schema/row consistency and deduplication checks constrain field projection. |

Internal `_fetch_clients(limit=0)` is used by doctor, audits, snapshots, LAN
inspection and diagnostics. Shared write helpers are used in write target lookup
and rate-profile reference checks. **Never silently replace these internal
collectors with a short page or sparse projection.** Their completeness and
failure behavior must be tested independently from public bounded calls.

## 4. Chosen public contract

Extend existing tools; do not add another overlapping client-query tool or
increase the 132-tool catalog merely to offer a more efficient mode.

### 4.1 Tools and optional arguments

| Tool | Additions |
|---|---|
| `list_clients`, `list_wifi_clients`, `list_wired_clients`, `search_clients` | `pageSize`, `cursor`, `fields`, `resultFormat` |
| `get_client` | Faster internal streaming lookup; preserve its existing public arguments and object result in this milestone. |
| Other tools, including blocked clients, snapshots, audits and writes | No new public arguments or implicit projection/pagination behavior. |

| Argument | Proposed semantics |
|---|---|
| `limit` | Existing aggregate-return cap, 1–5,000/default 500. Preserve it; do not redefine it as a native page number or scan budget. |
| `pageSize` | Optional integer 1–500; activates bounded paged mode. Default 100 only when starting/resuming paged mode without an explicitly repeated size. It is the maximum returned matching rows, not the controller's native page size. |
| `cursor` | Optional opaque continuation handle; also activates paged mode. Resume only within the same MCP client/session and query context. |
| `fields` | Optional nonempty unique array of exact allowlisted public field names. Full projection remains the default. Always retain `mac` and report the effective selection in `selectedFields`. |
| `resultFormat` | `legacy` (default) or `envelope`. The latter is an opt-in transport representation, not a different collection/query. |

`limit` is mutually exclusive with `pageSize`/`cursor`. Validate this before
controller I/O. A cursor may inherit omitted filters, page size, fields and format;
an explicitly supplied conflicting value is invalid. An omitted `site` still
uses normal site resolution/pinning: repeat the site override when continuing a
query for a non-default site. A cursor never grants cross-site access.

Do not expose tunable raw controller endpoints, arbitrary query strings, unlimited
scan budgets, or controller credentials in these arguments.

### 4.2 Preserve a useful legacy mode

Calls without `pageSize` or `cursor` remain aggregate calls:

- Preserve defaults, row values, text-array behavior and existing filter/merge
  ordering for complete inputs.
- Optimize unfiltered `list_clients` where enough unique rows have been collected
  and controller-reported source totals can be represented truthfully. Preserve
  the existing controller-count interpretation and qualify it where necessary.
- Keep exhaustive bounded collection for legacy filtered queries if it is needed
  to preserve their exact matched totals or active/inactive merge ordering.
  Do not fake exact totals just to stop early.
- Propagate upstream incomplete metadata for search. A bounded or anomalous source
  scan cannot produce `truncated=false` and an apparently exact matched total.
- Keep internal `limit=0` collector behavior separate from the public schema,
  including its current safeguards. Do not remove bounds or introduce cursors
  into write safety checks through an incidental refactor.

The fast path is not permission to return different clients or to suppress
controller errors that affect completeness.

### 4.3 Paged mode and ordering

Paged mode introduces a specifically documented traversal contract:

- Native collection page size stays 100 initially. Do not assume larger native
  pages work across controller families without evidence.
- Process source rows incrementally, normalize/deduplicate identities, apply all
  query/type filters, then apply the returned matching-row cap.
- Preserve source encounter order within a traversal. This is not a sorted or
  transactionally consistent snapshot.
- For Admin `search_clients(active omitted)`, process the active stream before
  the inactive stream, retaining seen MACs across continuation calls. This makes
  active rows win without first collecting both sources. This **opt-in ordering**
  differs from legacy combined search, whose ordering must remain unchanged.
- Record the winning active MAC before applying search/type filters. An active
  row that fails a filter must still suppress its inactive duplicate; otherwise
  an older inactive value could incorrectly re-enter the query result.
- For explicit active/inactive searches, use the corresponding source and validate
  matches using full normalized internal rows.
- For Viewer insight fallback, preserve that source's first-observed MAC
  deduplication semantics; do not claim the same active-precedence guarantee as
  the two-stream Admin path.
- A row without a usable MAC is not silently dropped or assigned a fabricated
  identity. Preserve it by source position and report an identity warning.
- Cross-call additions/removals/reordering can still cause omissions or
  inconsistencies in page-number APIs. Return `consistency="bestEffort"`;
  deduplication does not turn the controller API into a snapshot.

For a stable 10,000-client fixture, navigating past native page 20 must work:
the per-call budget is a window, not a permanently enforced global page number.

### 4.4 Metadata and completion semantics

Maintain `items` and `count`, the row types, and existing pagination fields.
Declare additional client metadata explicitly in outputSchema.

| Field | Meaning |
|---|---|
| `count` | Rows in this response, never the collection total. |
| `totalRows` | Exact matched unique total only when established; omit when unknown. Legacy unfiltered controller totals retain their documented source meaning and are qualified. |
| `totalRowsExact` | Whether totalRows is an exact query-result count. False or absent must not be presented as an exact total. |
| `totalRowsSource` | `controller`, `observed` or `matched`; identifies the basis of a reported totalRows value. |
| `sourceTotalRows` | Optional controller-advertised source count, not an exact filtered/deduplicated total. Do not sum overlapping active/inactive totals. |
| `rowsScanned` | Raw rows actually examined in this call; distinguish from rows downloaded in a native page. |
| `pagesFetched` | Successful native pages in this call; exclude initial authentication. |
| `controllerRequests` | Actual HTTP attempts attributable to the query, including rejected probes/recovery inside the query; document initial authentication separately. |
| `maxPages` | Per-call page-attempt budget, not the highest native page navigable. |
| `hasMore` | More source positions may be examined; does not promise another matching row. |
| `nextCursor` | Opaque handle when safe continuation is possible; omit when unavailable. |
| `complete` | True only when every required source is exhausted without uncertainty. |
| `truncated` / `truncationReason` | Backward-compatible partial-result indicator and readable explanation. |
| `stopReason` | Stable code: `complete`, `result_limit`, `scan_budget`, `traversal_limit`, `repeated_page`, `source_error`, `source_changed`, `field_unavailable` or `cursor_capacity`. |
| `consistency` | `bestEffort` for paged traversal. |
| `source` / `warnings` | Safe source classification and availability warnings; no tokens, raw error bodies or endpoint URLs. |
| `selectedFields` | Effective public field selection when projection was requested; includes mac. |

Explicit count mapping:

- Legacy unfiltered `list_clients` retains its existing numeric totalRows. If
  derived from a reported controller count, mark totalRowsSource=`controller`
  and mirror that reported count in sourceTotalRows. Set totalRowsExact=false
  unless exhaustion without anomalies establishes that it equals the complete
  unique matched count. A capped result is not evidence of that equality.
- If a legacy result's numeric totalRows is only an observed bounded prefix,
  retain the number for compatibility but mark totalRowsSource=`observed` and
  totalRowsExact=false. Omit sourceTotalRows when the controller supplied none.
- Complete legacy filtered/merged collection can report its exact unique matched
  total, even when returned rows are capped: totalRowsSource=`matched` and
  totalRowsExact=true. An incomplete scan cannot use that qualification.
- Paged mode omits totalRows until the exact matched total has been established;
  it may still expose sourceTotalRows when the selected source supplies a count.
  Never add overlapping source counts to fabricate a union total.

A full page with unknown totals may legitimately produce a cursor whose next
call finds no matches. An empty page with `complete=false` is valid when the scan
budget was consumed by nonmatches. Empty/incomplete is never definitive absence.

An unchanged or repeated page is not evidence of exhaustion. Detect repeated
fingerprints including nonadjacent cycles within a bounded history; return an
incomplete/anomaly outcome. Do not issue endless continuation cursors for a
controller that ignores its page parameter.

Use normalized identities and stable public fields for progress fingerprints,
excluding traffic counters and timestamps that can change on every fetch. A
legitimate overlap between adjacent pages must not be mistaken for a complete
repeated page; identity deduplication and page-progress detection are separate.

If required filter evidence is unavailable, use `field_unavailable`, keep
`complete=false`, omit an exact matched total, and explain which public fields
could not be evaluated. Source exhaustion alone cannot prove that query's result
is empty. A per-traversal hard ceiling uses `traversal_limit`; a changed pinned
source uses `source_changed`. Neither is a normal end-of-results indication.

If response shape or totals are malformed, do not silently substitute an empty
healthy collection. Distinguish unsupported features, permission denials,
transport errors and a confirmed empty page. Totals changing between calls are
observations, not exact query counts.

### 4.5 Opaque cursor design and resource limits

Use a small stdlib-only, process-local cursor store owned by `OmadaClient`.
Native Omada pagination is numbered; these are MCP-side continuations, not a
claimed controller-native cursor.

Recommended starting limits (validate before freezing release constants):

- At most 32 retained cursor checkpoints per client.
- Idle expiry 10 minutes; absolute traversal lifetime one hour.
- At most 8 MiB of serialized safe checkpoint state in the store, plus measured
  Python object overhead. Track both serialized size and benchmarked heap use.
- Native page size 100; at most 20 native page attempts per call across all
  sources; at most 24 actual controller requests inside a query.
- At most 100,000 consumed source rows per traversal before an explicit hard
  incomplete outcome. This is a safety ceiling, not a new supported-site claim.
- Keep only the current unconsumed native-page suffix (at most 100 projected
  rows), normalized identity history, source positions, query options and bounded
  page fingerprints. Do not cache the entire inventory or raw controller objects.

Use unpredictable `secrets.token_urlsafe(32)` handles with a short version prefix,
bounded length and syntax. Store context server-side; do not encode credentials,
MAC lists, IPs or filesystem paths into client-visible cursor strings.

Bind each checkpoint to the tool, resolved controller/site, authenticated
principal, selected source/source phase, canonical filters, page size, fields and
format. Existing authentication and cross-site gates remain authoritative.

A checkpoint must be replay-safe: retries of the same cursor must not advance
shared state and silently skip the next page. Prefer immutable checkpoints with
bounded copy-on-write state. Under unchanged fixtures, replay returns the same
rows; under changing controllers it retains the same source position and the
documented best-effort consistency. Concurrent forks must not corrupt each other.

LRU eviction/expiry/restart returns an explicit invalid/expired-cursor error,
never a successful empty result. No cursor persistence across process restarts.
Close/teardown clears the store. Invalid handle syntax, incompatible parameters
and unknown handles fail before controller I/O. An oversized checkpoint ends with
`cursor_capacity` and explicit incompleteness instead of exceeding the bound.

The request budget must count actual attempts, including GET retries and
re-authentication occurring inside the query. Use a scoped read-budget mechanism
at request dispatch; do not mutate shared Config/timeouts or change write gates.
Do not promise a wall-clock SLA: per-request timeout, pacing and authentication
still apply.

### 4.6 Error, fallback and lookup behavior

- Preserve rich collection and insight role fallback. Before any result is
  emitted, discard a failed partial rich attempt and restart fallback cleanly.
  Count its work against the same query budget.
- Pin the successful source in the cursor. A failure or privilege change after
  earlier pages were emitted cannot silently switch sources or mix inventories;
  invalidate/stop that traversal with a clear restart instruction.
- Reuse one authenticated session. Cursor use must not log in for every page.
  A legitimate session refresh does not make a cursor an authentication bypass.
- Stream `get_client` in existing encounter order, keeping MAC/name/hostname/IP
  matching semantics. Stop at the first match; do not introduce an unverified
  direct endpoint whose shape or active-client semantics differ.
- Exhausted lookup with no match retains the ordinary not-found behavior.
  Budget/anomaly-limited lookup instead reports incomplete search and suggests
  narrower/paged discovery. Do not claim the client does not exist.
- Do not broaden fallback/retry conditions casually. In particular, never change
  the no-blind-replay policy for writes while introducing a read optimization.

## 5. Token-efficient output contract

### 5.1 Field selection

Apply presentation projection after full internal identity normalization,
deduplication, filtering and lookup/matching logic. Filtering by SSID/VLAN/type
must still work when the selected response excludes those fields.

Allowed base keys are the existing public projection:

`mac, name, hostName, ip, wireless, guest, active, ssid, apName, networkName,
vlan, download, upload, duration, lastSeen, signal, rssi, signalLevel, snr,
txRate, rxRate, uptime, connectType, radioId, channel`.

Only `search_clients` additionally allows `blocked, fixedIp, fixedNetId`.
Reject arbitrary controller keys, wildcard selection, empty arrays, duplicate
names, wrong case and excessive arrays before I/O. Use enum/minItems/maxItems/
uniqueItems constraints already supported by the input validator.

Use canonical field ordering for stable snapshots/token measurements. Always
retain mac and expose the effective selectedFields. Preserve existing value
types, nullability and missing-value behavior; do not invent Viewer-only data.
Optional search extras absent in full output remain absent when selected.

### 5.2 Output schemas

The current client item schema requires 16 fields. Sparse results cannot reuse
it unchanged.

Keep the full item schema for default results and introduce a client-specific
projected variant that requires mac, permits only typed allowlisted properties
and forbids unknown controller fields. Discriminate selected output through the
selectedFields metadata. Preserve root `type=object`, properties, and required
items/count in both slim and full descriptor modes. Do not weaken every generic
list schema or reuse sparse rows inside snapshots/write validations.

Validate actual complete, sparse and paged results using a real JSON Schema/MCP
client in developer-only tests. A model's input schema cannot express that output
keys exactly match requested fields: enforce that invariant in handler tests too.

Schema widening for opted-in sparse output is an additive minor-release change.
Host schema caches must refresh on upgrade; default runtime output remains
compatible. Publish examples and migration notes for consumers that validate
against a previously cached output schema.

### 5.3 Envelope rendering

Default `resultFormat="legacy"` retains a bare array in content[0].text, an
items/count object in structuredContent, and the existing truncation-note behavior.

For `resultFormat="envelope"`:

1. Build one safe object containing rows and all applicable pagination,
   projection and warning metadata.
2. Assign that object to structuredContent.
3. Serialize the same object as the single text block.
4. Include truncation explanation inside the object; do not append a second
   independently worded text note.
5. Require `json.loads(content[0].text) == structuredContent`, regardless of
   compact/pretty output.

Use typed client result metadata/internal wrappers rather than ad-hoc dictionaries
that expose raw rows. Restrict this opt-in serializer to the four client list/
search tools. Other list tools, object tools and write envelopes are unchanged.

The object is still duplicated on the MCP wire for compatibility. The goal is to
allow a host's semantic duplicate detection to collapse model-visible copies;
never promise that every host does so. Do not remove structuredContent, MCP
outputSchema or the legacy representation globally.

### 5.4 Usage examples

Legacy calls continue to work:

```json
{"limit": 50}
```

Start a bounded, compact query:

```json
{
  "site": "<site-id>",
  "pageSize": 50,
  "fields": ["mac", "name", "ip", "ssid", "vlan"],
  "resultFormat": "envelope"
}
```

Resume using the same tool and site context:

```json
{
  "site": "<site-id>",
  "cursor": "<nextCursor-from-previous-response>"
}
```

Representative partial envelope; values illustrate the contract, not a new
measured production result:

```json
{
  "items": [{"mac": "02:00:00:00:00:01", "name": "example-client", "ip": "192.0.2.123", "ssid": "Example", "vlan": 20}],
  "count": 1,
  "selectedFields": ["mac", "name", "ip", "ssid", "vlan"],
  "pagesFetched": 1,
  "controllerRequests": 1,
  "maxPages": 20,
  "sourceTotalRows": 10000,
  "totalRowsExact": false,
  "complete": false,
  "truncated": true,
  "truncationReason": "More source rows remain; continue with nextCursor",
  "stopReason": "result_limit",
  "hasMore": true,
  "nextCursor": "<opaque-handle>",
  "consistency": "bestEffort"
}
```

Here totalRows is deliberately absent. The illustrative request that produced
this one-row page would have pageSize=1; it is not the preceding 50-row example.

## 6. Implementation sequence

Use the companion [execution checklist](todo.md). Each task is a focused slice;
keep source changes to roughly 1–5 files per task. Generated-doc changes can be
separate mechanical commits. Do not implement this entire document as one patch.

### T01: Baseline fixtures and reproducible measurements

**Dependencies:** None. **Size:** M.

**Files:** new `tests/client_query_fixtures.py`, new
`scripts/benchmark_client_reads.py`, focused benchmark tests.

**Acceptance:** Generate deterministic 13/50/205/500/2,000/5,000/10,000-row sources,
mixed types and controlled faults without real identifiers. Serve only requested
slices in the benchmark fake. Record actual HTTP counts, controller-body bytes,
rendered bytes, matched/returned rows and source time separately.

**Verify:** Small known fixtures match current projections; benchmark metadata
names Python/OS/commit/auth warm-up/pacing. Do not sum overlapping test totals or
embed private captures. Record the current 20-request/2,000-row behavior before
changing it.

### T02: Client result metadata and schema contracts

**Dependencies:** T01. **Size:** M.

**Files:** client-specific result/schema module, `_common.py` if needed,
`tool_specs_read.py`, schema tests.

**Acceptance:** Implement explicit client metadata and full/projected variants;
preserve generic tools and current default shape. Unknown totals can be omitted.
Document aggregate versus paged behavior in executable fixtures.

**Verify:** Existing schema tests plus complete/partial/empty/unknown-total cases
validate in slim/full modes. Prevent premature exposure of unsupported arguments.
Assert the legacy-to-qualified count mapping on capped, duplicate and complete
fixtures; preserving a numeric legacy field must not imply an exact total.

### T03: Incremental read-only source scanner

**Dependencies:** T01–T02. **Size:** M.

**Files:** new `domains/client_queries.py`, `clients_read.py`, targeted tests.

**Acceptance:** Fetch one native page at a time; retain source position and safe
unconsumed suffix; deduplicate/filter before result caps. Detect malformed,
short, empty, repeated and cycling pages. Preserve existing collector adapters
and exported helper names; no behavior change for shared write helpers.

**Verify:** Compare complete small-fixture output and ordering to the old path;
inject duplicates at page boundaries and at nonadjacent pages. Confirm no mutation
transport call occurs.

### T04: Actual request-budget enforcement

**Dependencies:** T03. **Size:** M.

**Files:** scoped budget helper, `client.py`, scanner, budget tests.

**Acceptance:** Count actual dispatch attempts within query scope, including
retries/auth refresh. Enforce 20 native page attempts/24 requests across sources.
Budget exhaustion preserves an honest partial continuation where safe.
Unrelated calls and all write semantics remain unchanged.

**Verify:** Fake time/retry/session faults cannot exceed the declared budget.
Initial server authentication is measured separately. No global Config mutation;
nested scopes and thread-local site overrides cannot leak budget state.

### T05: Legacy list fast path and streaming lookup

**Dependencies:** T03–T04. **Size:** M.

**Files:** `clients_read.py`, list/lookup regression tests.

**Acceptance:** Stable unfiltered Admin limit=50 returns the same first 50 unique
clients using one collection GET. Streaming lookup of an early match stops early.
Definitive not-found requires source exhaustion; incomplete lookup is explicit.
Legacy filtered exact-count paths retain exhaustive bounded behavior.

**Verify:** Admin/Viewer, duplicate rows, MAC formats, hostname/IP matching,
case handling, unknown totals and low limits. Preserve the old first-match
precedence rather than opportunistically redefining identity resolution.

### T06: Bounded opaque cursor store

**Dependencies:** T02–T04. **Size:** M.

**Files:** new `client_cursors.py`, `client.py` lifecycle hooks, cursor unit tests.

**Acceptance:** Scope-bound, unpredictable, expiring, replay-safe checkpoints;
32-checkpoint/8-MiB logical-state bounds; explicit capacity/expiry outcomes;
safe-field buffers only. Clear on close. No disk state or raw objects/secrets.

**Verify:** Changed site/tool/principal/filters/output options, malformed/unknown
handles, eviction, time expiry, restart, concurrent forks, replay after lost
response and memory-accounting boundaries. Use deterministic clock/token hooks
in tests; no production fixed tokens.

### T07: Public unfiltered paged listing

**Dependencies:** T04–T06. **Size:** M.

**Files:** `clients_read.py`, `tool_specs_read.py`, cursor integration tests.

**Acceptance:** Expose pageSize/cursor for list_clients with argument exclusivity
and complete/partial metadata. Traverse beyond native page 20 without one huge
request or full-inventory caching. Reuse the authenticated session/source.

**Verify:** Quiescent 10,000-client traversal yields every valid unique MAC once;
pageSize 1/50/100/500, retained suffixes, unknown totals and the final empty/full
boundary. First page uses one successful Admin collection GET.

### T08: Filtered Wi-Fi/wired pagination

**Dependencies:** T07. **Size:** M.

**Files:** `clients_read.py`, descriptors, filtered pagination tests.

**Acceptance:** Stop only after sufficient distinct matches or a bound; preserve
full internal filter fields. Total matched count is unknown until proved.
Sparse-match budget exhaustion returns a continuation, not false absence.

**Verify:** Place matches beyond the first native page and beyond native page 20;
mixed types, omitted fields, duplicates, zero matching rows and source changes.
Assert default complete small-fixture counts remain unchanged.

### T09: Search source and merge correctness

**Dependencies:** T03, T07–T08. **Size:** M.

**Files:** client query source adapters, `clients_read.py`, search tests.

**Acceptance:** Page explicit active/inactive searches and the combined Admin
active-first traversal; preserve active precedence and cursor phase state.
Viewer fallback retains its source semantics. Fix lost upstream truncation in
legacy search without silently changing legacy complete-result order.

**Verify:** Same MAC in both sources with conflicting values/filters; source
transition at an exact page boundary; missing Viewer fields; first-page denial;
mid-traversal source failure; partial active/inactive scans; SSID/VLAN/query
normalization. Failed source data must not be mixed with fallback data.
Include an active row that fails a filter and an inactive duplicate that would
pass it: the duplicate must stay suppressed across cursor boundaries.

### T10: Availability and failure reporting

**Dependencies:** T05, T07–T09. **Size:** M.

**Files:** client metadata/errors, scanner, failure regression tests.

**Acceptance:** Consistent completion/stop/source/warning metadata and safe
restart instructions. A role-limited missing field is not a negative match proof.
No synthetic totals, raw exception bodies, session tokens or cursor values in
diagnostics. Resolve how unsupported filter evidence is surfaced before release.

**Verify:** Malformed counts/rows, empty page with positive total, repeated/cyclic
pages, errors after prior emitted pages, session refresh, controller reorder and
explicit wrong-site attempts. Assert bounded I/O and no silent healthy result.

### T11: Optional public-field projection

**Dependencies:** T02, T05, T08–T10. **Size:** M.

**Files:** new client projection helper or `clients_read.py`, descriptors, tests.

**Acceptance:** Expose validated fields on the four list/search tools; retain mac,
canonical ordering/types and accurate selectedFields. Default full rows remain
unchanged. Projection does not alter query eligibility, dedup, safety helpers,
pagination state or missing-data interpretation.

**Verify:** Invalid/empty/duplicate/wildcard fields fail before I/O; selecting only
optional search extras is still valid because mac is retained. Inject unknown
secret fields and confirm neither full nor sparse outputs leak them.

### T12: Opt-in identical envelope representation

**Dependencies:** T02, T07–T11. **Size:** M.

**Files:** client result wrapper, `server.py`, descriptors, serialization tests.

**Acceptance:** Expose resultFormat; envelope text parses to exactly the same
object as structuredContent, including pagination/projection/warnings. Keep one
text block in envelope mode. Default arrays and notes remain unchanged.

**Verify:** Complete/partial/empty, projected/full, resumed pages, compact/pretty
and Unicode inputs. Compare full object equality, not substring/size heuristics.
Other list, object and write tools retain their existing behavior.

### T13: Host interoperability and token measurement

**Dependencies:** T11–T12. **Size:** M.

**Files:** optional developer token script, protocol fixtures, host validation notes.

**Acceptance:** Validate actual outputSchema with an official MCP SDK client in a
developer-only environment. Exercise at least two host paths: text-only consumers
and structured-output consumers. Record installed host versions. Reproduce the
specific upstream Hermes duplicate-rendering behavior without making that
version's behavior a universal assumption.

**Verify:** Capture sanitized model-facing schemas/results where permitted;
measure tokens before/after. Separate actual provider usage from tokenizer/
renderer proxies. Test upgrade/reload so cached schemas do not invalidate new
arguments or sparse outputs. No paid model calls are mandatory for unit CI.

### T14: Deterministic efficiency budgets

**Dependencies:** T01, T05, T07–T13. **Size:** M.

**Files:** benchmark script/tests, optional token script, CI benchmark job.

**Acceptance:** Gate request counts, bounded state, canonical byte sizes and
token targets on deterministic fixtures. Pin the developer tokenizer version
and encodings; never add it to runtime dependencies. Retain raw JSON artifacts.

**Verify:** Meet the table in section 7. Wall-clock/CPU timings are published
with sample counts and host metadata, not flaky universal pass/fail thresholds.
Snapshot checks must not freeze incorrect semantics or force raw-field leakage.

### T15: Public documentation and generated reference

**Dependencies:** T07–T14. **Size:** M; split mechanical regeneration if needed.

**Files:** README, generated tools reference, this plan's follow-up evidence,
dedicated client-query guide, changelog (split across small commits).

**Acceptance:** Document legacy/paged semantics, exact versus unknown totals,
fields/envelope examples, process-local cursor lifetime, role/consistency limits,
and migration for cached schemas. Keep catalog counts unchanged at 54 read /
78 write unless an unrelated separately reviewed change requires otherwise.

**Verify:** Run docs generator and zero-drift check; examples validate against
descriptors; links resolve; no private identifiers. Controller support statements
identify exact builds/roles and distinguish mocks, lab evidence and real hardware.

### T16: Disposable-controller qualification and release

**Dependencies:** T13–T15. **Size:** M per qualification/release slice.

**Files:** read-only smoke harness, qualification record, version metadata.

**Acceptance:** Use explicit isolated lab env files; GET-only request guard
except authentication. Verify Viewer/Admin fallback, paging, fields/envelope
and cleanup/session behavior on available 5.x/6.x lab builds. Qualify actual
paging/filter support; publish unavailable targets as unverified.

**Verify:** No production controller access or write operations. All suite,
lint/type, packaging, protocol, benchmark and generated-doc gates pass. Review
the actual minor-release change, then use the repository's PR/CI/release workflow.
Do not publish a release merely because the plan exists.

## 7. Quantitative release gates

These are proposed deterministic acceptance budgets, not claimed results.

| Area | Gate |
|---|---|
| Stable Admin first page, 2,000 clients/pageSize=50 | One successful collection GET after warm authentication |
| Viewer first page | At most one denied rich probe plus one successful insight GET in the standard denial fixture |
| Continuation source | No repeated rich permission probe after pinning insight |
| Early lookup | First-page match uses one successful collection GET; not all 20 |
| Full navigation | Every unique MAC in a stable 10,000-client fixture reachable across calls; no duplicates/omissions |
| Per-call limits | At most 20 native page attempts and 24 actual in-query HTTP attempts, including retries |
| Cursor retained state | At most 32 checkpoints and 8 MiB serialized safe state; publish Python heap overhead from tracemalloc |
| Query memory growth | Bounded by returned page/buffer/dedup/checkpoint limits, not an uncapped inventory list; compare measured peaks against baseline |
| 13-client five-field item text | At most 600 o200k tokens versus baseline 2,072; at least 70% reduction |
| 50-client five-field item text | At most 2,200 o200k tokens versus baseline 7,970; at least 70% reduction |
| Modeled deduplicated envelope, 13 / 50 clients | At most 800 / 2,500 o200k tokens on the fixed baseline fixture; include continuation/projection metadata |
| Read-only function-schema proxy | At most 5,200 o200k tokens versus baseline 4,108; document added functionality and amortized result savings |
| Schema correctness | Actual SDK/client validation passes for every full/projected/paged format |
| Legacy behavior | Existing complete-fixture rows, ordering, types and default content shape unchanged |
| Safety | Zero mutation transport calls; no raw fields/credentials; existing write safety/recovery tests unchanged and passing |

Do not reduce mandatory metadata or input validation to hit a token budget.
If a safety-correct contract exceeds a target, publish the measured tradeoff and
review the target explicitly. Do not silently move the baseline or claim success.

## 8. Test matrix

| Dimension | Required cases |
|---|---|
| Size | 0, 1, 13, 50, 99, 100, 101, 205, 500, 2,000, 2,001, 5,000, 10,000 |
| Role/source | Admin rich active/inactive; Viewer first-page denial; insight with missing IP/SSID/radio data; role changes |
| Identity | MAC separators/case, boundary/nonadjacent duplicates, malformed/missing MAC, conflicting active/inactive records |
| Filter | Query, active, wireless/wired, guest, VLAN, SSID; combinations; matches only on later pages |
| Pagination | Known/unknown/changing totals, exact/short/empty/repeated/cyclic pages, unexpected envelope shapes, controller ignoring page parameters |
| Cursor | Same query replay, lost-response retry, forks, expiry, eviction, restart, wrong site/tool/user, changed presentation/filter params, retained suffix |
| Fault | GET -1600 retry, HTML/redirect/-30109 session expiry, permission refusal, error after emitted pages, request budget during recovery |
| Presentation | Default rows, selected fields, missing optional fields, legacy/envelope, compact/pretty, Unicode, null/zero/false values |
| Consumers | MCP schema validator, array-text parser, structuredContent parser, installed Hermes and another supported host where available |
| Shared callers | Doctor, audit, LAN inspection, snapshots, diagnostics, client writes and wireless reference checks retain their old complete-collector contracts |

Prefer tests proving business/query behavior and bounded I/O over tests mirroring
helper implementation. Use synthetic fixtures; keep network-dependent lab
qualification separate from the fast offline suite.

## 9. Verification commands and evidence

Repository gates, using the project's normal developer environment:

```powershell
python -m unittest discover -s tests -v
python -m ruff check src tests scripts
python -m mypy src
python -m mypy scripts
python scripts/generate_docs.py --check
python -m build
```

New benchmark commands should be stdlib-first and explicit about their source:

```powershell
python scripts/benchmark_client_reads.py --json --output <private-or-ci-report-path>
```

Finalize the optional tokenizer command in T13 with a pinned developer environment;
do not assume its presence in a production installation. Any live read-only
qualification must pass an explicit isolated lab env path and retain the transport
mutation guard. No benchmark should silently discover the maintainer's normal env.

For each checkpoint, retain: package/commit/controller/host versions, account role,
sample count, fixture dimensions, request/page counts, bytes, both token encodings,
completion metadata, pass/fail/skip and known limits. Prefer sanitized JSON artifacts
plus a short Markdown interpretation. Do not publish full controller payloads.

## 10. PR sequence, checkpoints and delegation

Suggested small PR sequence:

1. T01–T02: fixtures and result-contract foundation; no prematurely advertised flags.
2. T03–T05: scanner, budget and compatible list/lookup improvements.
3. T06–T07: cursor lifecycle and unfiltered paged API.
4. T08–T10: filtered/source-merge behavior and incomplete-result reporting.
5. T11–T12: selected fields and opt-in identical envelope.
6. T13–T16: host qualification, budgets, public docs and release preparation
   (split tests, generated docs and release metadata as needed).

After each PR: existing relevant tests and all newly exposed contracts pass;
rerun the full suite and required static/docs gates before merging. A task must
not expose a partial mode that silently violates its declared contract.

Keep architecture, merge semantics, cursor scope and security review with the
primary agent. Use **GPT Luna at xhigh** for small tasks: fixture generation,
checking field/schema consistency, focused documentation updates, link checking,
and independently verifying bounded-request test cases. Parallelize only tasks
with independent files after the shared contract is fixed. Do not let agents
concurrently edit the shared client handler/schema files.

The plan is complete for review; implementation remains unchecked in todo.md.
Implementation authorization and final contract review are separate from this
documentation task. No further permission is needed merely to save this plan.

## 11. Risks and mitigations

| Risk | Impact | Mitigation / decision gate |
|---|---|---|
| Early stopping alters exact counts or active precedence | Incorrect answers | Legacy collectors retain exact-count/merge paths; paged semantics are explicit; source-specific tests |
| Shared helper optimization truncates write safety reads | Connectivity/security risk | Isolate read scanner; preserve helpers/internal collectors; run write regression suite |
| Numbered pages change during traversal | Missing/unstable inventory | bestEffort contract, identity dedup, anomaly metadata; no snapshot claim |
| Cursor state grows or leaks private data | Memory/privacy risk | Safe projected rows only, bounded checkpoints/bytes/lifetime, close cleanup and measured heap use |
| Cursor retry consumes mutable state | Skipped pages | Immutable replay-safe checkpoints; concurrent and lost-response tests |
| Permission fallback mixes inventories | Wrong data or duplicates | Pin source; clean restart before emission; explicit invalidation afterward |
| Sparse rows violate advertised output schemas | Host rejects results | Typed projected schema variants and real SDK validation before exposure |
| Envelope default breaks array parsers | Backward incompatibility | Opt-in resultFormat; keep legacy default and contract tests |
| Actual host does not deduplicate matching representations | Token saving not realized | Measure installed versions; report schema/text/wire/host/provider layers separately |
| Field options enlarge every tool schema | Upfront context cost | Catalog budget plus task-level before/after accounting; no new overlapping tools |
| Mock response work dominates timings | Misleading performance claims | Efficient page fake, transport/app timing separation; no synthetic-as-live claims |
| Budgets interact with retries/auth refresh | Overrun or false empty result | Count actual dispatch in a scoped read budget; preserve partial state and explicit stop |
| Controller page-size/filter assumptions are wrong | Compatibility regression | Native size 100 initially; qualification records per build/role; don't invent endpoint parameters |

## 12. Decisions to validate before implementation progresses

These are bounded engineering gates, not reasons to invent new behavior silently:

- **Contract gate (T02):** validate output-schema variants with real MCP clients;
  revise metadata/schema design if a host cannot accept it while preserving
  legacy defaults.
- **Cursor gate (T06):** prove replay safety and 10,000-row bounded-state traversal.
  If the proposed memory limits are insufficient, measure and review the tradeoff;
  do not switch to unbounded caching or unauthenticated stateless offsets.
- **Source gate (T09–T10):** capture/qualify active/inactive/insight behavior on
  available controllers. Missing Viewer filter evidence must remain explicit.
- **Host gate (T13):** identify the tested Hermes version/model and another host.
  The earlier renderer proxy cannot be promoted to actual billing evidence.
- **Release gate (T16):** choose the actual minor version/date only after the
  public contracts, regression and compatibility evidence are reviewable.

Future follow-ups, outside this milestone: native controller-side search where
verified; sorted/snapshot-consistent exports; persistent resumable inventory jobs;
additional list-tool projection; composite diagnostic request reduction; and
long-running production resource/usage measurement.
