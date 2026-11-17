# Client queries and output size

Added in `v2.4.0`. These options extend
`list_clients`, `list_wifi_clients`, `list_wired_clients`, and `search_clients`;
the tool inventory stays at 54 read tools and 78 optional write tools.

Existing calls retain full client fields, the default `limit=500`, and a JSON
array in the first text block. Internal audit, snapshot, and write helpers keep
their bounded full-collection behavior. The list tools describe connected
clients; use `search_clients` to include inactive history.

## Read one page

Pass these arguments to `list_clients`:

```json
{"pageSize":50,"fields":["mac","ip","wireless","active","vlan"],"resultFormat":"envelope"}
```

`pageSize` opts into resumable traversal and accepts 1–500 matches. Each native
controller page contains at most 100 rows. Filtering and MAC deduplication
happen before the requested result count and field selection. A Wi-Fi or search
query may scan several controller pages to find enough matches.

Resume the same tool with the returned handle:

```json
{"cursor":"<nextCursor from the previous result>"}
```

Omitted filters, page size, fields, and format inherit from the checkpoint.
Explicit conflicting options fail before another collection request. Do not
combine `limit` with `pageSize` or `cursor`. A cursor alone resumes a paged query;
the default size for a new paged query is 100. Repeat a non-default `site`
argument when continuing; normal site visibility and cross-site restrictions
still apply. Cursors cannot move between tools, controllers, accounts, or sites.

Checkpoints are process-local and can be replayed or forked without advancing
shared state. A restart, eviction, expiry, or scope mismatch produces an explicit
error; restart the query without the old cursor. Retrying a checkpoint against a
changing controller still provides best-effort data, not a frozen snapshot.

## Choose fields and format

`fields` is a nonempty, unique, case-sensitive list of the tool's advertised
client properties. Unknown names fail validation. `mac` is always retained;
results and `selectedFields` use schema order. Omitting `fields` keeps the full
25-field projection (search can also return `blocked`, `fixedIp`, `fixedNetId`).
Selection happens after matching, so it cannot change filter decisions or source
precedence. Controller credentials and unknown fields are never projected or
stored in checkpoints.

`fields` and `resultFormat` can also be used without paging. They then change
presentation while preserving the bounded aggregate scan and legacy `limit`:

```json
{"limit":50,"fields":["mac","ip","wireless","active","vlan"],"resultFormat":"envelope"}
```

These presentation options alone do not create a cursor or reduce the scan needed
for exact filtered totals. Use `pageSize` when you want resumable bounded pages.

`resultFormat="envelope"` returns one text block whose parsed JSON is exactly
`structuredContent`: an object with `items`, `count`, and metadata. Hosts that
recognize this equality (or read `structuredContent` alone) can avoid forwarding
duplicate content to a model. However, the wire protocol still includes both
forms: on hosts that forward **both** `content[0].text` and `structuredContent`
(verified live on Hermes), `resultFormat="envelope"` repeats the envelope metadata
and uses slightly more tokens than `fields` + default `legacy` format (`1,042` vs
`958` `o200k_base` tokens on 13 clients). When in doubt on such hosts, pass
`fields` without `resultFormat="envelope"`.

Note on error surfaces: invalid schema arguments (`limit` combined with
`pageSize`/`cursor`, unknown/empty/duplicate `fields`) fail before execution as
JSON-RPC `-32602`, while runtime cursor errors (expired, unknown, or wrong
tool/site scope) return an MCP tool result with `isError=true`. No existing tool
arguments were renamed in `v2.4.0` (`delete_ip_group` uses `group`, and
`diff_config_snapshots` uses `baseline`/`current` as in `v2.0.0`+).

## Interpret completeness

| Field | Meaning |
| --- | --- |
| `count` | Matches returned in this response. |
| `hasMore`, `nextCursor` | Unscanned source data may remain. Continue even if this page is empty. |
| `complete` | Source traversal completed without a known source or filter-data problem. |
| `totalRows`, `totalRowsExact` | A paged total is supplied only when the total unique matches across the traversal is known. It can exceed this page's `count`. |
| `totalRowsSource`, `sourceTotalRows` | Distinguish matched/observed counts from the controller's raw count. Active/inactive source counts are never added as a unique total. |
| `truncated`, `truncationReason`, `stopReason` | Distinguish a result cap or resumable scan budget from a terminal anomaly. |
| `rowsScanned`, `pagesFetched`, `controllerRequests` | Raw rows, native page attempts, and actual HTTP attempts for this invocation. Initial authentication is excluded; retries and session recovery within the query are included. |
| `source`, `warnings`, `consistency` | Selected endpoint, availability/anomaly warnings, and `bestEffort` consistency. |

`hasMore=false` with `complete=false` does **not** prove that no other client
matches. Repeated pages, changed totals, malformed/short responses, absent filter
fields, source failures, and capacity limits remain visible. Narrow or restart
the query to investigate. Older legacy unfiltered callers still receive their
numeric `totalRows`; `totalRowsExact=false` identifies an unverified count.
Legacy filtered calls scan their bounded collection for exact match totals when
possible, even if the returned array is capped.

Combined paged search scans active clients first. An active MAC takes precedence
before filtering, so an older inactive duplicate cannot reappear because the
current record failed a filter. Legacy combined search retains inactive insertion
order with active values replacing duplicates. Viewer fallback uses the first
observed insight record and is pinned once a paged response has been emitted.

## Resource and consistency limits

Each call permits at most 20 native page attempts and 24 actual HTTP attempts,
including query retries and session recovery. A continuation can move beyond
native page 20. A traversal stops after 100,000 raw rows. `get_client` streams
until the first match and reports an incomplete lookup instead of a definitive
not-found result when the bounded scan cannot establish absence.

The store keeps at most 32 checkpoints and 8 MiB of serialized safe state, with
LRU eviction, 10-minute idle expiry, and a 1-hour absolute lifetime per stored
checkpoint. Python object/allocator overhead is additional memory. Pending rows
are bounded by one native page. Deduplication uses normalized MACs; rows without
MACs are retained by position with a warning and cannot receive identity guarantees.

Omada's numbered pages can shift as clients join or leave. Count and page-cycle
checks detect some anomalies; unchanged counts cannot prove the absence of all
movement, omissions, or stale observations. These reads are not authoritative
inputs for network-changing operations.

## Reproduce qualification

```bash
python -m unittest discover -s tests -q
python scripts/benchmark_clients.py --check --output reports/client-efficiency.json
```

For token gates, install `tiktoken==0.14.0` in a developer environment and add
`--require-tokens`. It is not a runtime dependency. The benchmark distinguishes
item JSON, envelopes, protocol bytes, a modeled host representation, and schema
input; timings use an in-memory source without controller pacing.

The optional MCP SDK check uses an isolated loopback mock. The live qualification
script requires an explicit disposable loopback lab dotenv file and blocks every
method except GET and login:

```bash
python scripts/check_client_interop.py
python scripts/qualify_client_queries.py --env-file /path/to/isolated/viewer.env
```

The SDK check was qualified with developer-only `mcp==2.3.0` and
`jsonschema==4.26.0`. Use these versions to reproduce the recorded SDK behavior.

See [the local test record](testing/client-queries-2026-11-17.md) for measured
results and untested hardware/host combinations. After updating the server,
restart it and refresh the MCP host's cached tool schemas to expose the new
arguments. Existing integrations can keep their old arguments and output format.
