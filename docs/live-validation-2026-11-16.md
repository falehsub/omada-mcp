# Live home-network validation — omada-mcp 2.3.0

**Date:** 2026-11-16

**Final status:** Upgrade and the restricted validation completed; the MCP integration
was restored to read-only operation; no temporary controller objects remained.

## Evidence and scope

This record consolidates two Hermes reports supplied by the operator in the project
chat: the initial upgrade/read/write report and the follow-up after reloading the
MCP configuration. Results below are **Hermes-reported observations**, unless
explicitly identified as local checks performed separately by Codex. The remote
tests were not independently rerun by Codex, and the underlying private JSON
artifacts were not copied into this repository.

The operator explicitly authorized one live create/delete cycle for a new,
unreferenced IPv4 IP group. This was a narrowly scoped exception for this session,
not authorization for future live writes or a general write-tool sweep. Existing
network configuration, device/client actions and controller/container maintenance
were outside the authorized test scope.

Credentials, controller/site IDs, real IP/MAC addresses and private host paths are
omitted. `192.0.2.123/32` below is the documentation-range address used in the test.

## Environment and upgrade

| Item | Reported result |
|---|---|
| Previous MCP version | 2.0.0 |
| Requested and installed MCP version | 2.3.0 |
| Installation method | Existing `uv tool` installation; binary path preserved |
| Upgrade command | `uv tool install --reinstall omada-mcp==2.3.0` |
| Package availability | Wheel and sdist confirmed on PyPI before modification |
| Package identity | PyPI version, installed distribution metadata and `--version` all 2.3.0 |
| Controller | Software controller 6.3.0.45; Docker deployment reported by operator |
| Site | One visible site; pinned by exact ID, omitted here |
| Adopted devices | Four: one gateway, one switch, two APs |
| Clients at baseline/final check | 13; final split five wireless/eight wired |
| Final interpreter | uv-managed CPython 3.13.15 |
| Final MCP identity | `serverInfo.version=2.3.0`, protocol `2025-06-18` |
| Backup | Existing Hermes MCP configuration backed up before editing |
| TLS | Existing private CA and verification settings preserved |

Docker CLI access was unavailable to Hermes. Controller container image, uptime,
volumes and database were not independently inspected. Hermes reported no Docker
commands or controller/container maintenance during either round.

## Round 1: read-only baseline

Every baseline read used an explicit configuration and the following settings:

```dotenv
OMADA_READ_ONLY=true
OMADA_WRITE_TOOLS=
OMADA_ALLOW_CROSS_SITE=false
OMADA_MIN_INTERVAL_SECONDS=0.8
```

The selected site was pinned, TLS settings were retained, and requests were
performed sequentially. The doctor authenticated with an Admin account; this does
not establish Viewer-role behavior for this run.

| Check | Result | Observation |
|---|---|---|
| `--doctor --json` | PASS | Status `pass`, exit code 0, all six phases passed |
| `list_sites` | PASS | One visible site |
| `get_site_info` | PASS | Selected site resolved |
| `list_devices` | PASS | Four devices |
| `list_clients(limit=50)` | PASS | 13 clients |
| `list_wlans` | PASS | Two WLANs |
| `list_lan_networks` | PASS | Six networks |
| `list_ip_groups` | PASS | Five groups |
| `list_acls(aclType="all")` | PASS | Three rules across ACL scopes |
| `network_audit` | PASS (tool execution) | `healthy=false`, six findings; not a clean-health result |
| `get_ap_radios` | PASS | One AP inspected, two radios: 2.4 and 5 GHz |
| `get_switch_ports` | PASS | One switch, 20 ports; cable test explicitly disabled |
| `get_config_snapshot` | PASS | `networks`, `acls`, `groups`, `wlans` captured |

**Reported baseline total: 13 passed, zero failed, zero skipped.** The table counts
the doctor as one check; its six internal phases are not six additional tool tests.

The server advertised 54 read-only tools and no writes. The complete release
catalog contained 132 definitions: 54 read and 78 opt-in write tools. Catalog
enumeration does not mean that all 54 read handlers were exercised live.

No RF scans, cable tests, speed tests, optimization, provisioning, device actions
or client actions were triggered. The private baseline was stored with mode `0600`.

## Round 1: restricted write cycle

The writer ran separately from the read-only integration, with the same
controller, pinned site and TLS configuration:

```dotenv
OMADA_READ_ONLY=false
OMADA_WRITE_TOOLS=create_ip_group,delete_ip_group
OMADA_ALLOW_CROSS_SITE=false
OMADA_WRITE_INTERVAL_SECONDS=1.0
```

The allowed write surface was restricted to these two operations; read tools
remained available. The temporary object had the unique name `hmtest-7cd5e5` and
the sole member `192.0.2.123/32`. It was never attached to any ACL or other object.
The controller-assigned group ID was journaled privately and is omitted here.

| Step | Result | Evidence reported |
|---|---|---|
| Write-tool allowlist | PASS | Only create/delete IP group writes advertised |
| Site pin | PASS | Same exact site as baseline |
| Name uniqueness | PASS | Test name absent before creation |
| Pre-write journal | PASS | Written before mutation; mode `0600` |
| Create preview | PASS | Exactly one new group; confirmation token captured |
| Create commit | PASS | `applied=true`, `verified=true` |
| Create readback | PASS | Exact name and sole CIDR matched; ID recorded |
| Reference check | PASS | Three rules across gateway/switch/EAP scopes; no references |
| Delete preview | PASS | Targeted the exact group created by this run |
| Delete commit | PASS | `applied=true`, `verified=true` |
| Cleanup readback | PASS | Created ID and name both absent |

**Reported write total: 11 passed, zero failed. Actual mutations: one create and
one delete.** Existing objects were not modified, according to the report.

An earlier harness attempt incorrectly supplied a `site` argument to `list_sites`.
Argument validation rejected it and the site-pin guard aborted before the journal
or any mutation. The harness was corrected before the single successful cycle.
This aborted attempt is not an additional committed write test.

## Round 1: configuration comparison and device observations

The same four snapshot sections were captured after cleanup and compared with
the baseline using `diff_config_snapshots`:

```json
{
  "hasChanges": false,
  "sectionsChanged": 0,
  "added": 0,
  "removed": 0,
  "changed": 0
}
```

| Observation | Before | After |
|---|---|---|
| Adopted devices | 4 | 4 |
| Online devices | 4 | 4 |
| Devices reporting pending firmware | 0 | 0 |
| IP groups | 5 | 5 |
| Temporary test group | Absent | Absent after cleanup |
| Audit `healthy` | `false` | `false` |
| Audit finding count | 6 | 6 |
| Audit finding codes reported | `VLAN_UNISOLATED`, `AP_HIGH_RETRY_RATE`, `WAN_LINK_DEGRADED` | Same codes |

Hermes reported a post-write read sweep of **14 passed, zero failed, zero skipped**.
Its additional verifier reported **5/5 checks, exit code 0**, covering harness
compilation, a 14/14 read-harness result, wrong-site abort behavior, absence of
leftover groups, and journal permissions/status/credential-string checks. These
are overlapping verification results, not independent totals to add together.

Zero drift applies only to the compared snapshot sections and captured fields.
It is not a byte-for-byte controller backup comparison or a full network
performance measurement. Device online status and unchanged audit findings do
not prove an absence of every transient service interruption.

The audit warnings predated this test. Unisolated VLANs can be intentional; AP
retry and WAN-link findings require supporting measurements before diagnosing
their cause or severity. A successful audit call is not proof of network health.

## Reload issue: detected and subsequently resolved

After the upgrade, the Hermes supervisor initially respawned an MCP child using
its cached pre-change environment: read-only disabled with the previous eight-tool
write allowlist. Updating the on-disk registration and restarting only the child
did not refresh that environment; two respawns reproduced the mismatch.

Hermes stopped the stale-environment child. At the end of the first report, the
on-disk configuration was read-only but the normal MCP integration was offline.
This was an incomplete end state, not a verified running read-only integration.

The follow-up report, after an MCP configuration reload, established a stable
single replacement child using the intended environment. **F1 is resolved in the
reported follow-up.** The behavior was attributed by Hermes to supervisor caching;
no underlying Hermes implementation or supervisor logs were independently audited
in this documentation task, and no omada-mcp source fix was made.

## Round 2: final running configuration and fail-closed checks

This round performed no controller mutations and did not repeat the write cycle.

| Check | Result | Observation |
|---|---|---|
| Running version | PASS | Installed metadata and MCP `serverInfo` both 2.3.0 |
| Effective environment | PASS | Read from running child's `/proc` environment; credentials not printed |
| Read-only | PASS | `OMADA_READ_ONLY=true` |
| Write allowlist | PASS | `OMADA_WRITE_TOOLS` empty |
| Cross-site access | PASS | `OMADA_ALLOW_CROSS_SITE=false` |
| Disk/process agreement | PASS | Saved registration matched effective safety flags |
| Advertised catalog | PASS | 54 read-only tools, zero writes, no category filter |
| Hermes session catalog | PASS | Write tool no longer registered in the session |
| Non-read-only call refusal | PASS | `create_ip_group` dry-run probe returned JSON-RPC `-32003` |
| Unknown-tool refusal | PASS | Also `-32003`, because read-only gate precedes tool lookup |
| `get_site_info` | PASS | Controller 6.3.0.45; WAN/LAN/WLAN connected; four devices, 13 clients |
| `list_devices` | PASS | Four online devices; reported `status=1`, all `needUpgrade=false` |
| `list_ip_groups` | PASS | Five groups; temporary test object absent |

The non-mutating refusal probe used:

```json
{
  "name": "readonly-gate-probe",
  "cidrs": ["192.0.2.123/32"],
  "dryRun": true
}
```

Reported response: `-32003`, stating that `OMADA_READ_ONLY=true` refuses the
non-read-only tool `create_ip_group`; no transport call and no object creation.
`dryRun` was never set to `false` during this round. The probe name differs from
the temporary group used for the completed write cycle.

**Method qualification:** the supervisor owned the running child's stdio, so
Hermes did not query that child's raw `tools/list` directly. It enumerated a
short-lived process using the exact running binary and `/proc` environment and
cross-checked the result against the reloaded Hermes session catalog. The actual
running process's version and safety environment were checked separately. The
reports do not provide a direct raw supervised-child transcript of every probe;
preserve this distinction when citing the verification.

No second configuration diff was generated in this round. The established claim
is that Hermes performed no controller mutations in the round, not that another
actor could not have changed configuration in the meantime. The earlier four-
section zero-drift result remains the measured configuration comparison.

## Other observations and remaining limits

- Hermes noted firmware versions and uptime differing from earlier sessions,
  while reporting no upgrades, reboots or provisioning itself. Exact device
  builds were not supplied in the retained reports. The cause, actor and timing
  of these differences were not independently established.
- Docker hosting is operator-reported; no independent image/uptime inspection
  was possible from the Hermes context.
- The live baseline used an Admin account. Viewer behavior and other controller
  families are outside this record's demonstrated scope.
- One AP and one switch were inspected. This is not exhaustive adopted-hardware
  coverage, and device counts do not establish hardware model compatibility.
- Two of the release's 78 write tools were exercised live. The remaining 76,
  cross-site access, recovery after an uncertain mutation, and rollback behavior
  were not live-validated by this session.
- Read-only gate checks validate caller restrictions; a confirmation argument
  or preview token alone is not evidence of human approval enforcement.

## Retained private artifacts

The first report identified the following artifacts on the Hermes host. Their
continued existence has not been checked from this workspace:

| Artifact | Reported state |
|---|---|
| Pre-upgrade Hermes configuration backup | Saved before the integration update |
| `omada230-baseline.json` | Private snapshot, mode `0600`; identifiers not copied here |
| `omada230-write-journal.json` | Mode `0600`, final status `deleted`; no credential strings reported |
| `hermes-verify-omada230.py` and companion write harness | Retained as operator-side evidence |
| Host-side integration verifier | Tool-count floor updated from 43 to 54 in a separate host repository |

These private artifacts must not be committed without anonymization. This
Markdown record preserves the reported results even if chat context is lost.

## Separate local offline checks

During the earlier project evaluation in this chat, Codex ran the local suite at
the 2.3.0 checkout:

- `python -m unittest discover -s tests -q`: **250 passed in 9.330 seconds** after
  allowing loopback networking for the offline mock-controller tests.
- An initial sandboxed run had one failure and seven errors associated with
  socket access restrictions; the successful rerun resolved that execution limit.
- `python scripts/generate_docs.py --check`: **PASS**, 132 tools, reference docs,
  `.env.example` and `server.json` in sync.

These checks are separate from the Hermes live results above. They were not
rerun while writing this record, and no live controller calls were made by Codex.

## Final disposition

The reports establish a completed 2.0.0-to-2.3.0 MCP upgrade, successful selected
live reads on software controller 6.3.0.45, one verified create/delete cycle with
cleanup and zero measured drift in four configuration sections, and restored
read-only operation after resolving the supervisor environment mismatch.

No temporary group remained. No further live writes are needed to complete this
upgrade validation. Future validation should append dated evidence and preserve
the scope and method qualifications above.
