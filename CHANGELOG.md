# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-11-14

Minor architecture, compatibility, and reliability release (**210 passing tests**).

### Added

- **Modular domain architecture**: Split monolithic tool and HTTP transport modules into
  `transport.py`, `errors.py`, and cohesive `omada_mcp.domains.*` modules with backward-compatible
  re-exports in `tools.py`, `write_tools.py`, and `_helpers.py`, plus `ruff` and strict `mypy`
  enforcement in CI.
- **Omada 5.x / 6.x Docker compatibility matrix & fixture tooling**: Added
  `.github/workflows/compat.yml`, `scripts/docker_lab_init.py`, `scripts/capture_fixtures.py`,
  `scripts/anonymize_capture.py`, `docs/compatibility.md`, and `tests/test_phase2_compat_and_fixtures.py`
  covering Viewer/Admin projections across Omada 5.15 and 6.2 shapes.
- **Recursive JSON Schema validation** (`omada_mcp.schema_validation`): Validate nested
  `properties`, `required`, `additionalProperties` (with typo/`camelCase` hints), `items`, `type`,
  `enum`, numeric/string/array bounds, `anyOf`, and `oneOf` before issuing controller requests.
- **Explicit paginated truncation metadata** (`PaginatedList`): Preserve JSON array outputs in
  `content[0]` while surfacing `truncated`, `totalRows`, `pagesFetched`, `maxPages`, `limit`,
  and `truncationReason` in `structuredContent` (plus a note block when truncated) across
  `list_clients`, `list_wifi_clients`, `list_wired_clients`, `search_clients`, `list_logs`,
  and `OmadaClient.paginate`.
- **Superseded-snapshot rollback guard & 47-tool hardening suite** (`tests/test_phase3_hardening.py`):
  `rollback_from_snapshot` refuses stale snapshots superseded by newer writes on the same target
  unless `force=true`, checks target existence before PATCH rollback, and verifies dry-run/confirm
  gating, deep secret redaction (`deep_redact`) across all 47 write tools, and MCP protocol
  conformance across all supported `PROTOCOL_VERSIONS`.

### Fixed

- **Monitor & stdio lifecycle resilience**: Guarantee client/HTTP socket cleanup on exit in
  `Server.serve()`, `run_watch()`, `export_metrics_once()`, `serve_metrics_http()`, and CLI
  `SIGTERM`; surface outage errors when both `devices` and `LAN networks` endpoints fail so
  `run_watch` enters bounded exponential backoff (`degraded`) and `/healthz` reports HTTP `503`
  (`degraded` / `stale`) until a scrape recovers.

## [1.3.1] - 2026-11-14

Patch release addressing findings verified against a live Omada 6.2 hardware deployment
(**190 passing tests**).

### Fixed

- **`list_logs(hours=0)` full-history window**: Send `filters.timeStart=1&filters.timeEnd=<now_ms>`
  when `hours=0` instead of `0&0`, which Omada 6.2 treated as an empty range (`0` rows)
  while rejecting missing time parameters.
- **Session-level `-1600` negative cache**: After an uncached `GET` fails with `-1600`
  twice across the burst-backoff retry (e.g. firmware-unsupported endpoints such as
  `cmd/getSpeedTestResult` or `dashboard/wireguardtunnels`), cache the negative result
  for `300s` (bypassed during write verification read-backs and invalidated on mutations),
  eliminating repeated `0.8s` + double-request stalls on `diagnose_wan`, `diagnose_client`,
  and `list_vpn_tunnels`.

### Added

- **`get_ap_radios` per-band client counts**: Derive `clientCount` per radio (`2g`, `5g`,
  `5g2`, `6g`) by grouping active wireless clients via `radioId` when AP/radio telemetry is
  available (returning `None` honestly when `insight/clients` strips those fields under
  Viewer accounts).
- **Extended client telemetry fields**: Preserve `rssi`, `signalLevel`, `snr`, `txRate`,
  `rxRate`, `uptime`, `connectType`, `radioId`, and `channel` as optional/nullable fields
  in `project_client` (`list_clients`, `list_wifi_clients`, `list_wired_clients`,
  `get_client`, `search_clients`).
- Clarified `includeCableTest` and `get_rf_scan` descriptions to explicitly note cached /
  previously-triggered scan/test semantics.

## [1.3.0] - 2026-11-14

80-tool minor release (33 read-only diagnostics/discovery + 47 opt-in write
controls) combining live Omada 6.2 Docker audit improvements with security,
protocol recovery, allowlist export, and packaging hardening (**186 passing tests**).

### Security

- Remove query strings from ambiguous write-disconnect errors so session tokens cannot
  appear in tool responses or audit logs. Writes are still never replayed blindly.
- Use explicit nested field allowlists (`project_controller_row`) for configuration snapshots,
  services, IP-group entries, policy routes, and LAN DNS rules (including forward
  `dnsServers`). Unknown controller fields are omitted.
- Prevent the system-proxy transport from following redirects with authentication headers.
- Create rollback snapshots exclusively with private POSIX permissions and unique names
  across processes, preventing another session from overwriting recovery state.

### Added

- `delete_port_profile` write tool (`OMADA_WRITE_TOOLS` allowlisted), bringing total tool
  surface to **80 tools** (`33` read-only + `47` write).
- Adaptive `-1600` pacing and a gateway-absent fast-path (`hasGateway=false`) across
  gateway/routing diagnostics.
- `scripts/read_selftest.py`: an explicit-config, read-only live tool sweep with mutation
  blocking, timings, request counts, and payload-free pass/fail/skip JSON reports.
- A static correctness CI gate (`ruff check src --select E9,F`) and `.dockerignore`.
- A local review report and prioritized adoption/feature roadmap in
  `docs/review-2026-11-14.md`.

### Fixed

- Recover once from HTTP redirect session expiry, verified against Docker Omada 6.2.14.11.
- Preserve valid string/integer JSON-RPC request IDs on `jsonrpc != "2.0"` `-32600` errors,
  reject invalid IDs and parameter shapes before dispatch, ignore notifications without
  a request ID, and bound stdio frames while streaming.
- Harden v6.2 ACL read-back, UTF-8 BOM `.env` parsing, schema parameter bounds, and
  `scripts/write_selftest.py` preflight checks.
- Apply Wi-Fi/wired client limits after filtering; stop repeated client pagination pages.
- Report malformed URL/port configuration cleanly and reject non-finite or invalid timing
  values, including CLI polling intervals.
- Include mock-controller fixtures, schemas, scripts, and Docker packaging files in sdists
  so the source archive can run the complete test suite.

### Compatibility

- The diagnostic exports above intentionally omit undocumented/raw fields. Supported
  fields remain available; these exports are not full controller backups.

## [1.2.2] - 2026-11-13

Patch release from a live write-mode session: two reporting/schema defects found by using the
server, plus a self-test for the DHCP pool contract.

### Fixed

- **`release_client_fixed_ip` claimed a removal it had not performed.** When no static
  reservation row existed, the cleanup step returned success and the tool appended
  "static DHCP reservation row removed" to `warnings` anyway. The cleanup is now tri-state
  (`removed` / `absent` / `failed`): the warning is emitted only for a real removal, a failure
  names the DELETE result, and an absent row says nothing.
- **`create_lan_network` pool schema rejected the reader's shape.** It advertised only
  `{ipaddrStart, ipaddrEnd}` while `list_lan_networks` returns `[{start, end}]`, so feeding a
  reader's output into a create failed client-side schema validation. Both shapes are now
  declared (same `anyOf` contract as `set_vlan_dhcp_pools`); the handler already normalised
  them through the same safety check.

### Added

- `scripts/write_selftest.py`: a new `lan-pool-shape` scenario that dry-runs
  `create_lan_network` with the reader's pool shape, so the two schemas cannot drift apart
  again without failing loudly. Dry run only — it never creates a network.

### Notes

- No tool surface change, no new dependencies, no behaviour change for callers that already
  used the controller field names.

## [1.2.1] - 2026-11-13

Live-controller client & audit fixes verified on Omada `v6.2.10.17` and
Docker `v6.2.14.11` (**160 passing tests**).

### Fixed

- **`list_clients` / `list_wifi_clients` blank wireless fields (`_fetch_client_rows`)**:
  Prefer `sites/{id}/clients?filters.active=true` (carrying `ssid`, `ip`,
  `apName`, and `signalLevel`) with automatic fallback to `insight/clients` on
  `OmadaError` so Viewer accounts keep working while Admin accounts no longer see
  blank Wi-Fi columns on Omada `6.2.10.x`.
- **`search_clients` `vlan` and `ssid` filtering**:
  Added validated `vlan` (`0-4094`, rejecting booleans and non-integers) and
  case-insensitive `ssid` arguments matching the documented schema, composable
  with `query`, `active`, `wireless`, and `guest`.
- **`network_audit` health predicate (`_findings_healthy`)**:
  Unified `_network_audit` and `_network_audit_enriched` on a single
  `_findings_healthy(findings)` rule so warnings keep `healthy: false` across
  both paths.

## [1.2.0] - 2026-11-13

79-tool release (33 read-only diagnostics/discovery + 46 opt-in write, rollback,
and device controls), persistent keep-alive connection pooling, per-call scoped
caching, default `OMADA_READ_ONLY=true` + `OMADA_SCHEMA_MODE=slim`, `--watch` /
`--export-metrics` monitoring, non-root `Dockerfile`, and live `v6.2.10.17` /
`v6.2.14.11` verification fixes.

### Added

- **HTTP efficiency, keep-alive pooling, per-call memoization & MCP token reduction**:
  - Upgraded `UrllibTransport` (`src/omada_mcp/client.py`) to pool persistent stdlib
    `http.client.HTTPSConnection` / `HTTPConnection` sockets (`Connection: keep-alive`,
    `threading.RLock`, `CookieJar` header/cookie wiring) when direct/non-proxied, falling
    back cleanly to `urllib` `opener` when a matching system proxy applies, with 1x
    transparent reconnect on stale `GET` sockets and fail-safe no-replay semantics on
    non-idempotent writes (`POST`/`PUT`/`PATCH`/`DELETE`).
  - Added ephemeral per-invocation `OmadaClient.scoped_cache()` around composite read
    workflows (`network_audit`, `diagnose_client`, `diagnose_wan`, `get_config_snapshot`,
    `get_network_services`, `get_switch_ports`, `monitor.collect_telemetry_snapshot`) so
    site-wide endpoints (`setting/lan/profiles`, `insight/switch/detail`,
    `insight/switch/port/poe`, `devices`) are fetched at most once per call while clearing
    on scope exit and never serving cached state inside `write()`.
  - Added `OMADA_SCHEMA_MODE=slim|full` (default `slim`, cutting `tools/list` bytes by
    ~48% without weakening `inputSchema` constraints or MCP `2025-06-18` `outputSchema`
    invariants), `OMADA_TOOL_CATEGORIES` (`core,diagnostics,switch,wifi,routing,security,rollback`),
    `OMADA_COMPACT_OUTPUT=true|false` (default `true` for compact single-line `tools/call`
    JSON text), `--compact` on CLI `--list-tools`, and `includeDownPorts`/`compact` options
    on `get_switch_ports`.
- **Diagnostics surface (`src/omada_mcp/tools.py`, `src/omada_mcp/_helpers.py`, +13 read-only tools -> 33 total, ~11.3k `tools/list` tokens)**:
  - **Switch port, PoE & cable diagnostics (`get_switch_ports`, `list_port_profiles`)**:
    normalizes per-switch link/speed/duplex, PoE budget & per-port wattage, LAG
    membership, uplink vs `carriesController` port flags (preferring switch
    `upperPort.port` over upstream `upLinkPort`), RX/TX errors/drops, and cable tests.
  - **AP radio & RF environment (`get_ap_radios`, `get_rf_scan`, `list_wlan_groups`)**:
    per-band `2g`/`5g`/`5g2`/`6g` telemetry, channel index resolution via
    `channelInfo` + `actualChannel`, width flags (`20/40/80/160/320MHz`), retry/drop
    rates, utilization %, interference/noise floor, and RF scan summaries.
  - **WAN, VPN, topology, routing, local DNS & security (`get_wan_status`, `list_vpn_tunnels`, `get_topology`, `get_security_status`, `list_policy_routes`, `list_lan_dns_rules`)**:
    adds WAN link/internet health, failover/load-balance state, optional WAN IP masking,
    WireGuard/OpenVPN/IPsec/L2TP tunnel status (redacting private keys/PSKs/PEM blocks),
    compact uplink tree (`topology-v2` with v5 `/devices` fallback), IPS/WIDS alerts with
    missing-hardware warnings, and typed gateway/switch/EAP support in `list_acls` (`aclType?`).
  - **Composite troubleshooters (`diagnose_client`, `diagnose_wan`, enriched `network_audit`)**:
    correlates client signal/SNR with parent AP radio or switch port counters and recent logs,
    and enriches `network_audit` with PoE budget >= 85%, uplink speed mismatches, high AP
    retry rates, and WAN failover/loss findings without breaking existing schema keys.
- **Config, rollback & automation write surface (`src/omada_mcp/write_tools.py`, +15 opt-in write tools -> 46 total, 79 tools overall)**:
  - **Snapshot rollback (`rollback_from_snapshot`)**: resolves snapshots strictly inside
    `OMADA_SNAPSHOT_DIR` (rejecting path traversal), previews live drift on `dryRun=true`,
    and dispatches verified restoration + read-back on `dryRun=false`.
  - **Switch ports & profiles (`update_switch_port`, `cycle_poe_port`, `upsert_port_profile`)**:
    enforces fail-closed anti-stranding guards rejecting mutations on uplink, LAG member,
    or controller-hosting ports unless `allowUplinkMutation=true`, plus PoE-AP warnings.
  - **AP tuning & WLAN groups (`update_ap_radio`, `start_rf_scan`, `assign_ap_wlan_group`)**:
    preserves sibling band configs during `config/radios` PUT and validates channels/widths
    against `availableChannels` before calling the controller.
  - **Policy routes, LAN DNS, Switch/EAP ACLs & client Wi-Fi controls**: added
    `upsert_policy_route`, `delete_policy_route`, `upsert_lan_dns_rule`,
    `delete_lan_dns_rule`, `create_switch_acl`, `create_eap_acl`,
    `set_client_lock_to_ap`, and `set_client_rate_limit` — all obeying Section 1 of
    `docs/write-support.md` (`dryRun=true`, `confirm="<tool>:<target>"`, snapshot +
    read-back verify, no write retry on `-1600`).
- **Operational watch, Prometheus metrics & non-root container (`src/omada_mcp/monitor.py`, `src/omada_mcp/cli.py`, `Dockerfile`)**:
  - Added `--watch` (`--interval`, `--iterations`) JSON snapshot/diff streaming for
    WAN failover, AP retry spikes, weak-client RSSI trends, and DHCP pool utilization.
  - Added `--export-metrics` (one-shot stdout Prometheus exposition or HTTP `/metrics` +
    `/healthz` with `--metrics-port` / `--metrics-host` scrape caching). Both modes reuse
    a **single persistent `OmadaClient` session** respecting `>= 0.8 s` pacing.
  - Added non-root `Dockerfile` (`USER omada`, `OMADA_READ_ONLY=true`, `stdio` default).
- **Offline verification (`tests/mock_controller.py`, `tests/test_bridge.py`, `tests/test_write_support.py`)**:
  Expanded stateful v5/v6 mock controller and offline suite to **154 passing tests**.
- **51-tool foundation included in v1.2.0**:
  20 read-only tools (`search_clients`, `list_lan_networks`, `list_dhcp_reservations`,
  `list_acls`, `list_ip_groups`, `list_port_forwards`, `list_static_routes`,
  `get_network_services`, `list_logs`, `get_config_snapshot`) and 31 core/extended write
  tools (`set_client_fixed_ip`, `release_client_fixed_ip`, `set_vlan_dhcp_pools`,
  `set_vlan_isolation`, `create_ip_group`, `replace_ip_group`, `delete_ip_group`,
  `create_gateway_acl`, `update_gateway_acl`, `set_acl_rule_status`, `delete_gateway_acl`,
  `upsert_dhcp_reservation`, `delete_dhcp_reservation`, `create_lan_network`,
  `update_lan_network`, `delete_lan_network`, `create_ssid`, `update_ssid`, `delete_ssid`,
  `upsert_port_forward`, `delete_port_forward`, `upsert_static_route`,
  `delete_static_route`, `upsert_mdns_rule`, `delete_mdns_rule`, `set_upnp`,
  `set_client_blocked`, `reconnect_client`, `update_client`, `update_device`,
  `reboot_device`), `OmadaClient.paginate`, JSON `-30109` re-auth, and `--doctor` `write`
  phase (verified live against Docker Omada `v6.2.14.11`).

### Fixed

- **Live `v6.2.14.11` LAN/DHCP & ACL field quirks caught during Docker testing**:
  - Updated `_extract_dhcp_pools` and `_project_lan_network` to read `ipaddrStart`/
    `ipaddrEnd` inside `ipRangePool` and lowercase `leasetime` (avoiding integer
    `ipRangeStart`/`ipRangeEnd` mirrors).
  - Normalized empty `dhcpGuard: {}` / `dhcpv6Guard: {}` and `lanNetworkIpv6Config` in
    `_ensure_lan_patch_body` so PATCHes on freshly created LAN networks do not fail
    with `-1001`.
  - Updated `update_lan_network` to persist manual DHCP DNS via `priDns`/`sndDns` +
    `dhcpns` (ignoring benign controller sync of `origName` and `existSyslog` on
    `update_gateway_acl` when `name` or `syslog` changes).
  - Aligned `create_lan_network` `pools` schema to `ipaddrStart`/`ipaddrEnd` while
    accepting `{start, end}` aliases via `_validate_dhcp_pools`.
  - Added optional `aclType` (`gateway`/`switch`/`eap`) and cross-type auto-detection
    to `set_acl_rule_status`, `update_gateway_acl`, and `delete_gateway_acl`.
  - Updated `set_upnp` and `rollback_from_snapshot` for Omada `v6.2` (`PUT setting/upnp`
    accepts `{"enable": false}` when disabling, requires non-empty `wanPortIds` +
    `networkIds` when enabling, auto-resolves site WAN/LAN IDs, and warns when no
    adopted gateway exists so `-33001` is anticipated before commit).
  - Added an idempotent no-op short-circuit to `set_client_fixed_ip` when the client
    already matches the requested fixed IP and `netId` (returns `applied=true`,
    `verified=true`, empty `diff`, `snapshot=null`, and skips redundant `PATCH` writes).
  - Scrubbed anonymized fixture & test addressing (`tests/fixtures/*.json`,
    `tests/test_bridge.py`) to documentation/private-lab ranges (`172.16.<vlan>.x`,
    `192.0.2.x`).

### Kept unshipped

- Firmware upgrade and global ACL disable (`aclDisable`) toggles remain unshipped
  pending a dedicated maintenance-window policy (`aclDisable` is advisory only).
- `/controller/setting` writes remain unshipped because the controller accepts PATCHes
  with `errorCode: 0` while silently discarding changes.

## [1.1.1] - 2026-11-13

MCP `outputSchema` declarations, documented tool output shapes, path redaction
in `--doctor --json`, and a GitHub compatibility report template.

### Added

- **MCP `outputSchema` on all 10 tools (`tools/list` / `--list-tools`)**: Every
  tool descriptor now declares an MCP `2025-06-18` `outputSchema` (`type: "object"`)
  derived from its projection and matching `structuredContent`
  (`{"items": [...], "count": N}` for `list_*` tools; projected object schemas
  for `get_*`, `get_site_info`, `network_audit`, and `explain_error`).
- **Controller compatibility issue template**: Added
  `.github/ISSUE_TEMPLATE/controller-report.yml` so users can paste
  `omada-mcp --doctor --json` output to help verify new hardware/firmware builds.
- **Output shape documentation (`README.md`)**: Documented the exact `content[0].text`
  and `structuredContent` formats for list vs. single-object tools.

### Changed

- **Output shape note (`list_*` tools vs legacy wrapper objects)**: `list_devices`,
  `list_clients`, `list_wifi_clients`, `list_wired_clients`, and `list_wlans`
  emit a **bare JSON array** (`[...]`) in `content[0].text` and
  `{"items": [...], "count": <int>}` in `structuredContent` (unlike earlier
  private bridge wrappers such as `{"devices": [...]}`), while `get_device`,
  `get_client`, `get_site_info`, `network_audit`, and `explain_error` emit a
  JSON object in both `content[0].text` and `structuredContent`.
- **Demoted `software-5.x` (`5.13.30.8`) in `docs/compatibility.md` and `README.md`**:
  Moved `software-5.x` (`5.13.30.8`) from "Verified Controllers" to
  "Expected / Community-Reportable Builds" until a reproducible `--doctor --json`
  capture is attached.

### Fixed

- **Filesystem path redaction in `--doctor --json`**: Config origin (`OMADA_ENV_FILE`,
  `cwd`, `appdata`, `xdg`, `environment`) and `OMADA_CA_BUNDLE` are emitted as
  canonical labels instead of local filesystem paths when `--json` is passed,
  keeping pasted issue diagnostics free of user home/profile directories.

## [1.1.0] - 2026-11-13

Hardware/v5.x session compatibility, error-code decoder, composite network audit,
machine-readable `--doctor --json`, and CA-pinned TLS hostname override.

### Added

- **Composite `network_audit` tool (`readOnlyHint: true`)**: One idempotent, paced
  call checking WAN state, offline devices, pending firmware upgrades (`needUpgrade`),
  0-client APs, guest/unexpected VLAN clients, unisolated VLANs, and DHCP pool
  utilization (`ipRangePool`), emitting stable finding codes.
- **First-class `explain_error` tool + `ERROR_CATALOG`**: Exposes the Omada
  `errorCode` decoder (`-1`, `-1001`, `-1505`, `-1600`, `-30104`, `-30109`, `-33726`,
  `-41011`, `-44116`) offline without touching the controller, with endpoint context
  for `-1600` (GET vs write) and `-30109` (login vs session expiry).
- **`omada-mcp --doctor --json` + `schemas/doctor.schema.json`**: Machine-readable
  doctor report including `controller.family` (`software-6.x`, `hardware-5.x`, etc.)
  and `controller.sessionCookie` (`TPOMADA_SESSIONID` / `TPEAP_SESSIONID`).
- **`OMADA_TLS_SERVER_NAME`**: Optional TLS `server_hostname` override (e.g. `Omada`)
  so connecting by IP against the controller's default certificate (`SAN=DNS:Omada`)
  works with `OMADA_CA_BUNDLE` + `OMADA_VERIFY_SSL=true` instead of disabling TLS
  verification.
- **`docs/compatibility.md`**: Tracked compatibility matrix for software and hardware
  controllers.

### Fixed

- **`test_missing_config_exits_non_zero` hang on configured developer machines**:
  Isolated `_xdg_config_home` when an explicit `environ` dict is provided and
  isolated `APPDATA`, `XDG_CONFIG_HOME`, `HOME`, `USERPROFILE`, and `stdin` in the
  CLI test so `python -m unittest discover -s tests` runs cleanly even when
  `~/.config/omada-mcp/.env` or `%APPDATA%\omada-mcp\.env` exists.
- **Misleading `-30109` message on `/api/v2/login`**: Wrong credentials on login
  now report `"Invalid username or password (or account temporarily locked)"`
  instead of `"Session expired or invalid; re-authenticate."`.
- **v6.x `list_wlans` WLAN group expansion**: `list_wlans` now expands v6.x WLAN
  groups into their SSIDs via `setting/wlans/{groupId}/ssids` while still redacting
  `securityKey`, `pskSetting`, and `ppskSetting` and reporting `hasPresharedKey`.
- **v5.x / OC200 / OC300 compatibility**: Added `TPEAP_SESSIONID` cookie detection,
  legacy `result.omadacId` / top-level `token` login handling, and `needUpgrade` on
  device projections.

## [1.0.1] - 2026-11-13

Windows support, without changing the tool surface or the safety model.

### Added

- `%APPDATA%\omada-mcp\.env` is discovered on Windows, ahead of the POSIX
  `~/.config/omada-mcp/.env`, and documented (including a PowerShell setup block).
- `OMADA_USE_SYSTEM_PROXY` (default `false`): system/WinINET proxies are ignored
  for controller calls. On Windows, `urllib` inherits the registry proxy, which
  turns a one-hop controller into a timeout.
- `--doctor` prints the host platform and Python version, so a pasted report is
  triageable without asking.

### Fixed

- **Stdio encoding.** Streams are forced to UTF-8. A Windows console code page
  (cp1252, cp1256, cp437) raised `UnicodeEncodeError` on the first non-ASCII SSID
  or device name, killing the session mid-frame.
- **Frame terminators.** Frames are written with a single `\n`; text mode on
  Windows emitted `\r\n`, which strict MCP clients can mis-frame. Incoming CRLF
  frames are also accepted (regression test included).
- **Permissions advice.** `--doctor` no longer suggests `chmod 600` on Windows,
  where it silently does nothing; it points at `icacls` in the README instead.

### Changed

- `.gitattributes` normalises text files to LF on checkout, so a Windows clone
  cannot rewrite the tree.
- CI runs the suite on `windows-latest` (3.10 / 3.12 / 3.14) alongside Ubuntu, and
  asserts, from the installed wheel, that frames are LF-only and complete.

## [1.0.0] - 2026-11-13

First public release. Extracted from a working private bridge and generalised so
that any Omada controller can be driven by an MCP host.

### Added

- Eight read-only MCP tools over the Omada **Web API v2**: `list_devices`,
  `list_clients`, `list_wifi_clients`, `list_wired_clients`, `get_device`,
  `get_client`, `list_wlans`, `get_site_info`.
- Configuration discovery chain: `OMADA_ENV_FILE` -> `./.env` ->
  `~/.config/omada-mcp/.env`, with the process environment always winning.
- Automatic `omadacId` discovery and site resolution via `OMADA_SITE_ID` or
  `OMADA_SITE_NAME`, defaulting to the first visible site.
- `OMADA_VERIFY_SSL`, `OMADA_CA_BUNDLE` and `OMADA_STRICT_X509` for controller
  certificates, including the Python 3.13+ `VERIFY_X509_STRICT` opt-out.
- `OMADA_READ_ONLY` safety mode: anything not declared read-only is refused with
  JSON-RPC error `-32003`, before tool lookup (fails closed).
- `omada-mcp --doctor`: ordered self-test for dotenv, TLS/CA, login, controller
  version, site discovery and one live read call, each failure with an exact fix.
- MCP tool annotations: `readOnlyHint`, `destructiveHint`, `idempotentHint`,
  `openWorldHint`, plus `title`.
- Session recovery: a 200 response containing the web UI shell triggers one
  re-authentication and a replay, never a loop.
- PACING: calls are spaced (`OMADA_MIN_INTERVAL_SECONDS`, default 0.25 s) and a
  burst `-1600` is retried once after 0.8 s.
- WLAN pre-shared keys are redacted; `hasPresharedKey` reports their presence.
- Zero runtime dependencies; 59 stdlib unit tests; CI on Python 3.10-3.14.
- Verified live on software controller v6.2.10.17: `--doctor` passes and all
  eight read tools return live data (4 devices, 15 clients, 1 WLAN, PSK not
  exposed); write refusal confirmed with `OMADA_READ_ONLY=true`.
