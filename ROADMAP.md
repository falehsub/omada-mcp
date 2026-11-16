# Roadmap

As of `v2.3.0`, the shipped control surface provides **54 read-only tools** and
**78 explicitly allowlisted opt-in write tools** (**132 tools total**, zero
runtime dependencies, **250 unit tests**). Priorities are driven by successful
user adoption and verifiable controller behavior.

Each item lists the evidence that it matters, so it can be re-prioritised when
that evidence changes.

## Shipped since the November 2026 review (`v2.0.0` → `v2.3.0`)

The items queued after the [local review](docs/review-2026-11-14.md) and Phases A–C
coverage expansion are now shipped on `main` and PyPI:

1. **Automated Docker compatibility & CI matrix (`v2.0.0`):** [`.github/workflows/compat.yml`](.github/workflows/compat.yml)
   plus multi-OS CI across Linux, macOS, and Windows (Python 3.10–3.14).
2. **PyPI Trusted Publishing & MCP Registry metadata (`v2.0.0` → `v2.3.0`):**
   [`server.json`](server.json), generated [`docs/tools-reference.md`](docs/tools-reference.md),
   and OIDC publishing to PyPI & GHCR via [`.github/workflows/publish.yml`](.github/workflows/publish.yml).
3. **Multi-site & cross-site fleet controls (`v2.0.0` → `v2.3.0`):** `list_sites`,
   per-call `site`, strict `OMADA_ALLOW_CROSS_SITE` pinning, and `audit_all_sites`.
4. **Deterministic configuration drift diff (`v2.0.0` → `v2.3.0`):**
   `diff_config_snapshots` over redacted snapshots (expanded in `v2.3.0` to cover
   schedules, rate-limit profiles, PoE schedules, wireless features, RF planning,
   VPNs, WireGuard tunnels/peers, DDNS, traffic rules, and QoS).
5. **Active diagnostics, deep switch L2, Wi-Fi/RF, VPN/WireGuard, Hotspot & Backup (`v2.1`–`v2.3` shipped as `v2.3.0`):**
   Added 50 tools (`run_ping`, `run_traceroute`, `start_wan_speedtest`,
   `start_cable_test`, port/MAC groups, schedules, switch LAGs/global L2/port mirror,
   PoE schedules, AP SSID overrides, mesh & AI WLAN optimization, `get_wan_ip_details`,
   `get_ipv6_status`, `list_traffic_rules`, `list_qos_rules`, `list_backups`,
   `export_controller_backup`, `list_hotspot_vouchers` / `create_hotspot_vouchers` /
   `revoke_hotspot_voucher`, WireGuard/DDNS/VPN toggle CRUD, `hotspot` category, and
   `OMADA_TOOL_CATALOG=core|full`).

## Open & future priorities (`v2.4+`)

1. **Live v5.x hardware & controller captures:** Collect anonymized `--doctor --json`
   and `scripts/capture_fixtures.py` bundles from `OC200`/`OC300` hardware and
   `TPEAP_SESSIONID` v5.x builds.
2. **Guarded read-only Web API v2 discovery helpers / optional OpenAPI hybrid:** Only
   consider if a clear user workflow needs endpoints beyond the typed 132-tool surface
   without breaking zero-dependency defaults.
3. **Home Assistant add-on packaging:** Reuse the non-root container (`Dockerfile`)
   with Ingress / add-on config manifests.

## v1.1 — "works on the controllers people actually own" *(shipped in v1.1.0)*

### 1. Hardware controllers (OC200 / OC300) and v5.x session cookies *(shipped)*

**Why first:** the software controller is the minority deployment. Most Omada
households and small offices run an OC200, and a server that only works on the
software build caps adoption at people who already run a hypervisor.

* Accept whichever session cookie the controller sets (`TPOMADA_SESSIONID` on
  v6.x, `TPEAP_SESSIONID` on some v5.x builds). The cookie jar already replays
  whatever arrives; `--doctor` now detects and reports the active session
  cookie name and distinguishes "cookie missing" from "server-side session dead".
* Probe the two legacy login response shapes: `result.token` (v6.x) and the
  older `result.token` + `result.omadacId` split.
* Add a `--doctor` phase detail that prints the detected controller family
  (`software-6.x`, `hardware-5.x`, …) so a bug report is actionable in one line.
* CI cannot cover hardware directly; added [`docs/compatibility.md`](docs/compatibility.md)
  to track verified `controllerVer` strings and community reports.

**Acceptance:** `--doctor` reaches `PASS login` on an OC200 running v5.x, and the
read tools return live data.

### 2. Error-code decoder as a first-class surface *(shipped)*

**Why:** every support thread about Omada ends with "what does -1600 mean".
`describe_error()` already exists internally; exposing it costs almost nothing
and turns the server into the reference implementation.

* New read-only tool `explain_error` (`code`, optional `endpoint`) returning the
  meaning, the two-way ambiguity note for `-1600`, and the fix.
* `--doctor --json` for machine-readable output, validated against
  [`schemas/doctor.schema.json`](schemas/doctor.schema.json).
* `describe_error` gains endpoint + method context: `-1600` on `GET` vs on `POST`/`DELETE`,
  and `-30109` on `/api/v2/login` vs authenticated endpoints.

**Acceptance:** the message for `-33726` states the 16-entry limit and the CIDR
remediation; `--doctor --json` matches `schemas/doctor.schema.json`.

### 3. Composite `network_audit` tool *(shipped)*

**Why:** an LLM can chain multiple reads, but it costs extra round-trips and the
model still has to know what "healthy" looks like. One call that answers "is
this network okay?" is the feature people show each other.

One call, one JSON document:

* devices needing firmware upgrades, and devices offline;
* clients on guest SSIDs or on unexpected VLANs;
* APs with zero clients (dead radio, or misplaced);
* VLANs with `accessControlRule: false` where isolation was expected;
* DHCP pools close to exhaustion (`ipRangePool` vs live leases);
* controller/site identity, versions, and the site's WAN state.

Design constraints: bounded runtime (reuses one authenticated session), `readOnlyHint: true`,
and every finding carries a stable `code` so downstream tooling can diff two audits.

**Acceptance:** a fresh site produces the same audit twice in a row (idempotent),
and the runtime stays under ~5 s on a 4-device / 15-client site (verified at ~2.5 s live).

## v1.2 — "usable as a daily driver"

### 4. Write tools behind an explicit allowlist (shipped on `main`)

**Why:** DHCP reservations, VLAN isolation/DHCP pool tuning, and IP-group/ACL updates
are the next natural step after read-only visibility, but they must stay hidden and
fail closed unless explicitly enabled.

* `OMADA_WRITE_TOOLS` allowlist (default empty): `OMADA_READ_ONLY=false` alone cannot
  run writes; wildcards and `all` are rejected cleanly at startup.
* Expanded diagnostics (`33` read-only tools including `get_switch_ports`,
  `get_ap_radios`, `get_rf_scan`, `get_wan_status`, `list_vpn_tunnels`,
  `get_topology`, `get_security_status`, `diagnose_client`, `diagnose_wan`,
  `list_port_profiles`, `list_wlan_groups`, `list_policy_routes`,
  `list_lan_dns_rules`) plus `47` opt-in write tools:
  the core 8 (`set_client_fixed_ip`, `release_client_fixed_ip`, `set_vlan_dhcp_pools`,
  `set_vlan_isolation`, `create_ip_group`, `replace_ip_group`, `create_gateway_acl`,
  `set_acl_rule_status`), offline DHCP / LAN / ACL / IP-group / SSID / port-forward /
  static-route / mDNS / UPnP / client / device CRUD, and Milestone 2 automation +
  rollback (`rollback_from_snapshot`, switch port/PoE/profile controls with LAG/uplink
  anti-stranding, AP radio/RF scan/WLAN group tuning, policy routes, local LAN DNS,
  switch/EAP ACLs, and client Lock-to-AP / rate limiting).
* Every write tool defaults `dryRun` to `true`, requires `confirm: "<tool>:<target-id>"`
  for `dryRun=false`, saves pre-write JSON snapshots + `audit.jsonl` records, enforces
  controller/management-host anti-stranding guards, and verifies read-back state.
* Respects live controller traps documented in [`docs/write-support.md`](docs/write-support.md):
  two-endpoint LAN RMW, non-authoritative `aclDisable`, `-33726` aligned CIDR packing
  (`<=16`), `-33717` 6-step tmp-group swap for ACL-referenced IP groups, 20 stripped
  volatile client keys, `dhcpGuard`/`dhcpv6Guard`/`lanNetworkIpv6Config` normalization,
  `priDns`/`sndDns` DNS persistence, and no blind `-1600` retries on writes.
* Firmware upgrade remains unshipped until a dedicated maintenance-window policy exists.

### 5. Discoverability: MCP Registry `server.json` + listings

**Why:** a good README does not get found. The registry is where MCP hosts look.

* `server.json` per the MCP Registry schema (`name: io.github.<user>/omada-mcp`,
  `packages: [{registryType: "pypi", identifier: "omada-mcp", version}]`).
* Publish to the registry (requires the PyPI package to exist first, so this
  lands after `uv publish`).
* Listings/snippets for the popular directories, generated from `--list-tools`
  so the tool table cannot drift.

**Acceptance:** `mcp-publisher publish` succeeds and a registry client resolves
`omada-mcp` to this package.

### 6. Filtered search instead of "fetch everything" *(shipped on `main`)*

**Why:** a 200-client site returns a large payload for a question like "which
clients are on the guest VLAN".

* `search_clients` with `query`, `active`, `wireless`, `guest`, and `limit`
  filters applied server-side over paginated fetch (`insight/clients` fallback on
  Viewer `-1007`/`-41011`), returning a bounded matching slice without returning the
  entire client table.

## v1.3 — "operational"

* **Prometheus text endpoint & HTTP server** (`--export-metrics`, `--metrics-port`)
  *(shipped on `main`)*: single persistent authenticated session respecting `>= 0.8 s`
  pacing, exporting WAN link/failover, AP retries/utilization, client RSSI/signal,
  and DHCP pool metrics (`/metrics` + `/healthz`).
* **`omada-mcp --watch`** *(shipped on `main`)*: continuous read-only polling on one
  session emitting JSON diffs (`wan_failover`, `ap_retry_spike`, `weak_client_rssi`,
  `dhcp_pool_utilization`) with `--interval` / `--iterations`.
* **Container packaging** (`Dockerfile`) *(shipped on `main`)*: minimal non-root image
  with `OMADA_READ_ONLY=true` (`stdio` default, `--watch`, `--export-metrics`).
  *(Home Assistant add-on manifest remains planned.)*
* **Contract fixtures**: anonymised `--doctor --json` captures from v5.6, v5.13,
  v6.1 and v6.2 replayed in CI, so a firmware change is caught before a user
  reports it. *(v6.2 diagnostics/write fixtures captured; v5.6/v5.13/v6.1 captures planned.)*

## Explicitly out of scope

* Open API / OAuth2 support — it requires controller-side Platform Integration
  and buys nothing the Web API does not already do locally.
* Cloud portal or remote access. This server is for a network you can route to.
* Write access to controller settings (timezone, name, certificate): the Web API
  accepts those writes and silently ignores them, which is worse than refusing.
* Anything that needs a TP-Link developer account.
