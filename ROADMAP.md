# Roadmap

v1.0 is intentionally narrow: eight read-only tools, a doctor, and a safety
switch. The ordering below is driven by what blocks an external user from
adopting the server, not by what is fun to build.

Each item lists the evidence that it matters, so it can be re-prioritised when
that evidence changes.

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
* Read-only `get_config_snapshot` plus expanded read tools (`list_lan_networks`,
  `list_dhcp_reservations`, `list_acls`, `list_ip_groups`, `list_port_forwards`,
  `list_static_routes`, `get_network_services`, `list_logs`) and 31 opt-in write tools:
  the core 8 (`set_client_fixed_ip`, `release_client_fixed_ip`, `set_vlan_dhcp_pools`,
  `set_vlan_isolation`, `create_ip_group`, `replace_ip_group`, `create_gateway_acl`,
  `set_acl_rule_status`) plus offline DHCP reservation CRUD, LAN/VLAN CRUD, ACL
  update/delete, IP-group delete, SSID CRUD (PSK-redacted), port forwarding, static
  routing, mDNS/UPnP service controls, client block/reconnect/rename, and device
  rename/LED/locate/reboot.
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

* **Prometheus text endpoint** (`--export-metrics`) reusing the audit data, for
  people who already scrape.
* **Docker image** and a Home Assistant add-on manifest.
* **Contract fixtures**: anonymised `--doctor --json` captures from v5.6, v5.13,
  v6.1 and v6.2 replayed in CI, so a firmware change is caught before a user
  reports it.
* **`omada-mcp --watch`**: sample AP retries and client RSSI for N minutes and
  report the trend, for "why is the WiFi slow at 21:00" questions.

## Explicitly out of scope

* Open API / OAuth2 support — it requires controller-side Platform Integration
  and buys nothing the Web API does not already do locally.
* Cloud portal or remote access. This server is for a network you can route to.
* Write access to controller settings (timezone, name, certificate): the Web API
  accepts those writes and silently ignores them, which is worse than refusing.
* Anything that needs a TP-Link developer account.
