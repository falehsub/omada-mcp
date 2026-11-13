# omada-mcp

**A Model Context Protocol server for TP-Link Omada SDN controllers — zero dependencies, read-only by default, and honest about every failure.**

[![CI](https://github.com/falehsub/omada-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/falehsub/omada-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](pyproject.toml)

Your Omada controller already knows which AP is overloaded, which client is
sitting on the guest VLAN, and which switch dropped a port. `omada-mcp` hands
that to Claude, Cursor, Hermes or any other MCP host — as twenty read-only tools
that return clean JSON (plus 31 optional write tools behind an explicit allowlist),
with a self-test that tells you exactly what to fix when something is wrong.

```
uvx omada-mcp --doctor
```

```
omada-mcp doctor v1.1.1 on Linux-6.8 (Python 3.12.7)
------------------------------------------------------------------
PASS env      /home/you/.config/omada-mcp/.env | url=https://192.0.2.10:8043 user=omada-readonly password=set (24 chars)
PASS tls      verified against /home/you/.config/omada-mcp/controller-ca.pem (serverName=Omada) | reachable, omadacId=0123456789abcdef01234567, controllerVer=6.2.10.17, family=software-6.x
PASS login    token accepted for omada-readonly (role=Viewer, scope=all sites, cookie=TPOMADA_SESSIONID), Csrf-Token round-trip OK
PASS site     Home (89abcdef0123456789abcdef) site 1 of 1; matched OMADA_SITE_NAME=Home
PASS tools    list_devices -> 7 device(s); 20 read-only tools registered (0 write tool(s) enabled), 23 client(s)
PASS write    disabled (OMADA_WRITE_TOOLS is empty; read-only tools only)
------------------------------------------------------------------
6/6 checks passed
Ready: `omada-mcp` will serve 20 read-only tools on stdio.
```

Add `--json` (`omada-mcp --doctor --json`) for machine-readable output validated against [`schemas/doctor.schema.json`](schemas/doctor.schema.json). JSON output redacts local `.env` and `OMADA_CA_BUNDLE` filesystem paths to origin labels (`OMADA_ENV_FILE`, `cwd`, `appdata`, `xdg`, `environment`) so reports are safe to paste into issues.

---

## Why this exists

Omada exposes two unrelated APIs and the documentation blurs them:

| | **Web API v2** (`/{omadacId}/api/v2/...`) | **Open API** (`/openapi/v1/...`) |
|---|---|---|
| Auth | username + password (`Csrf-Token` + `TPOMADA_SESSIONID`) | OAuth2 client-credentials |
| Setup on controller | none — it is the API the web UI calls | "Platform Integration" must be configured |
| Account roles | Viewer is enough | Client ID/secret per integration |
| Works on OC200/OC300 | yes | firmware dependent |

`omada-mcp` speaks the **Web API**. That means: create a local Viewer account,
put three values in a dotenv file, and you are done. No OAuth app, no client
secret rotation, no per-firmware integration screen.

Three properties make it safe to hand to an LLM:

* **Read-only tools only.** Every tool is annotated `readOnlyHint: true`, and
  `OMADA_READ_ONLY=true` fails closed: a call to anything not declared read-only
  is refused with `-32003` *before* lookup, so a future write tool cannot leak
  past the switch.
* **No secret echo.** The password never appears in output (only `set (N chars)`),
  the session token is never logged, and WLAN pre-shared keys are redacted —
  `list_wlans` reports `hasPresharedKey: true` instead.
* **Errors that carry the fix.** Controller error codes are translated
  (`-1505`, `-1600`, `-33726`, `-41011`, `-44116`, …) and every message ends with
  the action to take.

## Install

```bash
# from git (works today)
uvx --from git+https://github.com/falehsub/omada-mcp omada-mcp --doctor

# from PyPI (once v1.0.1 is published there -- the name `omada-mcp` is reserved-free)
uvx omada-mcp --doctor

# or install the command (once published to PyPI)
uv tool install omada-mcp     # or: pipx install omada-mcp
pip install omada-mcp         # plain pip

# today, without PyPI:
git clone https://github.com/falehsub/omada-mcp && cd omada-mcp
uv tool install .             # installs the `omada-mcp` command from the checkout
```

Requires Python 3.10+ and nothing else. There are **no runtime dependencies** —
`urllib`, `ssl`, `json` and `argparse` are the whole stack, which keeps the
supply chain at zero.

## Configure

```bash
mkdir -p ~/.config/omada-mcp
cp .env.example ~/.config/omada-mcp/.env
chmod 600 ~/.config/omada-mcp/.env
$EDITOR ~/.config/omada-mcp/.env
```

The minimum is three lines:

```dotenv
OMADA_BASE_URL=https://192.0.2.10:8043
OMADA_USERNAME=omada-readonly
OMADA_PASSWORD=...
```

### Where configuration is read from

Highest priority first — the first hit wins per variable, and the process
environment always overrides a file:

1. **process environment** (`export OMADA_BASE_URL=...`)
2. **`$OMADA_ENV_FILE`** — an explicit path (missing file = hard error, so a typo
   cannot silently fall through)
3. **`./.env`** — relative to the working directory (handy for per-project setups)
4. **`%APPDATA%\omada-mcp\.env`** — Windows only, where a Windows user expects a per-user config
5. **`~/.config/omada-mcp/.env`** (or `$XDG_CONFIG_HOME/omada-mcp/.env`)

### Windows

Everything is supported natively — no WSL, no MSYS. The console script installs as
`omada-mcp.exe`, and `uvx` / `uv tool install` behave exactly as on POSIX.

```powershell
New-Item -ItemType Directory -Force "$env:APPDATA\omada-mcp" | Out-Null
Copy-Item .env.example "$env:APPDATA\omada-mcp\.env"
notepad "$env:APPDATA\omada-mcp\.env"
```

Windows-specific behaviour, handled for you:

* **Config location.** `%APPDATA%\omada-mcp\.env` is picked up before
  `~/.config/omada-mcp/.env`, so the usual Windows location just works.
* **Encoding.** Stdio is forced to UTF-8. The console code page (cp1252, cp1256,
  cp437 …) cannot encode an Arabic or CJK SSID, and the failure mode is a
  `UnicodeEncodeError` in the middle of a session — this never reaches you.
* **Line endings.** Frames are written with a single `\n`; text mode would
  otherwise emit `\r\n` and strict clients can mis-frame. Incoming `\r\n`
  frames are accepted too.
* **Proxies.** System/WinINET proxies are ignored by default
  (`OMADA_USE_SYSTEM_PROXY=true` to opt in).
* **File permissions.** API keys live in your user profile; `--doctor` skips the
  POSIX `chmod` advice on Windows rather than handing you a command that does
  nothing. To restrict the file to your account:
  `icacls "%APPDATA%\omada-mcp\.env" /inheritance:r /grant:r "%USERNAME%:F"`.

`get_device`/`get_client` accept a MAC in any format (`AA-BB-CC-DD-EE-FF`,
`aabbccddeeff`, `aa:bb:cc:dd:ee:ff`) as well as a hostname or IP, so PowerShell
output pastes straight in.

### All variables

| Variable | Default | Notes |
|---|---|---|
| `OMADA_BASE_URL` | — **required** | `https://host:8043`. Scheme-less values get `https://…:8043`; `http://` defaults to port 8088. Must not embed credentials. |
| `OMADA_USERNAME` | — **required** | Local controller account. `Viewer` is sufficient for reads; use a **dedicated Admin account** for writes (every login evicts an existing session sharing that username). |
| `OMADA_PASSWORD` | — **required** | Never printed, never logged. |
| `OMADA_SITE_NAME` | first site | Display name, e.g. `Home`. |
| `OMADA_SITE_ID` | first site | Hex id **or** name — names are resolved, because the controller only accepts the hex id in URLs (that mismatch is exactly what `-1505` reports). |
| `OMADA_CA_BUNDLE` | system store | PEM bundle with the controller's CA. |
| `OMADA_VERIFY_SSL` | `true` | `false` disables chain + hostname checks. Not for production. |
| `OMADA_STRICT_X509` | `true` | `false` clears Python 3.13+'s `VERIFY_X509_STRICT` while keeping chain and hostname checks — the fix for "self-signed certificate" errors on 3.13/3.14. |
| `OMADA_TLS_SERVER_NAME` | — | Optional TLS `server_hostname` override (e.g. `Omada`) when connecting by IP against the controller's built-in cert (`SAN=DNS:Omada`) so `OMADA_CA_BUNDLE` still verifies the chain and SAN. |
| `OMADA_READ_ONLY` | `false` | `true` refuses every non-read-only tool (`-32003`) before argument validation. |
| `OMADA_WRITE_TOOLS` | empty | Comma-separated exact write tool names to enable (wildcards and `all` are rejected). Both `OMADA_READ_ONLY=false` and this allowlist are required to expose or invoke any write tool. |
| `OMADA_SNAPSHOT_DIR` | platform state dir | Override directory for pre-write JSON snapshots and `audit.jsonl` (POSIX `0700`/`0600`). Defaults to `$XDG_STATE_HOME/omada-mcp/snapshots` (`%LOCALAPPDATA%\omada-mcp\snapshots` on Windows). |
| `OMADA_MANAGEMENT_CIDRS` | empty | Comma-separated IPv4 hosts/CIDRs (in addition to controller host IP) protected from lockouts during VLAN isolation, DHCP pool, or deny-ACL writes. |
| `OMADA_USE_SYSTEM_PROXY` | `false` | System/registry proxies are ignored by default. On Windows, `urllib` inherits the WinINET proxy, which makes a one-hop controller look unreachable; set `true` only when a proxy is genuinely required. |
| `OMADA_TIMEOUT_SECONDS` | `30` | Per-request timeout. |
| `OMADA_MIN_INTERVAL_SECONDS` | `0.25` | Minimum spacing between controller calls; raise to `0.8` on large sites. |
| `OMADA_WRITE_INTERVAL_SECONDS` | `1.0` | Minimum serialized spacing between write requests (writes never auto-retry `-1600`). |

`omada-mcp --show-config` prints the resolved values with the password masked;
`omada-mcp --doctor` validates them.

## Connect an MCP host

The server is plain stdio: a host runs `uvx omada-mcp`, then speaks JSON-RPC on
stdin/stdout. The `OMADA_ENV_FILE` environment variable lets several hosts share
one configuration file.

### Hermes Agent

```bash
hermes mcp add omada --command uvx --args omada-mcp \
  --env OMADA_ENV_FILE=$HOME/.config/omada-mcp/.env
```

Or in `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  omada:
    command: uvx
    args: ["omada-mcp"]
    env:
      OMADA_ENV_FILE: /home/you/.config/omada-mcp/.env
```

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or
`%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "omada": {
      "command": "uvx",
      "args": ["omada-mcp"],
      "env": {
        "OMADA_ENV_FILE": "/home/you/.config/omada-mcp/.env"
      }
    }
  }
}
```

A copy lives at [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json).

### Claude Code

```bash
claude mcp add omada --env OMADA_ENV_FILE=$HOME/.config/omada-mcp/.env -- uvx omada-mcp
claude mcp list
```

### Cursor

`.cursor/mcp.json` in the project, or the global `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "omada": {
      "command": "uvx",
      "args": ["omada-mcp"],
      "env": { "OMADA_ENV_FILE": "/home/you/.config/omada-mcp/.env" }
    }
  }
}
```

### Anything else

Any host that can spawn a process and speak newline-delimited JSON-RPC 2.0 works:

```json
{
  "mcpServers": {
    "omada": {
      "command": "uvx",
      "args": ["omada-mcp"],
      "env": { "OMADA_ENV_FILE": "/home/you/.config/omada-mcp/.env" }
    }
  }
}
```

From a git checkout instead of PyPI:

```bash
uvx --from git+https://github.com/falehsub/omada-mcp omada-mcp --doctor
```

## Tools

Twenty read-only tools are always registered; 31 optional write tools stay hidden
and disabled until both `OMADA_READ_ONLY=false` and `OMADA_WRITE_TOOLS` allowlist
them explicitly. `list_clients` windowing is bounded by `limit` (default 500, max 5000)
and de-duplicated by MAC.

### Read-only tools (always available)

| Tool | Arguments | Returns |
|---|---|---|
| `get_site_info` | — | Site name/id, WAN/LAN/WLAN state, device and client counts, controller version |
| `list_devices` | — | MAC, name, type, model, firmware, IP, uptime, client count, status, `needUpgrade` |
| `list_clients` | `limit?` | MAC, name, hostname, IP, wireless, guest, SSID, AP, network, VLAN, rx/tx, duration, last seen (UTC ISO-8601) |
| `list_wifi_clients` | `limit?` | Same projection, wireless only |
| `list_wired_clients` | `limit?` | Same projection, wired only |
| `search_clients` | `query?`, `active?`, `wireless?`, `guest?`, `limit?` | Filtered client search (`clients` for Admin; automatic `insight/clients` fallback on Viewer `-1007`/`-41011`) |
| `get_device` | `mac` (or name) | One device |
| `get_client` | `mac` (or hostname/IP) | One client |
| `list_wlans` | — | SSID, band, VLAN, security, guest, `hasPresharedKey` (expands v6.x WLAN groups; key never returned) |
| `list_lan_networks` | — | Merged `setting/lan/networks` + `/interface` view (VLAN, subnet, DHCP `ipRangePool`, `leasetime`, `isolation`, `accessControlRule`) |
| `list_dhcp_reservations` | `vlan?` | Offline/static DHCP reservations from `setting/service/dhcp` |
| `list_acls` | — | Gateway ACL rules (`?type=0`) and advisory `aclDisable` flag |
| `list_ip_groups` | `groupType?` | IP/port/profile groups (`setting/profiles/groups`) with CIDRs / entries |
| `list_port_forwards` | — | Port-forwarding NAT rules (`setting/transmission/portForwardings`) |
| `list_static_routes` | — | Static/interface routes (`setting/transmission/staticRoutings`) |
| `get_network_services` | — | UPnP, DNS proxy, mDNS rules & built-in profiles, DDNS, and WAN port state |
| `list_logs` | `category?`, `hours?`, `level?`, `limit?` | Controller `alerts`, `events`, or `audit` logs within time window |
| `network_audit` | — | Composite one-call health audit: pending firmware, offline devices, 0-client APs, guest/unexpected VLAN clients, unisolated VLANs, DHCP pool utilization, and stable finding codes |
| `explain_error` | `code`, `endpoint?` | Structured decoder for Omada `errorCode` values (`-1600`, `-33717`, `-33726`, `-1505`, `-1001`, `-30109`, `-41011`, `-44116`, …) with ambiguity notes and fixes |
| `get_config_snapshot` | `objects?` | Read-only snapshot merging `networks`, `acls`, `groups`, `wlans`, `devices`, and optional `clients`, `dhcpReservations`, `portForwards`, `staticRoutes`, `mdnsRules`, `services` |

### Opt-in write tools (`OMADA_READ_ONLY=false` + `OMADA_WRITE_TOOLS`)

Every write tool defaults `dryRun=true` and requires `confirm="<tool>:<target>"` when `dryRun=false`.

| Category | Tools | Behaviour & Safety |
|---|---|---|
| Live client fixed IP | `set_client_fixed_ip`, `release_client_fixed_ip` | Full-object client PATCH (20 volatile keys stripped), mandatory `netId`, lease-delayed, refuses device MACs (`-41011`) |
| Client actions & metadata | `set_client_blocked`, `reconnect_client`, `update_client` | Block/unblock, kick/reconnect, or rename active/known client (`cmd/clients/...`, `clients/{mac}`) |
| Offline DHCP reservations | `upsert_dhcp_reservation`, `delete_dhcp_reservation` | Create/update/delete reservations in `setting/service/dhcp` with subnet & IP-overlap validation |
| LAN & VLAN management | `create_lan_network`, `update_lan_network`, `delete_lan_network`, `set_vlan_dhcp_pools`, `set_vlan_isolation` | Two-endpoint LAN RMW, normalizes `lanNetworkIpv6Config` + `dhcpGuard`/`dhcpv6Guard`, uses `priDns`/`sndDns`, checks `ipRangePool`, refuses management/primary VLAN deletion |
| IP groups & Gateway ACLs | `create_ip_group`, `replace_ip_group`, `delete_ip_group`, `create_gateway_acl`, `update_gateway_acl`, `set_acl_rule_status`, `delete_gateway_acl` | Aligned CIDR packing (`<=16`, `-33726`), typed delete `/{type}/{id}`, auto 6-step swap for `-33717`, gateway ACL `?type=0` PUT/POST/DELETE with management-host anti-stranding |
| Wireless SSIDs | `create_ssid`, `update_ssid`, `delete_ssid` | Manage SSIDs under `setting/wlans/{groupId}/ssids`; PSK/secret keys scrubbed recursively from diffs, outputs, and snapshots |
| Port forwards, routes & services | `upsert_port_forward`, `delete_port_forward`, `upsert_static_route`, `delete_static_route`, `upsert_mdns_rule`, `delete_mdns_rule`, `set_upnp` | NAT port forwards, static routing (`routeType`, `nextHop`, `metric`), mDNS repeater rules (profile name/ID resolution), and UPnP toggle |
| Device operations | `update_device`, `reboot_device` | Rename / LED / locate / reboot EAPs, switches, and gateways (`destructive=True` on reboot; firmware upgrade remains unshipped) |

`omada-mcp --list-tools` prints active descriptors without touching the network
(add `--all` to inspect all 51 tools including non-allowlisted writes).

Every descriptor in `tools/list` declares MCP annotations and an MCP `2025-06-18`
`outputSchema`, so hosts can auto-approve reads and validate structured results:

```json
{
  "name": "list_devices",
  "title": "List Omada devices",
  "outputSchema": {
    "type": "object",
    "properties": {
      "items": { "type": "array" },
      "count": { "type": "integer", "minimum": 0 }
    },
    "required": ["items", "count"]
  },
  "annotations": {
    "title": "List Omada devices",
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "openWorldHint": true
  }
}
```

### Output shape (`content` vs `structuredContent`)

* **List tools** (`list_devices`, `list_clients`, `list_wifi_clients`,
  `list_wired_clients`, `search_clients`, `list_wlans`, `list_lan_networks`,
  `list_dhcp_reservations`, `list_acls`, `list_ip_groups`, `list_port_forwards`,
  `list_static_routes`, `list_logs`): `content[0].text` is serialized as a
  **bare JSON array** (`[{...}, ...]`), while `structuredContent` is an object
  matching `outputSchema`: `{"items": [...], "count": <int>}`. Callers parsing
  `content[0].text` (for example migrating from wrapper objects like
  `{"devices": [...]}`) receive a JSON list directly, whereas MCP `2025-06-18`
  hosts read `structuredContent.items` and `structuredContent.count`.
* **Object tools** (`get_device`, `get_client`, `get_site_info`,
  `get_network_services`, `network_audit`, `explain_error`, `get_config_snapshot`,
  and write envelopes): both `content[0].text` and `structuredContent` contain
  the same JSON object matching `outputSchema`.

`omada-mcp --list-tools` prints active descriptors without touching the network;
`omada-mcp --list-tools --all` prints all 51 descriptors.

## Safety model

| Control | Behaviour |
|---|---|
| `OMADA_READ_ONLY=true` | Refuses any tool not declared read-only (`-32003`), before argument validation or transport. |
| `OMADA_WRITE_TOOLS` allowlist | Defaults empty. Wildcards and `all` are rejected; write tools remain hidden and return `-32003` unless explicitly named. |
| Two-phase apply (`dryRun` / `confirm`) | Every write defaults `dryRun=true` (zero writes; returns diff + `confirmToken`). Applying requires boolean `dryRun=false` and exact `confirm="<tool>:<target-id>"`. |
| Snapshot before & verify after | Saves pre-write JSON snapshot + `audit.jsonl` record (`0700`/`0600` on POSIX), re-reads state afterwards, and fails on silent controller no-ops or collateral field drift. |
| Anti-stranding guards | Refuses VLAN isolation, DHCP pool overlaps, or deny ACL rules that isolate/conflict with controller IP, gateway, device IPs, or `OMADA_MANAGEMENT_CIDRS`. |
| Credential handling | Password only ever rendered as `set (N chars)`; tokens never logged; stdout is reserved for JSON-RPC, diagnostics go to stderr. |
| Secret redaction | `list_wlans` and `get_config_snapshot` omit `securityKey` / `pskSetting`; only `hasPresharedKey` is exposed. |
| Session recovery | A 200 response containing the web UI shell triggers **one** re-login: reads replay once, writes re-read live state first and never auto-retry `-1600`. |
| Pacing | Reads spaced by `OMADA_MIN_INTERVAL_SECONDS`; writes serialized at `OMADA_WRITE_INTERVAL_SECONDS` (default 1.0 s). |
| Dotenv hygiene | `--doctor` warns when the dotenv file is readable by group/other, and flags Viewer accounts when write tools are enabled. |

## Troubleshooting

Run `omada-mcp --doctor` first — it names the failing phase and the fix. The
table below maps the symptoms it cannot see.

| Symptom | Cause | Fix |
|---|---|---|
| `-1505` on a site call | Site **name** used where the hex site id is required | Set `OMADA_SITE_NAME` (or `OMADA_SITE_ID`) and let the server resolve it |
| `-1600` everywhere | Wrong path shape (`GET /networks/{id}`, missing `/{type}` on group DELETE, no PATCH on groups) **or** burst rate-limiting | Reads retry once after 0.8 s; writes never auto-retry `-1600` |
| `-33717` on group delete | Group is referenced by one or more ACL rules | Use `replace_ip_group`, which performs the 6-step temp-group ACL swap automatically |
| `-33726` on an IP group write | The group holds at most **16** entries | Store ranges as network-aligned CIDRs (packed automatically by `create_ip_group`/`replace_ip_group`) |
| `-1001` "bean validation" | A mandatory field missing from a PATCH body — for LAN networks it is `lanNetworkIpv6Config` (`proto: "none"`, `enable: 0`) | Send the whole object (handled automatically by LAN write tools) |
| `-1007` "no permission" | Current user role lacks write permission (e.g. Viewer account on Omada 6.2.x) | Use a dedicated Admin account for writes; keep Viewer for read-only mode |
| `-33598` "network isolation" | No adopted gateway/switch on the site supports Network Isolation | Adopt an isolation-capable gateway/switch or use gateway ACLs instead |
| `-33601` "invalid destination type" | `destinationType: 0` (`network`) used on a `LAN->WAN` gateway ACL | Use an IP group (e.g. `IPGroup_Any`) or port group on `LAN->WAN` rules |
| `-41011` | Client does not exist, MAC belongs to a managed device, **or** Viewer role on `/clients/*` | Use `insight/clients` or `list_devices` to inspect; use a dedicated Admin account for writes |
| `-44116` | You are on the Open API without Platform Integration | Use this server (Web API) instead |
| HTTP 200 with HTML in response | The controller's **server-side** session died (cookie is still valid for 15 days) — another login for the same account, or a restart | Automatic: the client re-authenticates once and replays |
| `CERTIFICATE_VERIFY_FAILED` | Self-signed controller cert, IP/SAN mismatch, or Python 3.13+ strict X509 | Set `OMADA_CA_BUNDLE` to the controller CA, `OMADA_STRICT_X509=false`, and `OMADA_TLS_SERVER_NAME=Omada` when connecting by IP; `OMADA_VERIFY_SSL=false` only as a last resort |
| `cannot reach …` | Wrong port or unroutable network | Controller web UI is `https://host:8043` (or `http://host:8088`) |
| Host starts but every call fails | No credentials at server start | Expected: `initialize`/`tools/list` never touch the controller; run `--doctor` |
| Windows: timeouts although the controller pings | WinINET proxy inherited by `urllib` | Proxies are off by default; if you need one, `OMADA_USE_SYSTEM_PROXY=true` |
| Windows: `omada-mcp` not found after `pip install --user` | `%APPDATA%\Python\Python3x\Scripts` not on `PATH` | Use `uvx`/`uv tool install`, or add the Scripts directory to `PATH` |

## Compatibility

See [`docs/compatibility.md`](docs/compatibility.md) for the full compatibility table.

* **Software controller v6.x** — read-only path (`--doctor --json` and read tools)
  verified live on v6.2.10.17 (`TPOMADA_SESSIONID`), and all 20 read-only tools plus
  controller-native write CRUD (`create/update/delete_lan_network`,
  `set_vlan_dhcp_pools`, `upsert/delete_dhcp_reservation`, `create/replace/delete_ip_group`,
  `create/update/set_acl_rule_status/delete_gateway_acl` including the 6-step swap,
  `create/update/delete_ssid` with PSK redaction, `upsert/delete_port_forward`,
  `upsert/delete_static_route`, `upsert/delete_mdns_rule`, `set_upnp` dry-run,
  `-33598` on hardwareless isolation, Viewer `-1007 -> insight/clients` fallback,
  and `-41011`/not-found probes) verified live against an isolated Docker Omada
  Controller v6.2.14.11; client fixed-IP lease-delayed behavior (`set_client_fixed_ip`/
  `release_client_fixed_ip`), client actions, and device controls (`update_device`,
  `reboot_device`) are covered by the stateful mock controller.
* **Software controller v5.x** — expected (v5.13.30.8 core auth/list shapes
  supported; awaiting a `--doctor --json` capture via the issue template).
* **OC200 / OC300 hardware & `TPEAP_SESSIONID` builds** — expected (`--doctor`
  detects both `TPOMADA_SESSIONID` and `TPEAP_SESSIONID`, handles legacy
  `result.omadacId` login shapes, and reports `hardware-5.x` / `hardware-6.x`).
  Run `omada-mcp --doctor --json` and submit a
  [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml).

## Development

```bash
git clone https://github.com/falehsub/omada-mcp && cd omada-mcp
python -m unittest discover -s tests -v     # 127 tests, no network, no deps
python -m omada_mcp.cli --help              # after: pip install -e .
uvx --from . omada-mcp --doctor             # what an external user does

# uv caches the build of a local *path* and does not rebuild when the source
# changes (`--refresh` does not help). Force a fresh environment while iterating:
UV_CACHE_DIR=$(mktemp -d) uvx --from . omada-mcp --doctor
```

Layout:

```
src/omada_mcp/config.py         dotenv discovery, validation, base-URL normalisation, write allowlist
src/omada_mcp/client.py         Web API v2 client: auth, pagination, write gate, snapshots/audit, errors
src/omada_mcp/tools.py          20 read-only tools + 31 write descriptors, projections, outputSchema
src/omada_mcp/write_tools.py    read-modify-write handlers, CIDR packer, anti-stranding, 6-step swap
src/omada_mcp/server.py         JSON-RPC stdio server, fail-closed gates, strict arg/bool checks
src/omada_mcp/doctor.py         6-phase self-test (env, tls, login, site, tools, write) with --json
schemas/doctor.schema.json      JSON Schema for --doctor --json
docs/compatibility.md           controller family and cookie compatibility matrix
docs/write-support.md           write-support contract, verified endpoints, and controller traps
tests/mock_controller.py        stateful Web API v2 mock controller with fault injection
tests/test_bridge.py            read-only bridge + protocol tests (stdlib unittest)
tests/test_write_support.py     write-gate, RMW flows, anti-stranding, and fault-injection tests
skills/omada-controller/        agent skill: field notes for the Omada API itself
```

The API notes in [`skills/omada-controller/SKILL.md`](skills/omada-controller/SKILL.md)
document the parts of the controller that are not in any public reference:
session expiry semantics, CIDR packing limits, dual-pool DHCP bodies, and the
endpoints that are Admin-only.

## Write support

Read-only mode remains the default (`OMADA_WRITE_TOOLS` defaults empty and write
tools are hidden). Opt-in writes follow the contract in
[`docs/write-support.md`](docs/write-support.md) — explicit `OMADA_WRITE_TOOLS`
allowlist, `dryRun=true` default, `confirm="<tool>:<target-id>"`, pre-write snapshots +
`audit.jsonl`, whole-object verification, and anti-stranding checks. Use a **dedicated
Admin local account** separate from your read bridge and web UI to avoid session
eviction. Firmware upgrades remain unshipped pending a maintenance-window policy.

## Roadmap

Core read-only access, `--doctor --json`, error decoding, `network_audit`, `search_clients`,
and the expanded 51-tool read/write control surface are implemented on `main`. Next items
in [ROADMAP.md](ROADMAP.md) include MCP Registry `server.json` / PyPI publishing and v1.3
operational tooling.

## License

MIT — see [LICENSE](LICENSE).

Not affiliated with TP-Link. Omada is a trademark of TP-Link Technologies.
This server calls an undocumented internal API; a controller firmware update can
change it, which is exactly why `--doctor` exists.
