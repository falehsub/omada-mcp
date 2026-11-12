# omada-mcp

**A Model Context Protocol server for TP-Link Omada SDN controllers — zero dependencies, read-only by default, and honest about every failure.**

[![CI](https://github.com/falehsub/omada-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/falehsub/omada-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](pyproject.toml)

Your Omada controller already knows which AP is overloaded, which client is
sitting on the guest VLAN, and which switch dropped a port. `omada-mcp` hands
that to Claude, Cursor, Hermes or any other MCP host — as eight read-only tools
that return clean JSON, with a self-test that tells you exactly what to fix when
something is wrong.

```
uvx omada-mcp --doctor
```

```
omada-mcp doctor v1.0.1
------------------------------------------------------------------
PASS env      /home/you/.config/omada-mcp/.env | url=https://192.0.2.10:8043 user=omada-readonly password=set (24 chars)
PASS tls      verified against /home/you/.config/omada-mcp/controller-ca.pem | reachable, omadacId=0123456789abcdef01234567, controllerVer=5.13.30.8
PASS login    token accepted for omada-readonly (role=Viewer, scope=all sites), Csrf-Token round-trip OK
PASS site     Home (89abcdef0123456789abcdef) site 1 of 1; matched OMADA_SITE_NAME=Home
PASS tools    list_devices -> 7 device(s); 8 read-only tools registered, 23 client(s)
------------------------------------------------------------------
5/5 checks passed
Ready: `omada-mcp` will serve 8 read-only tools on stdio.
```

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
| `OMADA_USERNAME` | — **required** | Local controller account. `Viewer` is sufficient. |
| `OMADA_PASSWORD` | — **required** | Never printed, never logged. |
| `OMADA_SITE_NAME` | first site | Display name, e.g. `Home`. |
| `OMADA_SITE_ID` | first site | Hex id **or** name — names are resolved, because the controller only accepts the hex id in URLs (that mismatch is exactly what `-1505` reports). |
| `OMADA_CA_BUNDLE` | system store | PEM bundle with the controller's CA. |
| `OMADA_VERIFY_SSL` | `true` | `false` disables chain + hostname checks. Not for production. |
| `OMADA_STRICT_X509` | `true` | `false` clears Python 3.13+'s `VERIFY_X509_STRICT` while keeping chain and hostname checks — the fix for "self-signed certificate" errors on 3.13/3.14. |
| `OMADA_READ_ONLY` | `false` | `true` refuses every non-read-only tool (`-32003`). |
| `OMADA_USE_SYSTEM_PROXY` | `false` | System/registry proxies are ignored by default. On Windows, `urllib` inherits the WinINET proxy, which makes a one-hop controller look unreachable; set `true` only when a proxy is genuinely required. |
| `OMADA_TIMEOUT_SECONDS` | `30` | Per-request timeout. |
| `OMADA_MIN_INTERVAL_SECONDS` | `0.25` | Minimum spacing between controller calls; raise to `0.8` on large sites. |

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

Eight tools, all read-only, all idempotent, all returning JSON. `list_clients`
windowing is bounded by `limit` (default 500, max 5000) and de-duplicated by MAC.

| Tool | Arguments | Returns |
|---|---|---|
| `get_site_info` | — | Site name/id, WAN/LAN/WLAN state, device and client counts, controller version |
| `list_devices` | — | MAC, name, type, model, firmware, IP, uptime, client count, status |
| `list_clients` | `limit?` | MAC, name, hostname, IP, wireless, guest, SSID, AP, network, VLAN, rx/tx, duration, last seen (UTC ISO-8601) |
| `list_wifi_clients` | `limit?` | Same projection, wireless only |
| `list_wired_clients` | `limit?` | Same projection, wired only |
| `get_device` | `mac` (or name) | One device |
| `get_client` | `mac` (or hostname/IP) | One client |
| `list_wlans` | — | SSID, band, VLAN, security, guest, `hasPresharedKey` (key never returned) |

Each entry in `tools/list` carries MCP annotations, so hosts can auto-approve
reads instead of prompting on every call:

```json
{
  "name": "list_devices",
  "title": "List Omada devices",
  "annotations": {
    "title": "List Omada devices",
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "openWorldHint": true
  }
}
```

`omada-mcp --list-tools` prints every descriptor without touching the network.

## Safety model

| Control | Behaviour |
|---|---|
| `OMADA_READ_ONLY=true` | Refuses any tool not declared read-only, before lookup (`-32003`, fails closed). |
| Credential handling | Password only ever rendered as `set (N chars)`; tokens never logged; stdout is reserved for JSON-RPC, diagnostics go to stderr. |
| Secret redaction | `list_wlans` omits `securityKey`; only `hasPresharedKey` is exposed. |
| Session recovery | A 200 response containing the web UI shell produces **one** re-login and a replay; a second failure raises instead of looping. |
| Pacing | Calls spaced by `OMADA_MIN_INTERVAL_SECONDS`; a burst `-1600` is retried once after 0.8 s. |
| Dotenv hygiene | `--doctor` warns when the dotenv file is readable by group/other and tells you the `chmod`. |

## Troubleshooting

Run `omada-mcp --doctor` first — it names the failing phase and the fix. The
table below maps the symptoms it cannot see.

| Symptom | Cause | Fix |
|---|---|---|
| `-1505` on a site call | Site **name** used where the hex site id is required | Set `OMADA_SITE_NAME` (or `OMADA_SITE_ID`) and let the server resolve it |
| `-1600` everywhere | Wrong path shape **or** burst rate-limiting (the controller reuses one code) | Check the endpoint, and pace: the client already retries once after 0.8 s; raise `OMADA_MIN_INTERVAL_SECONDS` |
| `-33726` on an IP group write | The group holds at most **16** entries | Store ranges as network-aligned CIDRs; one `/32` per host overflows immediately |
| `-1001` "bean validation" | A mandatory field missing from a PATCH body — for LAN networks it is `lanNetworkIpv6Config.proto: "none"` | Send the whole object, not a partial patch |
| `-41011` | Client endpoints are **Admin-only** and the MAC is not in that site's client table | Use `insight/clients` with a Viewer account |
| `-44116` | You are on the Open API without Platform Integration | Use this server (Web API) instead |
| HTTP 200 with HTML in response | The controller's **server-side** session died (cookie is still valid for 15 days) — another login for the same account, or a restart | Automatic: the client re-authenticates once and replays |
| `CERTIFICATE_VERIFY_FAILED` | Self-signed controller cert, or Python 3.13+ strict X509 | Set `OMADA_CA_BUNDLE` to the controller CA; else `OMADA_STRICT_X509=false`; `OMADA_VERIFY_SSL=false` only as a last resort |
| `cannot reach …` | Wrong port or unroutable network | Controller web UI is `https://host:8043` (or `http://host:8088`) |
| Host starts but every call fails | No credentials at server start | Expected: `initialize`/`tools/list` never touch the controller; run `--doctor` |
| Windows: timeouts although the controller pings | WinINET proxy inherited by `urllib` | Proxies are off by default; if you need one, `OMADA_USE_SYSTEM_PROXY=true` |
| Windows: `omada-mcp` not found after `pip install --user` | `%APPDATA%\Python\Python3x\Scripts` not on `PATH` | Use `uvx`/`uv tool install`, or add the Scripts directory to `PATH` |

## Compatibility

* **Software controller v6.x** — verified live: `--doctor` and all eight read
  tools return data on v6.2.10.17.
* **Software controller v5.x** — same Web API family; the field notes in
  `skills/omada-controller/SKILL.md` include the v5.x session-cookie behaviour.
  Report your `controllerVer` if a tool answers `-1600`.
* **OC200 / OC300 hardware** — same Web API family; site and device reads are
  expected to work. Please open an issue with your `controllerVer` if a tool
  returns `-1600`.
* **Omada v5.x `TPEAP_SESSIONID` builds** — some older builds issue
  `TPEAP_SESSIONID` instead of `TPOMADA_SESSIONID`. The cookie jar replays
  whatever the controller sets, so login generally succeeds; if it does not, the
  error will name the phase. See the roadmap below.

## Development

```bash
git clone https://github.com/falehsub/omada-mcp && cd omada-mcp
python -m unittest discover -s tests -v     # 59 tests, no network, no deps
python -m omada_mcp.cli --help              # after: pip install -e .
uvx --from . omada-mcp --doctor             # what an external user does

# uv caches the build of a local *path* and does not rebuild when the source
# changes (`--refresh` does not help). Force a fresh environment while iterating:
UV_CACHE_DIR=$(mktemp -d) uvx --from . omada-mcp --doctor
```

Layout:

```
src/omada_mcp/config.py   dotenv discovery, validation, base-URL normalisation
src/omada_mcp/client.py   Web API v2 client: auth, pacing, session recovery, errors
src/omada_mcp/tools.py    8 read-only tools, field whitelists, MCP annotations
src/omada_mcp/server.py   JSON-RPC stdio server, read-only gate, lazy auth
src/omada_mcp/doctor.py   ordered self-test with fix hints
tests/test_bridge.py      fake controller + protocol tests (stdlib unittest)
skills/omada-controller/  agent skill: field notes for the Omada API itself
```

The API notes in [`skills/omada-controller/SKILL.md`](skills/omada-controller/SKILL.md)
document the parts of the controller that are not in any public reference:
session expiry semantics, CIDR packing limits, dual-pool DHCP bodies, and the
endpoints that are Admin-only.

## Roadmap

v1.0 is deliberately read-only. The next releases, in priority order, are listed
in [ROADMAP.md](ROADMAP.md) — OC200/v5 session-cookie support, an error-code
decoder, a composite `network_audit` tool, write tools behind an explicit
opt-in, and an MCP Registry `server.json`.

## License

MIT — see [LICENSE](LICENSE).

Not affiliated with TP-Link. Omada is a trademark of TP-Link Technologies.
This server calls an undocumented internal API; a controller firmware update can
change it, which is exactly why `--doctor` exists.
