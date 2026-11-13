# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Read-only configuration snapshot (`get_config_snapshot`)**: Brings the
  always-available read-only surface to 11 tools, merging both LAN endpoints
  (`setting/lan/networks` and `setting/lan/networks/interface`), gateway ACLs
  (explicitly flagging `aclDisable` as non-authoritative), IP/port groups,
  PSK-redacted WLANs, projected devices, and optional clients.
- **Opt-in write tools (`src/omada_mcp/write_tools.py`)**: Added the 8 allowlistable
  write tools specified in [`docs/write-support.md`](docs/write-support.md):
  - `set_client_fixed_ip`, `release_client_fixed_ip` (strips 20 volatile client keys,
    enforces mandatory `ipSetting.netId`, warns about lease delay and device-MAC `-41011`).
  - `set_vlan_isolation`, `set_vlan_dhcp_pools` (two-endpoint LAN read-modify-write,
    auto-populates `lanNetworkIpv6Config.proto` when omitted, checks whole-object integrity
    and `dhcpSettings.ipRangePool` without trusting stale `ipRangeStart`/`ipRangeEnd` mirrors).
  - `create_ip_group`, `replace_ip_group` (`<=16`-entry aligned CIDR packing preventing
    `-33726`, typed delete `/{type}/{id}`, and automatic 6-step temporary-group swap when
    ACL rules reference the group to prevent `-33717`).
  - `create_gateway_acl`, `set_acl_rule_status` (single-rule enforcement without touching
    or trusting `aclDisable`).
- **Fail-closed safety controls & configuration (`config.py`, `client.py`, `server.py`)**:
  - `OMADA_WRITE_TOOLS` explicit allowlist (rejects wildcards/`all`/read-only names),
    `OMADA_SNAPSHOT_DIR` (POSIX `0o700`/`0o600` pre-write snapshots + `audit.jsonl`),
    `OMADA_WRITE_INTERVAL_SECONDS` (default `1.0` s serialized write pacing), and
    `OMADA_MANAGEMENT_CIDRS` anti-stranding protection.
  - Every write tool defaults to `dryRun=true` (returning a diff and `confirmToken`);
    applying requires `dryRun=false` with `confirm="<tool>:<target-id>"`, strict JSON
    schema argument validation, no write auto-retry on `-1600`, and safe `reauth_prepare`
    state re-read on HTTP 200 HTML expiry.
- **Diagnostics & CLI (`doctor.py`, `cli.py`, `schemas/doctor.schema.json`)**:
  - Added read-only `write` phase to `omada-mcp --doctor` (validates write allowlist,
    warns on `Viewer` role `-41011`, advises dedicated Admin account to prevent session
    eviction, and redacts `snapshotDir` paths under `--doctor --json`).
  - `--list-tools` exposes only active tools (`11` by default); added `--list-tools --all`
    to inspect all `19` descriptors offline.
- **Offline mock controller & test suite (`tests/mock_controller.py`, `tests/fixtures/`,
  `tests/test_write_support.py`)**: Added 27 mock-controller & fault-injection tests
  alongside the 87 bridge tests (114 tests total).

### Kept unshipped

- Device rename/LED, device reboot, firmware upgrade, SSID create/delete, ACL global toggle
  (`aclDisable`), and `/controller/setting` remain unshipped pending a maintenance-window
  policy and controller verification.

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
