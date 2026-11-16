# Controller Compatibility Matrix

`omada-mcp` speaks the controller's internal **Web API v2** (`/{omadacId}/api/v2/...`) rather than the OAuth2 Open API. Because TP-Link does not publish a cross-version schema for the Web API, compatibility is tracked by controller family and exact `controllerVer`.

## Verified Controllers

| Controller Family | `controllerVer` | Session Cookie | Status | Notes |
|---|---|---|---|---|
| `software-6.x` | `6.2.10.17` / `6.3.0.45` | `TPOMADA_SESSIONID` | Verified live | `--doctor --json`, `v2.0.0` 35-tool read-only surface (`list_wlans` expands WLAN groups to SSIDs, `network_audit`, `explain_error`, `diagnose_client` roaming, `diff_config_snapshots`), PSK redaction, `OMADA_READ_ONLY=true`, and CA-pinned `OMADA_TLS_SERVER_NAME=Omada` verified. |
| `software-6.x` | `6.2.14.11` | `TPOMADA_SESSIONID` | Verified live (Docker lab) | `v2.3.0` (`54` read-only + `78` opt-in write = `132` tools): `read_selftest.py` passed 44 site/global read tools (10 skipped due to zero adopted physical hardware and default `OMADA_ALLOW_CROSS_SITE=false`), plus live `audit_all_sites`, WireGuard tunnel/peer CRUD (`upsert_wireguard_tunnel` with plain `localIp` validation & ephemeral `/setting/wireguard/key`, `upsert_wireguard_peer`, `delete_wireguard_tunnel` attached-peer guard, `delete_wireguard_peer`), Hotspot voucher group create/revoke (`create_hotspot_vouchers`, `revoke_hotspot_voucher`), bounded binary backup export (`export_controller_backup`), and zero-drift `diff_config_snapshots`, alongside full gateway/VLAN/ACL/SSID/routing/mDNS/UPnP CRUD (`set_vlan_dhcp_pools`, `create/replace/delete_ip_group`, 6-step ACL swap, `upsert/delete_port_profile`). Full hardware-dependent paths are covered across 250 tests using anonymized fixtures and `MockController`. |

## Expected / Community-Reportable Builds

| Controller Family | Target `controllerVer` / Models | Expected Cookie | Known Shape Differences | What to Report |
|---|---|---|---|---|
| `software-5.x` | `5.13.30.8` / `5.15.24.19` | `TPOMADA_SESSIONID` | Core Web API v2 auth, `sites`, `devices`, `insight/clients`, and `setting/wlans` shapes implemented; legacy integer `privilege` and v5 `sourceFilter`/`destinationFilter`/`protocol` shapes covered in offline tests; `5.15.24.19` is configured in [the compat CI workflow](../.github/workflows/compat.yml) (scheduled/manual, awaiting first CI artifact run). | Run `omada-mcp --doctor --json` and attach CI/local summary if testing another 5.x build. |
| `hardware-5.x` | OC200 / OC300 (v5.x) | `TPOMADA_SESSIONID` or `TPEAP_SESSIONID` | Older v5.x builds may issue `TPEAP_SESSIONID`, return `result.omadacId` in `/api/v2/login`, or wrap `devices` in `result.data`. All three are handled and covered against synthetic/fixture shapes in unit tests; awaiting direct live hardware capture. | Run `omada-mcp --doctor --json` and submit via the [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml) template. |
| `hardware-6.x` | OC200 / OC300 / OC400 (v6.x) | `TPOMADA_SESSIONID` | Same Web API v2 family as `software-6.x`; `setting/wlans/{groupId}/ssids` expansion and `roleName` privilege shape supported; anonymized `ER7206 v2.20`, `ES220GMP v1.0`, and `EAP725-Wall(EU) v1.0` payloads verified in `tests/fixtures/` and `MockController`. | Run `omada-mcp --doctor --json` and submit via the [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml) template. |

## Automated Compatibility CI & Fixture Captures

### Disposable Docker Matrix (`.github/workflows/compat.yml`)

[`.github/workflows/compat.yml`](../.github/workflows/compat.yml) defines a weekly (`cron`), manual (`workflow_dispatch`), and `compat`-labeled PR workflow that boots disposable `mbentley/omada-controller` containers (`5.15.24.19` and `6.2.14.11`), bootstraps a throwaway lab site with dedicated **Viewer** and **Admin** accounts plus leaf-CA pinning via [`scripts/docker_lab_init.py`](../scripts/docker_lab_init.py), runs `omada-mcp --doctor --json` and [`scripts/read_selftest.py`](../scripts/read_selftest.py) for both accounts, and uploads payload-free JSON status reports as CI artifacts.

### Capturing & Anonymizing Hardware Fixtures

Maintainers and contributors testing real adopted switches, gateways, or APs can produce shareable anonymized test bundles with zero writes using:

```bash
python scripts/capture_fixtures.py --env-file /path/to/isolated.env -o capture.json
python scripts/anonymize_capture.py capture.json --verify-clean --strict-private
```

[`scripts/capture_fixtures.py`](../scripts/capture_fixtures.py) enforces GET-only HTTP requests (aside from `/api/v2/login`), scrubs MACs, IPs, CIDRs, IPv6 prefixes, `omadacId`/`site` IDs, serial numbers, SSIDs, hostnames, emails, tokens, and cookies via [`scripts/anonymize_capture.py`](../scripts/anonymize_capture.py), and verifies with `--verify-clean --strict-private` before writing output. Existing anonymized hardware fixtures under `tests/fixtures/` (`ER7206 v2.20`, `ES220GMP v1.0`, `EAP725-Wall(EU) v1.0`) exercise all 54 read tools (0 skipped on `MockController`) and all 78 write dry-runs/confirmations.

## Reporting a New Controller Build

### Operator-reported live home-network verification (`v2.3.0`, 2026-11-16)

The [dated Hermes validation record](live-validation-2026-11-16.md) documents a
`2.0.0` to `2.3.0` MCP upgrade against software controller `6.3.0.45` with four
adopted devices. Hermes reported 13 baseline checks passed, a single authorized
`create_ip_group` / `delete_ip_group` cycle with verified cleanup, and no drift in
the compared `networks`, `acls`, `groups` and `wlans` snapshot sections. Follow-up
verification resolved a cached supervisor environment and confirmed the running
read-only configuration, a 54-read/zero-write catalog, and fail-closed `-32003`
responses. The record distinguishes helper-process catalog checks from direct
running-process inspection and preserves the limits of this operator-reported
evidence. It does not validate all read/write tools or authorize future live writes.

### Latest local Docker verification (`v2.3.0`, 2026-11-15)

On isolated Docker software controller `6.2.14.11` (`viewer.env` and
`writer_e2e.env`), `scripts/read_selftest.py` passed 44 read-only tools (`0`
failed, `10` skipped for absent adopted hardware and default
`OMADA_ALLOW_CROSS_SITE=false`). Live E2E write/cleanup verification also passed
`audit_all_sites`, `upsert_wireguard_tunnel`, `upsert_wireguard_peer`,
`delete_wireguard_tunnel` peer ref-guard, `delete_wireguard_peer`,
`create_hotspot_vouchers`, `revoke_hotspot_voucher`, `export_controller_backup`,
and post-cleanup `diff_config_snapshots` (`hasChanges=false`). Earlier `2.0.0`
read-only verification also passed 35/35 tools against live `6.3.0.45`.

See [the earlier 2026-11-14 review](review-2026-11-14.md) for historical notes.

```bash
python scripts/read_selftest.py --env-file /path/to/isolated/viewer.env
```

### Submitting a report

Run:

```bash
omada-mcp --doctor --json
```

The JSON output strips your password, session token, and local `.env` filesystem paths (replacing them with origin labels like `OMADA_ENV_FILE`, `cwd`, `appdata`, `xdg`, or `environment`) while keeping `controller.controllerVer`, `controller.family`, and `controller.sessionCookie`. Open an issue with the [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml) form to add your build to the verified table.
