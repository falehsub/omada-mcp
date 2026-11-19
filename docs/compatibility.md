# Controller Compatibility Matrix

`omada-mcp` speaks the controller's internal **Web API v2** (`/{omadacId}/api/v2/...`) rather than the OAuth2 Open API. Because TP-Link does not publish a cross-version schema for the Web API, compatibility is tracked by controller family and exact `controllerVer`.

## Verified Controllers

| Controller Family | `controllerVer` | Session Cookie | Status | Notes |
|---|---|---|---|---|
| `software-5.x` | `5.15.24.19` | `TPOMADA_SESSIONID` | Verified live (Docker lab) | `v2.4.1` (`54` read-only + `78` opt-in write = `132` tools): CI Docker compat passed `--doctor --json --share-safe`, `read_selftest.py` (44 passed, 0 failed, 10 skipped for absent adopted hardware/cross-site), and `qualify_client_queries.py` (12/12) for both Viewer and Admin with CA pinning. |
| `software-6.x` | `6.2.10.17` / `6.3.0.45` | `TPOMADA_SESSIONID` | Verified live | `--doctor --json`, `v2.0.0` 35-tool read-only surface (`list_wlans` expands WLAN groups to SSIDs, `network_audit`, `explain_error`, `diagnose_client` roaming, `diff_config_snapshots`), PSK redaction, `OMADA_READ_ONLY=true`, and CA-pinned `OMADA_TLS_SERVER_NAME=Omada` verified. |
| `software-6.x` | `6.2.14.11` | `TPOMADA_SESSIONID` | Verified live (Docker lab) | `v2.3.0`–`v2.4.1`: `read_selftest.py` passed 44 site/global read tools (0 failed, 10 skipped for absent physical hardware/cross-site) plus `qualify_client_queries.py` (12/12) in CI Docker compat for Viewer and Admin, alongside `v2.3.0` live `audit_all_sites`, WireGuard/Hotspot/backup/gateway/VLAN/ACL/SSID/routing/mDNS/UPnP E2E checks. |

## Expected / Community-Reportable Builds

| Controller Family | Target `controllerVer` / Models | Expected Cookie | Known Shape Differences | What to Report |
|---|---|---|---|---|
| `software-5.x` | `5.13.30.8` (other 5.x builds) | `TPOMADA_SESSIONID` | Core Web API v2 auth, `sites`, `devices`, `insight/clients`, and `setting/wlans` shapes implemented; legacy integer `privilege` and v5 `sourceFilter`/`destinationFilter`/`protocol` shapes covered in offline tests (`5.15.24.19` verified in [the compat CI workflow](../.github/workflows/compat.yml)). | Share `omada-mcp --doctor --json --share-safe` output for other 5.x builds. |
| `hardware-5.x` | OC200 / OC300 (v5.x) | `TPOMADA_SESSIONID` or `TPEAP_SESSIONID` | Older v5.x builds may issue `TPEAP_SESSIONID`, return `result.omadacId` in `/api/v2/login`, or wrap `devices` in `result.data`. All three are handled and covered against synthetic/fixture shapes in unit tests; awaiting direct live hardware capture. | Submit a share-safe report through the [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml) template. |
| `hardware-6.x` | OC200 / OC300 / OC400 (v6.x) | `TPOMADA_SESSIONID` | Same Web API v2 family as `software-6.x`; `setting/wlans/{groupId}/ssids` expansion and `roleName` privilege shape supported; anonymized `ER7206 v2.20`, `ES220GMP v1.0`, and `EAP725-Wall(EU) v1.0` payloads verified in `tests/fixtures/` and `MockController`. | Submit a share-safe report through the [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml) template. |

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

### Operator-reported live home-network verification (`v2.5.0`–`v2.5.3`, 2026-11-19)

The [2026-11-19 Hermes live validation record](live-validation-2026-11-19.md) documents verification across `v2.5.0`–`v2.5.3` on software controller `6.3.0.45` with adopted `EAP725-Wall` APs (`55` read-only + `80` opt-in write = `135` tools): `get_ssid`, `list_wlans` steering fields, `loadBalance`/`condBroadcastCtrl` `{"enable": false}` dict shapes, `set_wifi_radio_features` dry-run, `diff_config_snapshots`, `delete_ip_group(id=...)` schema alias, `get_rf_scan` (`chanWidthLabel` `2`/`3`/`5`/`7` -> `20MHz`/`40MHz`/`80MHz`/`160MHz` on `34` `5g` occupancy rows), and `survey_wifi` decoupled trigger verification + one-shot `360s` completion (`230–265s` measured on `EAP725-Wall`).

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
omada-mcp --doctor --json --share-safe
```

The share-safe JSON includes `"shareSafe": true`, controller firmware and family when recognized, the session cookie name, and phase statuses with generic troubleshooting hints. It omits account and site identities, controller URL and ID, local paths, and raw controller errors. Run `omada-mcp --doctor` locally for detailed troubleshooting. Open an issue with the [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml) form to add your build to the verified table.
