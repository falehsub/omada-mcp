# Controller Compatibility Matrix

`omada-mcp` speaks the controller's internal **Web API v2** (`/{omadacId}/api/v2/...`) rather than the OAuth2 Open API. Because TP-Link does not publish a cross-version schema for the Web API, compatibility is tracked by controller family and exact `controllerVer`.

## Verified Controllers

| Controller Family | `controllerVer` | Session Cookie | Status | Notes |
|---|---|---|---|---|
| `software-6.x` | `6.2.10.17` | `TPOMADA_SESSIONID` | Verified live | `--doctor --json`, all 33 read-only tools (`list_wlans` expands WLAN groups to SSIDs, `network_audit`, `explain_error`, diagnostics), PSK redaction, `OMADA_READ_ONLY=true`, and CA-pinned `OMADA_TLS_SERVER_NAME=Omada` verified. |
| `software-6.x` | `6.2.14.11` | `TPOMADA_SESSIONID` | Verified live (Docker lab) | `--doctor --json`, 20 baseline read-only tools + live probes for diagnostics, `get_config_snapshot` (11 object types), and controller-native write CRUD (`create/update/delete_lan_network` including `ipaddrStart`/`ipaddrEnd` pools, `set_vlan_dhcp_pools`, `upsert/delete_dhcp_reservation`, `create/replace/delete_ip_group`, `create/update/set_acl_rule_status/delete_gateway_acl` + 6-step swap, `create_switch_acl`/`create_eap_acl` + typed toggle/update/delete lifecycle, `upsert/delete_port_profile` with `profileIds` array delete, `create/update/delete_ssid` with PSK redaction, `upsert/delete_port_forward`, `upsert/delete_static_route`, `upsert/delete_mdns_rule`, `set_upnp` dry-run + live disable + `-33001` gateway check, `-33598` on hardwareless isolation, `-41011`/not-found probes). The full 80-tool surface (33 read-only diagnostics + 47 opt-in writes including switch/AP/routing/DNS/client controls and `rollback_from_snapshot`), missing-hardware fallback paths (`hasGateway=false`, absent WIDS/IPS, `topology-v2` -> `/devices`), and `--watch`/`--export-metrics` modes are verified across anonymized fixtures and `MockController`. |

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

[`scripts/capture_fixtures.py`](../scripts/capture_fixtures.py) enforces GET-only HTTP requests (aside from `/api/v2/login`), scrubs MACs, IPs, CIDRs, IPv6 prefixes, `omadacId`/`site` IDs, serial numbers, SSIDs, hostnames, emails, tokens, and cookies via [`scripts/anonymize_capture.py`](../scripts/anonymize_capture.py), and verifies with `--verify-clean --strict-private` before writing output. Existing anonymized hardware fixtures under `tests/fixtures/` (`ER7206 v2.20`, `ES220GMP v1.0`, `EAP725-Wall(EU) v1.0`) exercise all 33 read tools (0 skipped on `MockController`) and all hardware-gated write dry-runs/confirmations.

## Reporting a New Controller Build

### Latest local read-only sweep (2026-11-14)

On Docker software controller `6.2.14.11`, the explicit-config live sweep passed
27 read-only tools for both Viewer and Admin accounts. Six device/client-specific
tools were skipped because no hardware or clients were adopted. All six doctor
phases passed with CA/SAN verification. Additional checks covered all 11 snapshot
sections, typed ACL reads, logs, session expiry via HTTP 302, metrics and watch.
Writes remained disabled; write flows were exercised with the stateful mock.

See [the full review](review-2026-11-14.md) for limitations and reproduction steps.

```bash
python scripts/read_selftest.py --env-file /path/to/isolated/viewer.env
```

### Submitting a report

Run:

```bash
omada-mcp --doctor --json
```

The JSON output strips your password, session token, and local `.env` filesystem paths (replacing them with origin labels like `OMADA_ENV_FILE`, `cwd`, `appdata`, `xdg`, or `environment`) while keeping `controller.controllerVer`, `controller.family`, and `controller.sessionCookie`. Open an issue with the [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml) form to add your build to the verified table.
