# Controller Compatibility Matrix

`omada-mcp` speaks the controller's internal **Web API v2** (`/{omadacId}/api/v2/...`) rather than the OAuth2 Open API. Because TP-Link does not publish a cross-version schema for the Web API, compatibility is tracked by controller family and exact `controllerVer`.

## Verified Controllers

| Controller Family | `controllerVer` | Session Cookie | Status | Notes |
|---|---|---|---|---|
| `software-6.x` | `6.2.10.17` | `TPOMADA_SESSIONID` | Verified live | `--doctor --json`, read-only inspection (`list_wlans` expands WLAN groups to SSIDs, `network_audit`, `explain_error`), PSK redaction, `OMADA_READ_ONLY=true`, and CA-pinned `OMADA_TLS_SERVER_NAME=Omada` verified. |
| `software-6.x` | `6.2.14.11` | `TPOMADA_SESSIONID` | Verified live (Docker lab) | `--doctor --json`, all 20 read-only tools (incl. `search_clients` Viewer `-1007 -> insight/clients` fallback, `list_lan_networks`, `list_logs`, `get_network_services`), `get_config_snapshot` (11 object types), and controller-native write CRUD (`create/update/delete_lan_network`, `set_vlan_dhcp_pools`, `upsert/delete_dhcp_reservation`, `create/replace/delete_ip_group`, `create/update/set_acl_rule_status/delete_gateway_acl` + 6-step swap, `create/update/delete_ssid` with PSK redaction, `upsert/delete_port_forward`, `upsert/delete_static_route`, `upsert/delete_mdns_rule`, `set_upnp` dry-run, `-33598` on hardwareless isolation, `-41011`/not-found probes). Device/client ops (`update_device`, `reboot_device`, `set_client_*`, `update_client`, `reconnect_client`) covered by stateful mock controller. |

## Expected / Community-Reportable Builds

| Controller Family | Target `controllerVer` / Models | Expected Cookie | Known Shape Differences | What to Report |
|---|---|---|---|---|
| `software-5.x` | `5.13.30.8` / Software Controller 5.x | `TPOMADA_SESSIONID` | Core Web API v2 auth, `sites`, `devices`, `insight/clients`, and `setting/wlans` shapes implemented; legacy integer `privilege` shape supported. | Expected (awaiting reproducible `--doctor --json` capture). |
| `hardware-5.x` | OC200 / OC300 (v5.x) | `TPOMADA_SESSIONID` or `TPEAP_SESSIONID` | Older v5.x builds may issue `TPEAP_SESSIONID`, return `result.omadacId` in `/api/v2/login`, or wrap `devices` in `result.data`. All three are handled automatically. | Run `omada-mcp --doctor --json` and submit via the [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml) template. |
| `hardware-6.x` | OC200 / OC300 / OC400 (v6.x) | `TPOMADA_SESSIONID` | Same Web API v2 family as `software-6.x`; `setting/wlans/{groupId}/ssids` expansion and `roleName` privilege shape supported. | Run `omada-mcp --doctor --json` and submit via the [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml) template. |

## Reporting a New Controller Build

Run:

```bash
omada-mcp --doctor --json
```

The JSON output strips your password, session token, and local `.env` filesystem paths (replacing them with origin labels like `OMADA_ENV_FILE`, `cwd`, `appdata`, `xdg`, or `environment`) while keeping `controller.controllerVer`, `controller.family`, and `controller.sessionCookie`. Open an issue with the [Controller Compatibility Report](https://github.com/falehsub/omada-mcp/issues/new?template=controller-report.yml) form to add your build to the verified table.
