# Controller Compatibility Matrix

`omada-mcp` speaks the controller's internal **Web API v2** (`/{omadacId}/api/v2/...`) rather than the OAuth2 Open API. Because TP-Link does not publish a cross-version schema for the Web API, compatibility is tracked by controller family and exact `controllerVer`.

## Verified Controllers

| Controller Family | `controllerVer` | Session Cookie | Status | Notes |
|---|---|---|---|---|
| `software-6.x` | `6.2.10.17` | `TPOMADA_SESSIONID` | Verified live | `--doctor --json`, all 10 read-only tools (`list_wlans` expands WLAN groups to SSIDs, `network_audit`, `explain_error`), PSK redaction, `OMADA_READ_ONLY=true`, and CA-pinned `OMADA_TLS_SERVER_NAME=Omada` verified. |
| `software-5.x` | `5.13.30.8` | `TPOMADA_SESSIONID` | Verified live (v1.0) | Core Web API v2 auth, `sites`, `devices`, `insight/clients`, and `setting/wlans` verified; legacy integer `privilege` shape supported. |

## Expected / Community-Reportable Builds

| Controller Family | Expected Cookie | Known Shape Differences | What to Report |
|---|---|---|---|
| `hardware-5.x` (OC200 / OC300) | `TPOMADA_SESSIONID` or `TPEAP_SESSIONID` | Older v5.x builds may issue `TPEAP_SESSIONID`, return `result.omadacId` in `/api/v2/login`, or wrap `devices` in `result.data`. All three are handled automatically. | Run `omada-mcp --doctor --json` and open an issue with the JSON output (no secrets are included). |
| `hardware-6.x` (OC200 / OC300 / OC400) | `TPOMADA_SESSIONID` | Same Web API v2 family as `software-6.x`; `setting/wlans/{groupId}/ssids` expansion and `roleName` privilege shape supported. | Run `omada-mcp --doctor --json` and share `controllerVer`, `family`, and `sessionCookie`. |

## Reporting a New Controller Build

Run:

```bash
omada-mcp --doctor --json
```

The JSON output strips your password and session token and reports the exact `controller.controllerVer`, `controller.family`, and `controller.sessionCookie` fields needed to add your build to this table.
