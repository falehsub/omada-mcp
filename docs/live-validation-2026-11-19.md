# Live home-network validation & follow-up notes — omada-mcp 2.5.0–2.5.3

**Date:** 2026-11-18 – 2026-11-19

**Final status:** Live verification of `2.5.0`, `2.5.1`, `2.5.2`, and `2.5.3` completed on software controller `6.3.0.45` with adopted `EAP725-Wall` APs; zero wireless clients dropped (`7` wireless clients untouched across all scans), zero unintended config edits, and the live integration returned cleanly to read-only (`OMADA_READ_ONLY=true`, empty `OMADA_WRITE_TOOLS`, `OMADA_ALLOW_CROSS_SITE=false`).

## Evidence and scope

Results below summarize operator-supplied Hermes live verification reports across releases `2.5.0` through `2.5.3` alongside local and GitHub Actions CI verification:

- Controller: Omada software controller `6.3.0.45` (private Docker host; identifiers, MACs, SSIDs, and IPs omitted).
- Adopted APs observed: `AP1` (`2` clients on `5g`, excluded from scan targets) and `AP2` (`0` clients on `5g`, `4` clients on `2g`; only empty `5g` radio scanned).
- Authorized live writes: read-only defaults (`OMADA_READ_ONLY=true`) maintained on the live supervised child throughout; isolated allowlisted admin runs executed `dryRun=true` previews for `update_ssid`, `set_wifi_radio_features`, and `delete_ip_group(id=...)`, plus three `survey_wifi` cycles strictly targeting `AP2` `5g` (`totalAffectedClients=0`). `2.4 GHz` was never scanned.

## Summary of verified capabilities (`v2.5.3`)

| Capability | Result | Notes |
|---|---|---|
| Package & CLI (`2.5.3`) | Pass | PyPI `2.5.3` wheel/sdist, `--version`, `--doctor` (`6/6`), `--list-tools --all` (`135` total: `55` read-only + `80` optional write). |
| `list_wlans` & `get_ssid` | Pass | Exposes `bandSteering`, `bandSteeringMode`, `loadBalance`, `condBroadcastCtrl`, `wifiCallingEnable`, `pmfMode`, `pmfModeLabel`, `rateLimit`, and `hasPresharedKey` boolean with zero secret material returned. |
| Omada `6.3+` dict shapes (`2.5.1+`) | Pass | `loadBalance: {"enable": false}` and `condBroadcastCtrl: {"enable": false}` preserved cleanly across `get_ssid`, `update_ssid(..., dryRun=true)`, and `diff_config_snapshots`. |
| `get_wifi_radio_features` & dry-run setter | Pass | Reads roaming, band steering, ATF, and mesh policy; `set_wifi_radio_features(..., dryRun=true)` preserves sibling fields cleanly. |
| `get_config_snapshot` + `diff_config_snapshots` | Pass | Captures `capturedAt` and `ssids`/`wlans`/`wirelessFeature`; untouched live diff returns `hasChanges=false` (`0` added/removed/changed). |
| `delete_ip_group(id=...)` alias | Pass | Accepts `id`/`groupId` aliases and advertises them in JSON Schema (`properties`) while keeping `required: ["group"]`. |
| `get_rf_scan` & `chanWidthLabel` (`2.5.2+`) | Pass | Parses `channel2g`/`5g`/`5g2`/`6g`, `bandStatuses`, `bandTimes`; decodes `chanWidth` `2/3/5/7` to `20MHz`/`40MHz`/`80MHz`/`160MHz` across all `34` `5g` rows. `EAP725-Wall` on `6.3.0.45` reports channel occupancy/interference (`band`, `chan`, `chanWidth`, `inter`, `util`), omitting per-BSSID neighbor rows. |
| `survey_wifi` state-digest stability (`2.5.1+`) | Pass | Removing volatile `rfScan.time` from preview hashes eliminated false `observed state changed` blocks. |
| Short-timeout decoupled verify + resume (`2.5.3`) | Pass | `survey_wifi(5g, timeoutSeconds=15, dryRun=false)` returned `verified=true`, `outcome="verified"`, `after.triggerVerified=true`, `after.scanCompleted=false`, `after.scanning=true`, `after.timedOut=true` in `15.5s`; `get_rf_scan(wait=true, timeoutSeconds=360)` collected all `34` rows in `230.4s` without re-triggering. |
| One-shot `360s` full survey (`2.5.3`) | Pass | `survey_wifi(5g, timeoutSeconds=360, dryRun=false)` completed in `240.6s` (`verified=true`, `after.triggerVerified=true`, `after.scanCompleted=true`, `after.timedOut=false`, `after.channelCount=34`). Actual `5g` scan duration measured at `230–265s` on `EAP725-Wall`. |

## Pending Follow-Up Notes (Next Patch)

These two low-priority polish items were reported during `v2.5.3` live verification and are tracked here for the next release cycle:

1. **Avoid embedding literal AP MACs in `survey_wifi` `after.resumeHint`**
   - **Current behavior:** When a scan is still running or timed out, [`survey_wifi`](../src/omada_mcp/domains/devices_write.py) builds `after["resumeHint"]` with `f"... call get_rf_scan(mac={norm_mac!r}, wait=True, timeoutSeconds=600) ..."`.
   - **Why change it:** Embedding the raw AP MAC inside a copy-pasteable prose string can expose a device identifier if a user/assistant quotes `after.resumeHint` verbatim into logs, issue reports, or external chat summaries.
   - **Planned fix:** Phrase the prose hint generically (e.g., `"Scan is still in progress; call get_rf_scan with the same device mac and wait=True, timeoutSeconds=600 to collect results without re-triggering."`) or pair it with structured `{ "tool": "get_rf_scan", "arguments": { "wait": true, "timeoutSeconds": 600 } }` guidance rather than interpolating the raw MAC string.

2. **Document `timedOut` vs `verified` semantics explicitly**
   - **Current behavior:** When `survey_wifi(wait=True)` hits a short poll budget while the AP is actively scanning, it returns both `verified: true` (meaning the trigger write was observed executing on the AP) and `after.timedOut: true` (meaning the client-side wait window expired before completion), disambiguated by `after.scanCompleted: false`.
   - **Why clarify:** Callers inspecting only `verified` and `timedOut` without checking `after.scanCompleted` may find `verified: true` + `timedOut: true` counterintuitive.
   - **Planned fix:** Document in `survey_wifi`'s descriptor / `docs/write-support.md` that `timedOut` strictly reflects the polling wait window (while `verified`/`triggerVerified` reflect confirmed trigger acceptance and `scanCompleted` reflects terminal scan completion).
