# Write support — implementation brief (v1.2)

Audience: the agent implementing write tools. This is a handoff, not marketing.

Everything below was learned by operating this server against a live TP-Link Omada SDN
deployment (software controller `6.2.10.17`, 4 devices, 15 clients, 6 LAN networks) for
several months. The endpoint shapes, the ordering rules and — more importantly — the traps
are recorded here so they are not rediscovered by breaking somebody's home network.

Read this before writing code. Section 1 is binding.

Scope: the internal **Web API v2** only (`/{omadacId}/api/v2/...`). The OAuth2 Open API is
out of scope, as before.

---

## 1. Safety contract (binding)

The current release is read-only, `OMADA_READ_ONLY=true` fails closed with `-32003`, and
that property is the reason this server is safe to hand to an LLM. Write support must
extend the same shape rather than punch a hole in it.

1. **Read-only stays the default.** Absent configuration, every write tool refuses.
2. **Explicit allowlist.** `OMADA_WRITE_TOOLS=set_client_fixed_ip,set_vlan_isolation` —
   comma-separated, exact names, no wildcards, no "all". A tool not in the list is refused
   with `-32003` *before* argument validation, so a prompt-injected model cannot even probe
   which writes exist.
3. **Two-phase apply.** Every write tool takes `dryRun` (default **true**). `dryRun=true`
   resolves the target, fetches current state, computes the diff, returns it, writes nothing.
   `dryRun=false` requires `confirm` equal to `"<tool>:<target-id>"`, so a model cannot
   "confirm" a target it did not read in the same session.
4. **Snapshot before, verify after.** Persist the pre-write object (JSON, one file per
   operation under `OMADA_SNAPSHOT_DIR`, default `~/.local/state/omada-mcp/snapshots`) and
   return `before` in the result. After the write, **re-GET the object and diff the fields
   you intended to change**. If the controller reports success and the object is unchanged,
   the tool must return an error. This is not paranoia: `PATCH /controller/setting` accepts
   `{"timeZone": ...}`, answers `errorCode: 0`, and silently discards it.
5. **No blind retries on writes.** The existing `-1600` retry is GET-only and must stay
   that way. A replayed POST creates a second object.
6. **Annotations tell the truth.** `readOnlyHint: false` on all writes; `destructiveHint:
   true` for anything that can cut connectivity or traffic (VLAN isolation, ACLs, DHCP
   ranges, device reboot); `idempotentHint: true` only where a repeat is genuinely a no-op
   (setting a fixed IP, setting a boolean flag). Replacing an IP group is delete+create and
   is **not** idempotent.
7. **One write per second, serialised.** The client already paces. Do not parallelise write
   calls; do not batch unrelated changes into one "helpful" composite tool.
8. **Refuse to strand the controller.** Before touching a LAN network, ACL or firewall
   object, check whether the target is the network the controller, the management host, or
   the caller is reachable through. Refuse with a clear message rather than obeying.

---

## 2. Mechanics that already work (reuse them)

- `OmadaClient.api(endpoint, method="GET", data=None)` returns the raw envelope;
  `api_result()` raises `OmadaError` on non-zero `errorCode`. Both already:
  - put the token in the query **and** send `Csrf-Token` (both are required),
  - replay the `TPOMADA_SESSIONID` cookie jar,
  - recover once from an HTML body on HTTP 200 (dead server-side session) by re-authenticating,
  - retry a single `-1600` on GET after `BURST_BACKOFF_SECONDS` (0.8 s).
- Add `OmadaClient.write(endpoint, method, data, *, expect_keys)` as the only write path.
  It must: enforce the read-only/allowlist gate, pace, snapshot, call `api`, treat
  `errorCode != 0` as failure, then verify and return `{before, after, verified, snapshot}`.
- **Session eviction is real.** Logging in with the same account invalidates the previous
  server-side session: the old process then gets the SPA shell as HTML on HTTP 200. During a
  write, re-authenticate and **re-read state** before replaying; never replay a POST blindly.
  Give write tools their own dedicated account (see section 9).
- Method semantics observed on this controller:
  - `GET` read;
  - `PATCH` update-in-place, and for LAN networks it requires the **complete object**, not a
    delta;
  - `POST` create (returns the new id in `result`, usually as a bare string);
  - `DELETE` delete, sometimes requiring a type segment in the path.
- Error semantics are method-dependent and this bites:
  - `-1600` on GET = throttling/pacing (retry); on a write it usually means the
    path+method pair is not registered (do not retry, fix the call);
  - `-1` = "General error", nearly always a missing required field;
  - `-1001` = bean validation, and the message names the offending field.

---

## 3. Verified write surface

Confidence: **VERIFIED** = exercised against `6.2.10.x` and read back.

| # | Capability | Endpoint | Method | Confidence |
|---|---|---|---|---|
| 1 | Client fixed IP / DHCP reservation | `/sites/{S}/clients/{MAC}` | PATCH | VERIFIED |
| 2 | IP / domain group create | `/sites/{S}/setting/profiles/groups` | POST | VERIFIED |
| 3 | IP group delete | `/sites/{S}/setting/profiles/groups/{type}/{groupId}` | DELETE | VERIFIED |
| 4 | Gateway ACL create | `/sites/{S}/setting/firewall/acls?type=0` | POST | VERIFIED |
| 5 | LAN network / VLAN update | `/sites/{S}/setting/lan/networks/{id}` | PATCH | VERIFIED (with traps) |
| 6 | DHCP pool edit | same as 5 | PATCH | VERIFIED |
| 7 | SSID read (`pmfMode`, `enable11r`) | `/sites/{S}/setting/wlans[/{groupId}/ssids]` | GET | READ ONLY |
| 8 | Device rename / LED | `/sites/{S}/devices/{MAC}` | PATCH? | UNVERIFIED |
| 9 | Device reboot, firmware upgrade | — | — | NOT INVESTIGATED |
| 10 | Controller settings (e.g. timeZone) | `/controller/setting` | PATCH | VERIFIED INEFFECTIVE |

Details and payloads:

### 3.1 Client fixed IP (safest first tool)

```
GET   /sites/{S}/clients/{MAC}      # 55 keys on this build
PATCH /sites/{S}/clients/{MAC}
```

`GET` returns `ipSetting` already populated, plus `supportFixedIp` (must be truthy):

```json
"ipSetting": {"useFixedAddr": true, "netId": "<lan network id>", "ip": "192.168.20.184",
              "serverType": "gateway", "serverMac": "AA-BB-CC-DD-EE-FF"}
```

`serverType`/`serverMac`/`netId` are read-only facts about where the reservation lives; only
`useFixedAddr`, `netId` and `ip` are yours to set on the way in.

- PATCH the **full object minus volatile keys**. Drop at least: `trafficDown`, `trafficUp`,
  `downPacket`, `upPacket`, `uptime`, `lastSeen`, `activity`, `uploadActivity`, `rxRate`,
  `txRate`, `rssi`, `snr`, `signalLevel`, `signalRank`, `dpiStat`, `authInfo`, `channel`,
  `active`, `rateLimit`, `authStatus`. Sending them back writes stale counters and can
  regress state.
- `netId` is **mandatory**. Omit it and the controller answers `-1 General error` with no
  field hint.
- `netId` is the LAN network id, not the VLAN number. It comes from
  `GET /sites/{S}/setting/lan/networks` (`id` field), not from `/interface`.
- **The address changes only when the DHCP lease renews.** The tool must say so, and must
  not report the new IP as active. Verify with `GET clients/{MAC}` after the lease, not
  immediately. Releasing is `{"useFixedAddr": false}` with the same full-object discipline.
- `GET /clients/{MAC}` answers `-41011` when the MAC is not a *client* — a switch or AP MAC
  lands there. Resolve the MAC from `insight/clients` first and echo a clear error.

### 3.2 IP groups

```
GET    /sites/{S}/setting/profiles/groups
POST   /sites/{S}/setting/profiles/groups
DELETE /sites/{S}/setting/profiles/groups/{type}/{groupId}
```

```json
{"name": "IP_Static_Block", "type": 0, "resource": 0,
 "ipList": [{"ip": "192.168.20.180", "mask": 32, "description": ""}]}
```

- `type`: `0` IP, `3` IPv6, `7` domain. The list mixes all of them; filter before you show
  anything to a model.
- POST returns `result` = the new `groupId` (a bare string).
- **There is no PATCH/PUT.** Editing = delete + recreate. That makes "replace an IP group"
  destructive and non-atomic; it needs its own confirmation story and a snapshot.
- **16 entries per group** (`-33726`). Larger ranges must be split into aligned CIDRs: the
  range `192.168.20.180-199` is `.180/30`, `.184/30`, `.188/30`, `.192/29` — four entries.
  Give the tool a packer with tests; hand-computed CIDRs are where humans get it wrong.
- **A group referenced by an ACL rule cannot be deleted** (`-33717`). Changing such a group
  requires the tmp-group swap: create a temp group, re-point the rule at it, delete the old
  group, recreate it with the new contents, re-point the rule back, delete the temp group.
  Every step is a write; a failure in the middle leaves the network in a state you must be
  able to describe. Snapshot all of it and verify the rule's `sourceIds` after each step.
- DELETE without the `{type}` segment returns `-1600 Unsupported request path`.

### 3.3 Gateway ACLs

```
GET  /sites/{S}/setting/firewall/acls?type=0&currentPage=1&currentPageSize=100
POST /sites/{S}/setting/firewall/acls?type=0
```

Rule fields observed: `id`, `type`, `index`, `entryId`, `siteId`, `name`, `status` (bool),
`policy` (0 deny, 1 permit), `protocols` (`[256]` = any), `sourceType`, `sourceIds`,
`destinationType`, `destinationIds`, `customAclPorts`. First match wins by `index`.

```json
{"name": "Deny-Guest-To-LAN", "status": true, "policy": 0, "protocols": [256],
 "sourceType": 0, "sourceIds": ["<network id>"],
 "destinationType": 0, "destinationIds": ["<network id>"],
 "direction": {"lanToWan": false, "lanToLan": true, "wanInIds": [], "vpnInIds": []},
 "type": 0, "biDirectional": false, "stateMode": 0, "ipSec": 0, "syslog": false,
 "customAclDevices": [], "customAclOsws": [], "customAclStacks": []}
```

- `sourceType`/`destinationType`: `0` network, `1` IP group, `2` port group. This is
  confirmed against live rules; community documentation claiming "0 = network only" is wrong.
- The list envelope carries **`aclDisable`** — an engine-wide kill switch that makes every
  rule inert regardless of its own `status`. Toggling it affects **all** rules at once and
  has no business in a per-rule tool.
- **`aclDisable` is not a reliable indicator of enforcement.** A LAN->WAN deny rule was
  observed enforcing on the gateway while `aclDisable` read `true`. Do not build a "your
  network is protected" claim on that flag, and do not build a safety check on it either.
  Enforcement is verified empirically (per-rule `status` toggle plus client re-association),
  which means ACL tools must warn that verification is behavioural, not read-back.
- A deny rule that looks inert can be very much alive: after an ACL change, watch the
  affected clients, not the response body.

### 3.4 LAN networks / VLANs / DHCP

```
GET   /sites/{S}/setting/lan/networks?currentPage=1&currentPageSize=50   # audit view
GET   /sites/{S}/setting/lan/networks/interface                          # write source
PATCH /sites/{S}/setting/lan/networks/{id}                               # full object
```

**Two endpoints, two different objects. This is the trap that costs hours.**

- The **collection** (`.../networks`) exposes `accessControlRule`, `isolation`,
  `existNetworkIsolation` — it is what `network_audit` reads.
- The **`/interface`** collection is the object the controller accepts on PATCH. It carries
  `isolation`, `dhcpSettings`, `lanNetworkIpv6Config`, `gatewaySubnet`, `vlanType`,
  `interfaceIds`, `arpDetectionEnable`, `dhcpGuard`, … but **no `accessControlRule`**.
- Practical consequence: read the flag from one endpoint, apply the change with the object
  from the other, and re-read both to verify. A read-modify-write built on a single endpoint
  will either send an object the controller rejects or silently drop a field.

PATCH rules:

- Send the **complete** object from `/interface`, mutated. A delta is rejected or ignored.
- `lanNetworkIpv6Config.proto` must be present (`"none"` for IPv4-only) or the call fails
  `-1001 Parameter [proto] should not be null`. A top-level `proto`, a `dhcpSettings.proto`
  or a `?proto=` query parameter are all ignored.
- `GET /setting/lan/networks/{id}` returns `-1600`; only the collections read back.
- DHCP pools live in `dhcpSettings.ipRangePool`, an array of `{ipaddrStart, ipaddrEnd}`.
  That array is authoritative. `ipRangeStart`/`ipRangeEnd` are legacy integer mirrors the
  controller may leave stale, and `ipaddrStart`/`ipaddrEnd` are the outer bounds of the whole
  pool. Carving a static block out of a pool is two entries, e.g.
  `[{2..179}, {200..254}]`, with `.180-.199` reserved for fixed assignments.
- `isolation` is client isolation for that VLAN. `accessControlRule` is a separate concept
  that lives on the other endpoint. Setting one does not set the other; a VLAN can read
  `isolation: false, accessControlRule: false` and be wide open in both senses.

---

## 4. Three canonical flows (write these as acceptance tests)

**A. Reserve a fixed address for a device**

1. `insight/clients` -> resolve MAC (a device MAC will `-41011`).
2. `GET clients/{MAC}` -> check `supportFixedIp`; capture `ipSetting` as `before`.
3. `GET setting/lan/networks` -> resolve `netId` for the intended VLAN; verify the target IP
   is inside that subnet and outside every `ipRangePool` range.
4. `PATCH clients/{MAC}` with the full object minus volatiles and the new `ipSetting`.
5. `GET clients/{MAC}` -> assert `ipSetting.ip == requested`.
6. Report: applied, verified, "effective at next lease renewal", rollback = old `ipSetting`.

**B. Harden a guest VLAN**

1. `GET setting/lan/networks` -> confirm current `isolation` / `accessControlRule`.
2. `GET setting/lan/networks/interface` -> capture the full object (write source).
3. PATCH `isolation: true` (full object, `lanNetworkIpv6Config.proto` present).
4. Re-read both endpoints; assert `isolation` true and the rest of the object unchanged
   (diff the whole object, not just the field — a bad PATCH can reset `dhcpSettings`).
5. Only then consider an ACL. Note that an ACL engine flag is not trustworthy; report what
   was written and what was observed, separately.

**C. Grow an IP group past 16 entries**

1. Compute aligned CIDRs; assert `len(entries) <= 16` before writing.
2. If the group is referenced by a rule (`-33717`), run the tmp-group swap, snapshotting at
   every step and verifying `sourceIds` after each re-point.
3. Re-read the group and the rule; assert both.

---

## 5. Proposed tool surface (v1.2)

Names are the contract; keep them stable.

| Tool | Annotations | Args | Notes |
|---|---|---|---|
| `set_client_fixed_ip` | ro=false, destructive=false, idempotent=true | `mac`, `ip`, `vlan`(or `netId`), `dryRun`, `confirm` | Lease-delayed; reports pending |
| `release_client_fixed_ip` | ro=false, destructive=false, idempotent=true | `mac`, `dryRun`, `confirm` | `useFixedAddr: false` |
| `set_vlan_dhcp_pools` | ro=false, destructive=true, idempotent=true | `vlan`/`netId`, `pools[]`, `dryRun`, `confirm` | Full-object PATCH; validates ranges |
| `set_vlan_isolation` | ro=false, destructive=true, idempotent=true | `vlan`/`netId`, `isolation`, `dryRun`, `confirm` | Warns: cuts client-to-client traffic |
| `create_ip_group` | ro=false, destructive=false, idempotent=false | `name`, `cidrs[]` or `ipRange`, `dryRun`, `confirm` | Packs CIDRs, enforces <=16 |
| `replace_ip_group` | ro=false, destructive=true, idempotent=false | `group`, entries, `dryRun`, `confirm` | Delete+create; tmp-swap if referenced |
| `create_gateway_acl` | ro=false, destructive=true, idempotent=false | `name`, `policy`, `source`, `destination`, `direction`, `dryRun`, `confirm` | Engine flag out of scope |
| `set_acl_rule_status` | ro=false, destructive=true, idempotent=true | `rule`, `status`, `dryRun`, `confirm` | The only reliable per-rule switch |
| `get_config_snapshot` | ro=true | `objects[]` | Read-only, safe, useful before any change |

Every write returns:

```json
{"applied": true, "dryRun": false, "verified": true,
 "before": {...}, "after": {...}, "snapshot": "2026-...-set_client_fixed_ip.json",
 "warnings": ["effective at next DHCP lease renewal"],
 "rollback": {"tool": "set_client_fixed_ip", "arguments": {...}}}
```

`outputSchema` for each, as v1.1.1 does for the read tools.

Deliberately **not** in v1.2: device reboot, firmware upgrade, SSID create/delete, ACL engine
toggle, controller settings. Each needs a maintenance-window model that does not exist yet.

---

## 6. Error catalog additions

Add only what is verified here, with the endpoint/method context the existing
`explain_error` tool already supports:

| Code | Meaning | Context |
|---|---|---|
| `-33726` | IP group is full (16 entries max) | group create |
| `-33717` | Object is referenced elsewhere; delete refused | group delete while an ACL uses it |
| `-1001` | Bean validation failed; message names the field | LAN network PATCH missing `lanNetworkIpv6Config.proto` |
| `-1600` | On GET: throttled, retry after ~0.8 s. On write: path+method not registered | both |
| `-1` | General error; usually a missing required field (`netId` on client PATCH) | write |
| `-41011` | Not a client (a device MAC was supplied) | `clients/{MAC}` |

---

## 7. Testing without a controller

CI must never touch a real network, and neither should the first implementation.

- **Mock controller**: extend the stdlib test harness into `tests/mock_controller.py` — an
  `http.server` implementing `/api/info`, `/api/v2/login`, and the endpoints above, with a
  tiny in-memory state machine.
- **Fault injection**, all of which are behaviours this controller exhibited:
  - HTML body on HTTP 200 after a session is invalidated;
  - `-1600` once, then success (pacing);
  - `-33726` on the 17th entry;
  - `-33717` on deleting a referenced group;
  - `-1` when `netId` is omitted from a client PATCH;
  - **silent no-op**: `errorCode: 0` but state unchanged — the fixture that proves
    verify-after-write actually works.
- **Fixtures**: capture the read shapes (network object, ACL rule, group, client detail,
  device list) into `tests/fixtures/*.json`, scrubbed of real identifiers, and test the
  projections and diffing against them.
- **Gate tests**: empty allowlist -> `-32003`; `dryRun` defaults to true; `confirm` mismatch
  refused; snapshot written before the call; verification failure surfaces as a tool error;
  a write attempt with `OMADA_READ_ONLY=true` never reaches the transport.

Live writes: only behind an explicit env flag (`OMADA_ALLOW_LIVE_WRITE_TESTS=1`) against a
disposable controller, never against a home network in CI.

---

## 8. Definition of done

- A dry run of every write tool returns the exact diff and writes nothing (assert with a
  mock that counts transport calls).
- A committed write reports `verified: true` only after a re-read that matches intent; a
  silent no-op returns an error.
- The allowlist gate is enforced before argument validation.
- Every write emits one JSONL audit record: timestamp, tool, target, before-snapshot id,
  fields changed, result, verification outcome.
- `--doctor` gains a `write` phase that reports whether writes are enabled, for which tools,
  and with which account — without ever performing one.

---

## 9. Open questions for the owner

1. **Which account?** `Viewer` cannot write. An `Admin` account writes fine but every login
   with the same account evicts the previous session (the HTML-on-200 failure). The write
   server should own a dedicated Admin account, separate from read-only consumers.
2. **Maintenance policy** for device-affecting operations (reboot, firmware): window, notice,
   rollback expectations. Until there is one, those tools stay unshipped.
3. **Isolation semantics** on this controller: whether `accessControlRule` is a switch that
   creates rules, or a flag that reflects them, differs between firmware families. Probe on
   the target build before promising behaviour; report observation, not intent.

---

## 10. Suggested order

1. `OmadaClient.write()` + gate + snapshot + verify, with mock-controller tests. No new tools.
2. `set_client_fixed_ip` / `release_client_fixed_ip` — reversible, lease-delayed, low blast
   radius. Ship first.
3. `set_vlan_isolation` and `set_vlan_dhcp_pools` — the two-object read model gets exercised.
4. `create_ip_group` / `replace_ip_group` / `create_gateway_acl` / `set_acl_rule_status` —
   the destructive tier, behind the strictest confirmation.
5. Device operations — only after section 9.2 has an answer.

Provenance: verified on software controller `6.2.10.17` (Web API v2,
`TPOMADA_SESSIONID`). Hardware builds (`OC200`/`OC300`, v5.x, `TPEAP_SESSIONID`) are
untested for writes; treat every row above as "unverified" there and re-probe with
`--doctor --json` before shipping those paths.
