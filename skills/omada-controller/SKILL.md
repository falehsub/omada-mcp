---
name: omada-controller
description: Query TP-Link Omada controllers through the local Web API v2.
---

# Omada Controller — Web API v2 field guide

Everything here was verified against live controllers (software v5.13.30.8 and
v6.2.10.17) with an ordinary local account. It exists because the Omada Web API
is undocumented and its failure modes are misleading: the same code means
different things depending on context, and several "obvious" request shapes are
silently ignored.

Use this skill when:

- a controller URL, username and password are available and you need device,
  client, SSID, VLAN or ACL facts;
- an Omada call returns an `errorCode` and you need the real cause;
- an endpoint answers HTTP 200 with HTML instead of JSON;
- you need to decide between the Web API and the Open API.

The companion MCP server in this repository (`omada-mcp`) implements 33 read-only
diagnostics and inspection tools (plus 47 opt-in guarded write tools when
explicitly enabled). When it is installed, prefer its tools over hand-rolled
HTTP; when it is not, the snippets below are the reference implementation.

## Two APIs, one controller

| | Web API (this document) | Open API |
|---|---|---|
| Base path | `/{omadacId}/api/v2/...` | `/openapi/v1...` |
| Auth | username + password, `Csrf-Token` header + cookie | OAuth2 client credentials |
| Controller setup | none — it is the API the web UI calls | "Platform Integration" must be configured |
| Roles | `Viewer` is enough for reads | client id/secret per integration |
| Failure when unset | — | `-44116` |

`-44116` is the single most common wrong turn: it means the *Open* API is not
enabled and has nothing to do with credentials. The Web API works independently
and needs no controller-side setup.

## Authentication

```python
import http.cookiejar, json, ssl, urllib.request

base = "https://<controller-host>:8043"          # 8043 https (default), 8088 http
ctx = ssl.create_default_context(cafile="<controller-ca>.pem")
# self-signed cert on Python 3.13+: ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
# last resort only: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(jar),
)

# 1. controller id (public endpoint, no auth)
info = json.loads(opener.open(f"{base}/api/info").read())["result"]
cid = info["omadacId"]

# 2. login
req = urllib.request.Request(
    f"{base}/{cid}/api/v2/login",
    data=json.dumps({"username": user, "password": pwd}).encode(),
    headers={"Content-Type": "application/json"}, method="POST")
token = json.loads(opener.open(req).read())["result"]["token"]

# 3. every later call
#    URL:    {base}/{cid}/api/v2/{endpoint}?token={token}
#    Header: Csrf-Token: {token}
#    Cookie: TPOMADA_SESSIONID (the cookie jar replays it automatically)
```

Three rules that are not optional:

1. **The token goes in both places** — query string *and* `Csrf-Token` header.
   Either one alone fails authentication.
2. **The `omadacId` prefix is mandatory.** Without it the controller returns the
   ~2.9 KB web UI shell with HTTP 200. With a *user* id instead of the controller
   id you get "Controller ID not exist".
3. **The site id in the path is the hex id, never the site name.** Names are a
   display concept; the name in a URL produces `-1505`.

### Appending the token safely

Endpoints with their own query string break a naive `endpoint + "?token=..."`:

```python
sep = "&" if "?" in endpoint else "?"          # never produce two "?"
url = f"{base}/{cid}/api/v2/{endpoint}{sep}token={token}"
```

## Endpoints

Site id below is the hex string from `/sites` (e.g. `0123456789abcdef01234567`).

| Endpoint | Method | Notes | Viewer? |
|---|---|---|---|
| `/sites?currentPage=1&currentPageSize=50` | GET | site list + `totalRows` | yes |
| `/sites/{siteId}` | GET | name, WAN/LAN/WLAN state | yes |
| `/sites/{siteId}/devices` | GET | gateway, switches, APs | yes |
| `/sites/{siteId}/setting/wlans` | GET | SSIDs — **response contains the PSK** | yes |
| `/sites/{siteId}/setting/lan/networks?currentPage=1&currentPageSize=50` | GET | VLANs, subnets, DHCP, ACL flag | yes |
| `/sites/{siteId}/setting/lan/networks/interface` | GET | full network objects, the ones a PATCH needs | yes |
| `/sites/{siteId}/insight/clients?currentPage=1&currentPageSize=100` | GET | all known clients, WiFi + wired | **yes** |
| `/sites/{siteId}/insight/known-clients?page=1&pageSize=100` | GET | known-client grid with IP/SSID/AP | yes |
| `/sites/{siteId}/clients` | GET/POST | connected clients | **no** |
| `/sites/{siteId}/clients/{MAC}` | GET/PATCH | richest client read; fixed-IP writes | **no** |
| `/users/current` | GET | current user + `privilege.sites` | yes |
| `/controller/setting` | GET | timezone, region, DST | yes |
| `/loginStatus` | GET | session validity probe | yes |
| `/sites/{siteId}/setting/firewall/acls?type=0&currentPage=1&currentPageSize=100` | GET/POST | gateway ACLs | admin |
| `/sites/{siteId}/setting/profiles/groups` | GET/POST | IP/domain groups | admin |

Two shape traps:

* `sites/{id}/devices` returns `result` as a **bare list** on 6.2.x, while
  `sites` and `setting/lan/networks` return `{"data": [...]}`. Branch:
  `rows = res if isinstance(res, list) else res.get("data", [])`.
* Paginated reads return **empty `data` with `totalRows > 0`** unless
  `currentPage=1` (or `0`) is sent explicitly.

## Reading and writing LAN networks / VLANs

`PATCH /sites/{siteId}/setting/lan/networks/{networkId}` requires the **whole
object** as read from `/networks/interface` — a partial body silently resets
fields. Two hard requirements:

* `lanNetworkIpv6Config.proto` must be present (`"none"` for IPv4-only).
  A top-level `proto`, a `dhcpSettings.proto`, or `?proto=` are all ignored and
  you get `-1001 Parameter [proto] should not be null`. Also on 6.2.14+, `POST`
  creates interface networks with empty `dhcpGuard: {}` and `dhcpv6Guard: {}` —
  populate `{"enable": false}` on both before PATCHing or you also get `-1001`.
* `GET /networks/{id}` returns `-1600`. Only the collection and
  `/networks/interface` read back; `GET /setting/lan/networks` requires
  `?currentPage=...` (`-1001` without it). Take the object from `/interface`.
* On 6.2.14+, renaming `name` auto-updates `origName`, and manual DHCP DNS uses
  `dhcpSettings.dhcpns="manual"` + `priDns`/`sndDns` (`dns1`/`dns2`/`dnsEnable`
  and `icmpPingEnable` on LAN PATCHes are silently dropped).

Multiple DHCP pools (for example, carving a static block out of a dynamic range)
live in `dhcpSettings.ipRangePool` as `[{ipaddrStart, ipaddrEnd}, ...]`, with
`ipaddrStart`/`ipaddrEnd` kept as the outer bounds. `ipRangeStart`/`ipRangeEnd`
are legacy integer mirrors the controller may not update — **`ipRangePool` is
authoritative**.

Per-network fields worth reporting: `id`, `name`, `vlan`, `gatewaySubnet` (CIDR),
`accessControlRule` (this VLAN has ACLs attached), `dhcpSettings`
(`enable`, `priDns`, `sndDns`, `leasetime`), `isolation`, `deviceMac` (gateway),
`interfaceIds`.

## Clients, and the Viewer-role wall

`/sites/{siteId}/clients*` is Admin-only. With a Viewer account these answer
`-41011 "This client does not exist"` or `-1 "General error"` — which reads like
a missing object and is actually a permissions refusal. Use
`/sites/{siteId}/insight/clients`: every known client, WiFi and wired, with
`wireless: true/false`, traffic counters, duration and last-seen timestamp.

`insight/clients` carries **no IP field**; only `clients/{MAC}` has one, and only
for Admin. Do not promise per-client IPs from a Viewer account.

**Fixed IP (DHCP reservation)** — `PATCH /sites/{siteId}/clients/{MAC}` with the
full 55-key client object (`GET` it first and strip the 20 volatile runtime keys:
`trafficDown`, `trafficUp`, `downPacket`, `upPacket`, `uptime`, `lastSeen`,
`activity`, `uploadActivity`, `rxRate`, `txRate`, `rssi`, `snr`, `signalLevel`,
`signalRank`, `dpiStat`, `authInfo`, `channel`, `active`, `rateLimit`, `authStatus`),
then set:

```json
{"ipSetting": {"useFixedAddr": true, "netId": "<LAN network id>", "ip": "192.168.20.180"}}
```

Omitting `netId` returns `-1 General error` with no field hint; `ip` on the live
client remains at its current lease until DHCP renewal, while a managed device MAC
(switch/AP/gateway) answers `-41011` on `/clients/{MAC}` because devices are not
clients. The same endpoint also enforces Admin privilege (`-41011` for `Viewer`).
address changes when the DHCP lease renews; `useFixedAddr: false` releases it.

## ACLs and IP groups

On 6.2.x these endpoints read **and** write real rules (an older claim that ACLs
were unreachable through the Web API is wrong):

| Purpose | Endpoint |
|---|---|
| List gateway ACLs | `GET .../setting/firewall/acls?type=0&currentPage=1&currentPageSize=100` |
| Create / Update / Delete gateway ACL | `POST .../acls?type=0`, `PUT .../acls/{aclId}?type=0` (updates `existSyslog` when `syslog` changes), `DELETE .../acls/{aclId}?type=0` |
| Offline DHCP reservations | `GET/POST .../setting/service/dhcp`, `PUT/DELETE .../setting/service/dhcp/{id}` |
| LAN networks & WAN ports | `POST/DELETE .../setting/lan/networks`, `PATCH .../setting/lan/networks/{id}`, `GET .../setting/wan/networks` (`osgPortInfo.wanLanPortSettings`) |
| WLAN groups & SSIDs | `GET .../setting/wlans`, `GET/POST .../setting/wlans/{groupId}/ssids`, `PATCH/DELETE .../ssids/{ssidId}` |
| Port forwards, static routes & services | `.../setting/transmission/portForwardings`, `.../setting/transmission/staticRoutings`, `.../setting/service/mdns`, `.../setting/profiles/mdns`, `.../setting/upnp`, `.../setting/dns-proxy`, `.../setting/service/ddns` |
| Logs & Audit | `GET .../logs/alerts?...&filters.timeStart=...&filters.timeEnd=...`, `.../logs/events`, `GET .../audit/logs` (`audit-logs` returns `-1600`) |
| Devices & Clients | `PATCH .../eaps|switches|gateways/{mac}`, `PUT .../config/general`, `POST .../cmd/devices/{mac}/reboot`, `GET .../clients?filters.active=true|false`, `POST .../cmd/clients/{mac}/block|unblock|reconnect` |
| List groups | `GET .../setting/profiles/groups` |
| Create / Delete group | `POST .../setting/profiles/groups`, `DELETE .../setting/profiles/groups/{type}/{groupId}` |
| Per-client fixed IP | `PATCH .../clients/{MAC}` |

`result.aclDisable` in the list response is **advisory and unreliable**. A newly created
LAN→WAN deny rule was observed enforcing on the gateway while `aclDisable` still
read `true`; never build a safety check on `aclDisable`, and verify enforcement
empirically (toggle the rule's own `status`, watch a client re-associate) before
claiming a policy is or is not in force.

Group updates require delete + recreate (no `PATCH`/`PUT`). If any ACL rule
references the group, `DELETE` fails with `-33717`; perform a temporary-group swap
(create temp group → repoint ACL `sourceIds`/`destinationIds` → delete original →
recreate original → repoint ACLs back → delete temp) and re-read at each step.

Group object (`type: 0` = IP group):

```json
{"name": "deny-block", "type": 0, "resource": 0,
 "ipList": [{"ip": "192.168.20.180", "mask": 32, "description": ""}]}
```

* `POST` returns the new `groupId` (bare string on 6.2.14+, `{"id": ...}` on older builds). `GET .../setting/profiles/groups` returns `groupId` on 6.2.x.
* `DELETE` **requires the type segment**: `/groups/0/{groupId}`. Without it,
  `-1600 Unsupported request path`.
* There is no `PATCH`/`PUT` on groups — delete and recreate.
* **`-33726` means the group is full: an IP group holds at most 16 entries.**
  A range expressed as 16+ individual `/32` entries overflows immediately; send
  network-aligned CIDRs instead (`.180-.191` → `192.168.20.180/28` is 4 entries,
  not 12). Plan group membership before writing, because there is no partial
  update.

Gateway ACL body (verified working):

```json
{
  "name": "Deny-Guest-WAN", "status": true, "policy": 0, "protocols": [256],
  "sourceType": 1, "sourceIds": ["<groupId>"],
  "destinationType": 1, "destinationIds": ["<IPGroup_Any id>"],
  "direction": {"lanToWan": true, "lanToLan": false, "wanInIds": [], "vpnInIds": []},
  "type": 0, "biDirectional": false, "stateMode": 0, "ipSec": 0, "syslog": false,
  "customAclDevices": [], "customAclOsws": [], "customAclStacks": []
}
```

`policy`: `0` = deny, `1` = permit. `sourceType`/`destinationType`: `0` =
network, `1` = IP group, `2` = port (confirmed against live rules; community
posts claiming `0`-only for networks are wrong). `IPGroup_Any` is the catch-all
group used for "to WAN".

## Error codes

| Code | Meaning | What to do |
|---|---|---|
| `-1` | General error — usually a mandatory field missing from the body | Compare against a full `GET` of the object |
| `-1001` | Bean validation (`Parameter [x] should not be null`) | For LAN networks: include `lanNetworkIpv6Config: {"proto": "none", "enable": 0}` |
| `-1007` | Current user does not have permission for this endpoint/operation | Use a dedicated Admin account for writes (observed when Viewer attempts writes on 6.2.14+) |
| `-1505` | No permission for this site | Use the hex site id, not the name |
| `-1600` | Unsupported request path **or** burst rate-limiting | See below — the same code means both (`PATCH .../acls/{id}` also returns `-1600`; use `PUT`) |
| `-30109` | Session expired | Re-authenticate |
| `-33598` | Device does not support Network Isolation | Site has no isolation-capable adopted gateway/switch (`existNetworkIsolation=false`) |
| `-33601` | Invalid ACL destination type | `destinationType=0` (`network`) is disallowed on `LAN->WAN` rules; use `IPGroup_Any` (`type=1`) |
| `-33717` | IP/port group is referenced by an ACL rule | Re-point ACL rule(s) to a temporary group first, delete/recreate, re-point back |
| `-33726` | IP group full (16 entries max) | Use aligned CIDRs |
| `-41011` | Client does not exist, target MAC is a managed device, or Viewer role on `/clients/*` | Use `insight/clients` or `/devices` for read; use a dedicated Admin account for writes |
| `-44116` | Open API not enabled | Use the Web API |

### `-1600` is overloaded

It covers two unrelated conditions, and the fix differs:

* **wrong path shape** — e.g. `GET /networks/{id}` (only the collection reads),
  `/groups/{groupId}` without the type segment, or `PUT /controller/setting`;
* **burst throttling** — more than ~5 calls in a couple of seconds makes
  *correct* endpoints answer `-1600`.

Pace calls at **0.8 s** and retry a `-1600` **once** after that delay. A path
that works on retry was a burst block; one that fails again is wrong. Never loop
on `-1600` — it converts a throttle into a lockout.

## HTML instead of JSON

A 200 response containing the web UI shell has two very different causes:

1. **The URL is wrong** — missing `omadacId` prefix, or a path the controller
   does not register.
2. **The server-side session died** while the process stayed alive: another
   login with the same account, a controller restart, or the controller's own
   session timeout. The `TPOMADA_SESSIONID` cookie has a 15-day max-age, so a
   cookie that is present proves nothing — the *server-side* session is what
   ends.

Distinguish by replaying once after a fresh login. If the retry returns JSON,
the cause was (2); if it returns HTML again, the cause is (1), or the account is
being logged out by a competing session. A long-lived client must therefore
catch "HTML on 200", re-authenticate **once**, replay, and then raise rather than
loop. A freshly spawned process will mask a dead session — when auditing, test
the process that is actually running, not a new one.

## Reading devices

`sites/{siteId}/devices` fields that matter: `model` (`ER7206`, `ES220GMP`,
`EAP725-Wall`), `firmwareVersion` (full build string — take the leading
`x.y.z`), `needUpgrade` (firmware-outdated flag; the payload carries **no**
target version, so report the flag, never a "latest version"), `status`
(`14` = connected), and `name` (which is the MAC unless the device was renamed).
Two identical models arrive as indistinguishable rows — number them for a report.

## Controller updates (software installs)

Hardware controllers (OC200/OC300) update from their own UI. For a **software**
controller, prefer the package and avoid the web UI updater: the UI path assumes
hardware, and a software install can end with an inconsistent database.

1. Snapshot/back up the host or VM first, and keep it until the network is
   verified healthy.
2. Download the current `.deb` from the vendor's support page. Do not construct
   the URL from a distro package recipe — the build suffix differs and yields
   404s. Confirm with a `HEAD` request and check the size (~277–290 MB).
3. `systemctl stop omada` → `dpkg -i <package>.deb` → `systemctl start omada`.
4. Verify: the UI update prompt is gone, every AP/switch is still adopted, and
   clients associate. `dpkg -l | grep omada` reports the installed version.

Installed layout: package `omadac`, path `/opt/tplink/EAPController`, service
`omada`.

## Controller settings are read-only

`GET /controller/setting` returns `general.timeZone`, `region` and `dst`, but
every write shape dead-ends: `PATCH` with `{"timeZone": ...}` answers
`errorCode: 0, Success` **and changes nothing** (re-read after 10 s to prove it),
the `{"general": {...}}` form gives `-1001`, the whole-object form adds
`cerId should not be null`, and `PUT` gives `-1600`. Name and timezone belong to
the UI (Settings → Controller). Shipped timezone labels can be a neighbouring
IANA zone with the same UTC offset and no DST; report the **offset** you observe,
not just the label.

## Safety notes for automation

* SSID objects contain `securityKey` (the passphrase in plaintext). Whitelist
  fields when returning WLAN data; expose "has a key" rather than the key.
* Prefer a dedicated local account. Sharing one account across a long-lived
  bridge, write automation, and interactive web UI logins causes the
  session-eviction loop described above (each login kills the other session).
* Writes (when explicitly enabled in `omada-mcp` via `OMADA_READ_ONLY=false` and
  `OMADA_WRITE_TOOLS`) default to `dryRun=true`, require `confirm="<tool>:<target>"`,
  pace at `>= 1.0 s`, never retry on `-1600`, snapshot before mutation, and re-read
  afterwards to catch silent controller no-ops.
* Reads are idempotent; nothing in this document should be scheduled faster than
  the 0.8 s pacing. A health check that spawns a fresh login every minute will
  evict a session held by an agent — use `omada-mcp --watch` or
  `omada-mcp --export-metrics` (which reuse a single persistent session).
* Additional v6.2 field quirks handled in `omada-mcp`:
  * Switch `topology-v2` `upperPort`/`wiredUpInfo`: `.port` is the switch's own
    uplink port while `.upLinkPort` can report the upstream device's port.
  * AP `radioSetting*.channel` often stores a region-table index wire value whose
    physical channel number lives in `eaps/{mac}/channelInfo` (`value` ->
    `channelValue`) and `wp*.actualChannel`.
  * Local DNS (`setting/dns/local`), policy routes (`setting/routing/policy`),
    and WIDS/IPS security endpoints vary across v5/v6 hardware and firmware; wrap
    with `-1007` / `-1600` / missing-feature handling before failing.
