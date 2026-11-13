"""MCP tool definitions for omada-mcp.

Every tool is a thin, whitelisting projection over the controller's JSON. Two
product rules drive the design:

1. **Whitelist fields, never echo objects.** The WLAN object carries the SSID
   pre-shared key (``securityKey``), the site object carries the device account
   and the client object carries location data. Tools return an explicit field
   set and report ``hasPresharedKey: true`` instead of the key itself.
2. **Declare intent.** Each tool ships MCP annotations
   (``readOnlyHint`` / ``destructiveHint`` / ``idempotentHint`` /
   ``openWorldHint``) so hosts can gate or auto-approve calls without guessing.

v1.0 exposes eight read-only tools. ``OMADA_READ_ONLY=true`` is enforced by the
dispatcher for any tool that is not declared read-only, so adding a write tool in
a later release cannot silently bypass the safety switch.
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .client import OmadaClient, OmadaError, SiteInfo, explain_error_code
from .config import Config
from .write_tools import (
    WRITE_ENVELOPE_SCHEMA,
    _ACL_DISPATCH_NOTES,
    _fetch_acls,
    _fetch_groups,
    _fetch_lan_collection,
    _fetch_lan_interfaces,
    create_gateway_acl,
    create_ip_group,
    release_client_fixed_ip,
    replace_ip_group,
    set_acl_rule_status,
    set_client_fixed_ip,
    set_vlan_dhcp_pools,
    set_vlan_isolation,
)

__all__ = [
    "TOOLS",
    "TOOL_MAP",
    "Tool",
    "get_tool",
    "normalize_mac",
    "project_device",
    "project_wlan",
    "tool_descriptors",
]

_MAX_CLIENT_PAGES = 20


def normalize_mac(value: str) -> str:
    """Normalise ``AABBCCDDEEFF`` / ``AA-BB-CC-DD-EE-FF`` / ``aa:bb:..`` to colons."""
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).lower()
    if len(cleaned) == 12 and all(ch in "0123456789abcdef" for ch in cleaned):
        return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    return str(value or "").strip().lower()


def _iso(ms: Any) -> str:
    """Epoch-milliseconds to a UTC ISO-8601 string (empty when absent)."""
    try:
        stamp = float(ms)
    except (TypeError, ValueError):
        return ""
    if not stamp:
        return ""
    try:
        return datetime.datetime.fromtimestamp(stamp / 1000.0, datetime.timezone.utc) \
            .isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return str(ms)


def _pick(source: Dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in source and source[name] not in (None, ""):
            return source[name]
    return default


# -- projections -------------------------------------------------------------

_DEVICE_FIELDS: Tuple[Tuple[str, Tuple[str, ...], Any], ...] = (
    ("mac", ("mac",), ""),
    ("name", ("name",), ""),
    ("type", ("type",), ""),
    ("model", ("showModel", "model"), ""),
    ("ip", ("ip",), ""),
    ("firmware", ("firmwareVersion",), ""),
    ("uptime", ("uptime", "uptimeLong"), ""),
    ("clientCount", ("clientNum",), 0),
    ("status", ("statusCategory",), -1),
    ("needUpgrade", ("needUpgrade",), False),
)


def project_device(device: Dict[str, Any]) -> Dict[str, Any]:
    return {out: _pick(device, *src, default=default) for out, src, default in _DEVICE_FIELDS}


def project_client(client: Dict[str, Any]) -> Dict[str, Any]:
    """Client projection, including the fields an admin actually asks for."""
    wireless = bool(client.get("wireless"))
    return {
        "mac": client.get("mac", ""),
        "name": _pick(client, "name", "hostName", default=""),
        "hostName": client.get("hostName", ""),
        "ip": client.get("ip", ""),
        "wireless": wireless,
        "guest": bool(client.get("guest")),
        "active": bool(client.get("active", True)),
        "ssid": client.get("ssid", ""),
        "apName": _pick(client, "apName", "switchName", default=""),
        "networkName": _pick(client, "networkName", "network", default=""),
        "vlan": _pick(client, "vid", "vlan", default=0),
        "download": client.get("download", 0),
        "upload": client.get("upload", 0),
        "duration": client.get("duration", 0),
        "lastSeen": _iso(client.get("lastSeen")),
        "signal": _pick(client, "signalLevel", "rssi", default=None),
    }


#: Fields safe to expose from a WLAN object. ``securityKey`` is deliberately
#: absent: it is the literal SSID passphrase in plaintext.
_WLAN_FIELDS: Tuple[str, ...] = (
    "id", "name", "ssid", "band", "enabled", "guest", "security", "vlanId",
    "networkName", "hideSsid", "macFilterEnable", "rateLimitEnable",
)


def project_wlan(wlan: Dict[str, Any], group_name: Optional[str] = None) -> Dict[str, Any]:
    projected = {key: wlan[key] for key in _WLAN_FIELDS if key in wlan}
    is_v6_ssid = any(
        key in wlan
        for key in ("band", "security", "pskSetting", "guestNetEnable", "broadcast", "vlanSetting")
    )
    if "ssid" not in projected and "name" in wlan and is_v6_ssid:
        projected["ssid"] = wlan["name"]
    if "guest" not in projected and "guestNetEnable" in wlan:
        projected["guest"] = bool(wlan["guestNetEnable"])
    if "enabled" not in projected and "broadcast" in wlan:
        projected["enabled"] = bool(wlan["broadcast"])
    if "vlanId" not in projected and isinstance(wlan.get("vlanSetting"), dict):
        vid = wlan["vlanSetting"].get("currentVlanId")
        if vid is not None:
            projected["vlanId"] = vid
    if group_name:
        projected["wlanGroup"] = group_name
    psk_setting = wlan.get("pskSetting")
    has_psk = bool(
        wlan.get("securityKey")
        or (isinstance(psk_setting, dict) and psk_setting.get("securityKey"))
        or wlan.get("ppskSetting")
    )
    projected["hasPresharedKey"] = has_psk
    return projected


# -- tool handlers -----------------------------------------------------------

def _site(client: OmadaClient) -> SiteInfo:
    """Authenticate if needed and return the resolved site (never ``None``)."""
    client.authenticate()
    site = client.site
    if site is None:  # pragma: no cover - authenticate() guarantees a site
        raise OmadaError("site resolution failed", hint="run `omada-mcp --doctor`")
    return site


def _list_devices(client: OmadaClient) -> List[Dict[str, Any]]:
    site = _site(client)
    result = client.api(f"sites/{site.site_id}/devices?currentPage=1&currentPageSize=50")
    if result.get("errorCode") != 0:
        raise OmadaError(f"devices query failed: {result.get('msg', 'unknown')}",
                         code=result.get("errorCode"), endpoint="sites/{id}/devices")
    rows = result.get("result")
    if isinstance(rows, dict):  # some 5.x builds wrap the list
        rows = rows.get("data", [])
    return [project_device(row) for row in (rows or [])]


def _fetch_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    site = _site(client)
    collected: List[Dict[str, Any]] = []
    seen = set()
    for page in range(1, _MAX_CLIENT_PAGES + 1):
        payload = client.api(
            f"sites/{site.site_id}/insight/clients"
            f"?currentPage={page}&currentPageSize=100"
        )
        if payload.get("errorCode") != 0:
            raise OmadaError(
                f"client query failed: {payload.get('msg', 'unknown')}",
                code=payload.get("errorCode"),
                hint="insight/clients needs any role; clients/{mac} needs Admin",
                endpoint="sites/{id}/insight/clients",
            )
        result = payload.get("result") or {}
        rows = result.get("data") or []
        if not rows:
            break
        for row in rows:
            mac = normalize_mac(row.get("mac", ""))
            if mac and mac in seen:
                continue
            seen.add(mac)
            collected.append(project_client(row))
            if limit and len(collected) >= limit:
                return collected
        total = int(result.get("totalRows") or 0)
        if len(collected) >= total:
            break
    return collected


def _list_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    client.authenticate()
    return _fetch_clients(client, limit=limit)


def _list_wifi_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    return [c for c in _list_clients(client, limit=limit) if c.get("wireless")]


def _list_wired_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    return [c for c in _list_clients(client, limit=limit) if not c.get("wireless")]


def _get_device(client: OmadaClient, mac: str) -> Dict[str, Any]:
    wanted = normalize_mac(mac)
    for device in _list_devices(client):
        if normalize_mac(device.get("mac", "")) == wanted or \
                str(device.get("name", "")).lower() == str(mac).strip().lower():
            return device
    raise OmadaError(
        f"no device matches {mac!r}",
        hint="list devices first; the argument accepts a MAC or the device name",
    )


def _get_client(client: OmadaClient, mac: str) -> Dict[str, Any]:
    wanted = normalize_mac(mac)
    needle = str(mac).strip().lower()
    for entry in _fetch_clients(client, limit=0):
        if normalize_mac(entry.get("mac", "")) == wanted:
            return entry
        if needle and needle in (
            str(entry.get("name", "")).lower(),
            str(entry.get("hostName", "")).lower(),
            str(entry.get("ip", "")).lower(),
        ):
            return entry
    raise OmadaError(
        f"no client matches {mac!r}",
        hint="list clients first; the argument accepts a MAC, hostname or IP address",
    )


def _list_wlans(client: OmadaClient) -> List[Dict[str, Any]]:
    site = _site(client)
    result = client.api(f"sites/{site.site_id}/setting/wlans")
    if result.get("errorCode") != 0:
        raise OmadaError(f"WLAN query failed: {result.get('msg', 'unknown')}",
                         code=result.get("errorCode"), endpoint="sites/{id}/setting/wlans")
    payload = result.get("result") or {}
    rows = payload.get("data") if isinstance(payload, dict) else payload
    projected: List[Dict[str, Any]] = []
    for row in (rows or []):
        if any(k in row for k in ("ssid", "band", "security", "securityKey", "pskSetting")):
            projected.append(project_wlan(row))
            continue
        group_id = row.get("id")
        if not group_id:
            projected.append(project_wlan(row))
            continue
        ssids_res = client.api(
            f"sites/{site.site_id}/setting/wlans/{group_id}/ssids"
            "?currentPage=1&currentPageSize=50"
        )
        if ssids_res.get("errorCode") == 0:
            s_payload = ssids_res.get("result") or {}
            s_rows = s_payload.get("data") if isinstance(s_payload, dict) else s_payload
            if s_rows:
                for ssid_row in s_rows:
                    projected.append(project_wlan(ssid_row, group_name=row.get("name")))
                continue
        projected.append(project_wlan(row))
    return projected


def _get_site_info(client: OmadaClient) -> Dict[str, Any]:
    site = _site(client)
    result = client.api(f"sites/{site.site_id}")
    detail = result.get("result") if result.get("errorCode") == 0 else {}
    detail = detail if isinstance(detail, dict) else {}
    devices = _list_devices(client)
    clients = _fetch_clients(client, limit=0)
    wireless = sum(1 for c in clients if c.get("wireless"))
    return {
        "name": detail.get("name") or site.name,
        "id": detail.get("id") or site.site_id,
        "sitesVisible": site.total,
        "wanConnected": bool(detail.get("wan", False)),
        "lanConnected": bool(detail.get("lan", False)),
        "wlanConnected": bool(detail.get("wlan", False)),
        "deviceCount": len(devices),
        "clientCount": len(clients),
        "wifiClientCount": wireless,
        "wiredClientCount": len(clients) - wireless,
        "controllerVersion": getattr(client.auth_info, "controller_version", None),
        "siteUrl": f"{client.config.base_url}/{client.controller_id}/api/v2/sites/{site.site_id}",
    }


def _explain_error(
    _client: OmadaClient,
    code: int,
    endpoint: Optional[str] = None,
) -> Dict[str, Any]:
    return explain_error_code(int(code), endpoint=endpoint)


_ISOLATED_VLAN_KEYWORDS = ("iot", "guest", "kids", "camera", "security", "untrusted", "dmz")
_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _dhcp_pool_capacity(dhcp: Dict[str, Any]) -> int:
    """Total IPv4 addresses across ``dhcpSettings.ipRangePool`` (or start/end fallback)."""
    pools = dhcp.get("ipRangePool") or []
    if not pools and dhcp.get("ipaddrStart") and dhcp.get("ipaddrEnd"):
        pools = [{"ipaddrStart": dhcp.get("ipaddrStart"), "ipaddrEnd": dhcp.get("ipaddrEnd")}]
    total = 0
    for pool in pools:
        start_raw = (pool or {}).get("ipaddrStart")
        end_raw = (pool or {}).get("ipaddrEnd")
        if not start_raw or not end_raw:
            continue
        try:
            start = int(ipaddress.IPv4Address(str(start_raw)))
            end = int(ipaddress.IPv4Address(str(end_raw)))
        except ipaddress.AddressValueError:
            continue
        if end >= start:
            total += end - start + 1
    return total


def _network_audit(client: OmadaClient) -> Dict[str, Any]:
    """Composite, idempotent read-only health audit of the resolved Omada site."""
    site = _site(client)

    site_res = client.api(f"sites/{site.site_id}")
    site_detail = site_res.get("result") if site_res.get("errorCode") == 0 else {}
    site_detail = site_detail if isinstance(site_detail, dict) else {}

    dev_res = client.api(f"sites/{site.site_id}/devices?currentPage=1&currentPageSize=50")
    if dev_res.get("errorCode") != 0:
        raise OmadaError(
            f"devices query failed: {dev_res.get('msg', 'unknown')}",
            code=dev_res.get("errorCode"),
            endpoint="sites/{id}/devices",
        )
    dev_rows = dev_res.get("result")
    if isinstance(dev_rows, dict):
        dev_rows = dev_rows.get("data", [])
    raw_devices: List[Dict[str, Any]] = list(dev_rows or [])

    clients = _fetch_clients(client, limit=0)
    wlans = _list_wlans(client)

    lan_res = client.api(
        f"sites/{site.site_id}/setting/lan/networks?currentPage=1&currentPageSize=50"
    )
    lan_networks: List[Dict[str, Any]] = []
    if lan_res.get("errorCode") == 0:
        lan_payload = lan_res.get("result") or {}
        lan_rows = lan_payload.get("data") if isinstance(lan_payload, dict) else lan_payload
        lan_networks = list(lan_rows or [])

    findings: List[Dict[str, str]] = []

    if "wan" in site_detail and not bool(site_detail.get("wan")):
        findings.append({
            "code": "WAN_DISCONNECTED",
            "severity": "critical",
            "target": site.name,
            "detail": "Site reports WAN disconnected.",
        })

    offline_count = 0
    upgrade_count = 0
    for dev in raw_devices:
        target = str(dev.get("name") or dev.get("mac") or "unknown")
        status_cat = dev.get("statusCategory")
        status_val = dev.get("status")
        is_online = (status_cat == 1) or (status_cat is None and status_val in (1, 14))
        if not is_online:
            offline_count += 1
            findings.append({
                "code": "DEVICE_OFFLINE",
                "severity": "critical",
                "target": target,
                "detail": (f"{dev.get('showModel') or dev.get('model') or dev.get('type') or 'device'} "
                           f"is offline (statusCategory={status_cat}, status={status_val})."),
            })
        if bool(dev.get("needUpgrade")):
            upgrade_count += 1
            findings.append({
                "code": "DEVICE_FIRMWARE_UPGRADE_AVAILABLE",
                "severity": "warning",
                "target": target,
                "detail": (f"Firmware upgrade available (current="
                           f"{dev.get('firmwareVersion') or 'unknown'})."),
            })
        if is_online and str(dev.get("type") or "").lower() == "ap" and int(dev.get("clientNum") or 0) == 0:
            findings.append({
                "code": "AP_ZERO_CLIENTS",
                "severity": "info",
                "target": target,
                "detail": "Online access point currently has 0 associated clients.",
            })

    configured_vlans = {int(n["vlan"]) for n in lan_networks if n.get("vlan") is not None}
    if configured_vlans:
        configured_vlans.add(1)

    clients_by_vlan: Dict[int, int] = {}
    for entry in clients:
        vlan = int(entry.get("vlan") or 0)
        if vlan:
            clients_by_vlan[vlan] = clients_by_vlan.get(vlan, 0) + 1
        target = str(entry.get("name") or entry.get("mac") or "unknown")
        if entry.get("guest"):
            findings.append({
                "code": "CLIENT_ON_GUEST_NETWORK",
                "severity": "info",
                "target": target,
                "detail": f"Client is connected on a guest network (vlan={vlan}).",
            })
        if configured_vlans and vlan > 0 and vlan not in configured_vlans:
            findings.append({
                "code": "CLIENT_UNEXPECTED_VLAN",
                "severity": "warning",
                "target": target,
                "detail": f"Client is on VLAN {vlan}, which is not in configured site LAN networks.",
            })

    dhcp_pools: List[Dict[str, Any]] = []
    for net in lan_networks:
        net_name = str(net.get("name") or net.get("id") or "unknown")
        vlan = int(net.get("vlan") or 0)
        has_acl = bool(net.get("accessControlRule"))
        has_isolation = bool(net.get("isolation"))
        lower_name = net_name.lower()
        if any(kw in lower_name for kw in _ISOLATED_VLAN_KEYWORDS) and not has_acl and not has_isolation:
            findings.append({
                "code": "VLAN_UNISOLATED",
                "severity": "warning",
                "target": net_name,
                "detail": (f"VLAN {vlan} ({net_name}) has accessControlRule=false and "
                           "isolation=false."),
            })
        dhcp = net.get("dhcpSettings") or {}
        if isinstance(dhcp, dict) and dhcp.get("enable"):
            capacity = _dhcp_pool_capacity(dhcp)
            observed = clients_by_vlan.get(vlan, 0)
            util_pct = round(100.0 * observed / capacity, 1) if capacity > 0 else 0.0
            dhcp_pools.append({
                "network": net_name,
                "vlan": vlan,
                "subnet": net.get("gatewaySubnet") or "",
                "poolSize": capacity,
                "observedClients": observed,
                "utilizationPct": util_pct,
            })
            if capacity > 0 and util_pct >= 80.0:
                findings.append({
                    "code": "DHCP_POOL_NEAR_EXHAUSTION",
                    "severity": "critical" if util_pct >= 95.0 else "warning",
                    "target": net_name,
                    "detail": (f"VLAN {vlan} DHCP pool utilization is {util_pct}% "
                               f"({observed}/{capacity} addresses)."),
                })

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["code"], f["target"]))
    dhcp_pools.sort(key=lambda p: (p["vlan"], p["network"]))

    return {
        "healthy": not any(f["severity"] in ("critical", "warning") for f in findings),
        "controller": {
            "id": client.controller_id,
            "version": getattr(client.auth_info, "controller_version", None),
            "family": getattr(client.auth_info, "controller_family", None),
        },
        "site": {
            "id": site.site_id,
            "name": site.name,
            "wanConnected": bool(site_detail.get("wan", False)),
            "lanConnected": bool(site_detail.get("lan", False)),
            "wlanConnected": bool(site_detail.get("wlan", False)),
        },
        "counts": {
            "devices": len(raw_devices),
            "offlineDevices": offline_count,
            "upgradePendingDevices": upgrade_count,
            "clients": len(clients),
            "wifiClients": sum(1 for c in clients if c.get("wireless")),
            "wiredClients": sum(1 for c in clients if not c.get("wireless")),
            "wlans": len(wlans),
            "lanNetworks": len(lan_networks),
            "findings": len(findings),
        },
        "dhcpPools": dhcp_pools,
        "findings": findings,
    }


# -- registry ----------------------------------------------------------------

def _list_output_schema(item_schema: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "items": {"type": "array", "items": item_schema},
            "count": {"type": "integer", "minimum": 0},
        },
        "required": ["items", "count"],
    }


_DEVICE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "type": {"type": "string"},
        "model": {"type": "string"},
        "ip": {"type": "string"},
        "firmware": {"type": "string"},
        "uptime": {"type": ["string", "integer"]},
        "clientCount": {"type": "integer"},
        "status": {"type": "integer"},
        "needUpgrade": {"type": "boolean"},
    },
    "required": [
        "mac", "name", "type", "model", "ip",
        "firmware", "uptime", "clientCount", "status", "needUpgrade",
    ],
}

_CLIENT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "hostName": {"type": "string"},
        "ip": {"type": "string"},
        "wireless": {"type": "boolean"},
        "guest": {"type": "boolean"},
        "active": {"type": "boolean"},
        "ssid": {"type": "string"},
        "apName": {"type": "string"},
        "networkName": {"type": "string"},
        "vlan": {"type": "integer"},
        "download": {"type": "integer"},
        "upload": {"type": "integer"},
        "duration": {"type": "integer"},
        "lastSeen": {"type": "string"},
        "signal": {"type": ["integer", "number", "null"]},
    },
    "required": [
        "mac", "name", "hostName", "ip", "wireless", "guest", "active",
        "ssid", "apName", "networkName", "vlan", "download", "upload",
        "duration", "lastSeen", "signal",
    ],
}

_WLAN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "ssid": {"type": "string"},
        "band": {"type": ["integer", "string"]},
        "enabled": {"type": "boolean"},
        "guest": {"type": "boolean"},
        "security": {"type": ["integer", "string"]},
        "vlanId": {"type": ["integer", "null"]},
        "networkName": {"type": "string"},
        "hideSsid": {"type": "boolean"},
        "macFilterEnable": {"type": "boolean"},
        "rateLimitEnable": {"type": "boolean"},
        "wlanGroup": {"type": "string"},
        "hasPresharedKey": {"type": "boolean"},
    },
    "required": ["hasPresharedKey"],
}

_SITE_INFO_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "id": {"type": "string"},
        "sitesVisible": {"type": "integer"},
        "wanConnected": {"type": "boolean"},
        "lanConnected": {"type": "boolean"},
        "wlanConnected": {"type": "boolean"},
        "deviceCount": {"type": "integer"},
        "clientCount": {"type": "integer"},
        "wifiClientCount": {"type": "integer"},
        "wiredClientCount": {"type": "integer"},
        "controllerVersion": {"type": ["string", "null"]},
        "siteUrl": {"type": "string"},
    },
    "required": [
        "name", "id", "sitesVisible", "wanConnected", "lanConnected",
        "wlanConnected", "deviceCount", "clientCount", "wifiClientCount",
        "wiredClientCount", "controllerVersion", "siteUrl",
    ],
}

_NETWORK_AUDIT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "healthy": {"type": "boolean"},
        "controller": {
            "type": "object",
            "properties": {
                "id": {"type": ["string", "null"]},
                "version": {"type": ["string", "null"]},
                "family": {"type": ["string", "null"]},
            },
            "required": ["id", "version", "family"],
        },
        "site": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "wanConnected": {"type": "boolean"},
                "lanConnected": {"type": "boolean"},
                "wlanConnected": {"type": "boolean"},
            },
            "required": ["id", "name", "wanConnected", "lanConnected", "wlanConnected"],
        },
        "counts": {
            "type": "object",
            "properties": {
                "devices": {"type": "integer"},
                "offlineDevices": {"type": "integer"},
                "upgradePendingDevices": {"type": "integer"},
                "clients": {"type": "integer"},
                "wifiClients": {"type": "integer"},
                "wiredClients": {"type": "integer"},
                "wlans": {"type": "integer"},
                "lanNetworks": {"type": "integer"},
                "findings": {"type": "integer"},
            },
            "required": [
                "devices", "offlineDevices", "upgradePendingDevices",
                "clients", "wifiClients", "wiredClients",
                "wlans", "lanNetworks", "findings",
            ],
        },
        "dhcpPools": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "network": {"type": "string"},
                    "vlan": {"type": "integer"},
                    "subnet": {"type": "string"},
                    "poolSize": {"type": "integer"},
                    "observedClients": {"type": "integer"},
                    "utilizationPct": {"type": "number"},
                },
                "required": [
                    "network", "vlan", "subnet", "poolSize",
                    "observedClients", "utilizationPct",
                ],
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "severity": {"type": "string"},
                    "target": {"type": "string"},
                    "detail": {"type": "string"},
                },
                "required": ["code", "severity", "target", "detail"],
            },
        },
    },
    "required": ["healthy", "controller", "site", "counts", "dhcpPools", "findings"],
}

_EXPLAIN_ERROR_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "code": {"type": "integer"},
        "known": {"type": "boolean"},
        "title": {"type": "string"},
        "meaning": {"type": "string"},
        "fix": {"type": "string"},
        "ambiguous": {"type": "boolean"},
        "causes": {"type": "array", "items": {"type": "string"}},
        "endpointContext": {"type": ["string", "null"]},
        "summary": {"type": "string"},
    },
    "required": [
        "code", "known", "title", "meaning", "fix",
        "ambiguous", "causes", "endpointContext", "summary",
    ],
}


@dataclass(frozen=True)
class Tool:
    """A tool plus the MCP annotations and outputSchema describing it."""

    name: str
    title: str
    description: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    handler: Callable[..., Any]
    read_only: bool = True
    destructive: bool = False
    idempotent: bool = True
    open_world: bool = True
    requires_auth: bool = True

    def descriptor(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": self.open_world,
            },
        }


_EMPTY: Dict[str, Any] = {"type": "object", "properties": {}}
_LIMIT_PROP = {
    "type": "integer",
    "minimum": 1,
    "maximum": 5000,
    "default": 500,
    "description": "Maximum number of clients to return (default 500, max 5000)",
}

_SNAPSHOT_DEFAULT_OBJECTS: Tuple[str, ...] = ("networks", "acls", "groups", "wlans", "devices")
_SNAPSHOT_ALL_OBJECTS: Tuple[str, ...] = (
    "networks", "acls", "groups", "wlans", "devices", "clients",
)

_SNAPSHOT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "site": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "id": {"type": "string"},
            },
            "required": ["name", "id"],
        },
        "objects": {"type": "array", "items": {"type": "string"}},
        "networks": {"type": "array", "items": {"type": "object"}},
        "acls": {
            "type": "object",
            "properties": {
                "aclDisable": {"type": ["boolean", "null"]},
                "aclDisableReliable": {"type": "boolean"},
                "warning": {"type": "string"},
                "count": {"type": "integer"},
                "rules": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["aclDisable", "aclDisableReliable", "warning", "count", "rules"],
        },
        "groups": {
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
                "ipGroups": {"type": "array", "items": {"type": "object"}},
                "otherGroups": {"type": "array", "items": {"type": "object"}},
                "all": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["count", "ipGroups", "otherGroups", "all"],
        },
        "wlans": {"type": "array", "items": {"type": "object"}},
        "devices": {"type": "array", "items": {"type": "object"}},
        "clients": {"type": "array", "items": {"type": "object"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["site", "objects", "warnings"],
}

_WRITE_CONTROL_PROPS: Dict[str, Any] = {
    "dryRun": {
        "type": "boolean",
        "default": True,
        "description": (
            "Preview the exact before/after diff and obtain confirmToken without changing the "
            "controller (default true; pass dryRun=false with confirm='<tool>:<target>' to apply)"
        ),
    },
    "confirm": {
        "type": "string",
        "description": (
            "Confirmation token formatted '<tool>:<target-id>', required when dryRun is false; "
            "run with dryRun=true first to inspect the diff and obtain confirmToken"
        ),
    },
}


def _parse_group_type(group: Dict[str, Any]) -> Optional[int]:
    raw = group.get("type")
    if raw is None or isinstance(raw, bool):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _get_config_snapshot(
    client: OmadaClient,
    objects: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Read-only snapshot merging two-endpoint LAN data, ACLs, groups, WLANs, and devices."""
    if objects is None:
        selected = list(_SNAPSHOT_DEFAULT_OBJECTS)
    else:
        if not isinstance(objects, list):
            raise OmadaError("objects must be an array of snapshot section names")
        selected = []
        seen = set()
        for raw in objects:
            name = str(raw or "").strip().lower()
            if not name:
                raise OmadaError("objects contains an empty entry")
            if name not in _SNAPSHOT_ALL_OBJECTS:
                raise OmadaError(
                    f"unknown snapshot object {name!r}",
                    hint="valid objects: " + ", ".join(_SNAPSHOT_ALL_OBJECTS),
                )
            if name not in seen:
                seen.add(name)
                selected.append(name)
        if not selected:
            raise OmadaError(
                "objects must not be empty",
                hint="omit objects for default snapshot ("
                     + ", ".join(_SNAPSHOT_DEFAULT_OBJECTS) + ")",
            )

    site = _site(client)
    warnings: List[str] = []
    snapshot: Dict[str, Any] = {
        "site": {"name": site.name, "id": site.site_id},
        "objects": selected,
        "warnings": warnings,
    }

    if "networks" in selected:
        collection = _fetch_lan_collection(client, site)
        interfaces = _fetch_lan_interfaces(client, site)
        iface_by_id = {
            str(item.get("id")): item for item in interfaces if item.get("id") is not None
        }
        col_ids = set()
        merged_networks: List[Dict[str, Any]] = []
        for col_item in collection:
            nid = str(col_item.get("id") or "")
            if nid:
                col_ids.add(nid)
            iface_item = iface_by_id.get(nid)
            base = iface_item if iface_item is not None else col_item
            merged_networks.append({
                "id": nid,
                "name": base.get("name", ""),
                "vlan": base.get("vlan"),
                "purpose": col_item.get("purpose"),
                "gatewaySubnet": base.get("gatewaySubnet"),
                "isolation": col_item.get("isolation"),
                "interfaceIsolation": (
                    iface_item.get("isolation") if iface_item is not None else None
                ),
                "existNetworkIsolation": col_item.get("existNetworkIsolation"),
                "accessControlRule": col_item.get("accessControlRule"),
                "dhcpSettings": base.get("dhcpSettings"),
                "collection": col_item,
                "interface": iface_item,
            })
        for iface_item in interfaces:
            nid = str(iface_item.get("id") or "")
            if nid not in col_ids:
                merged_networks.append({
                    "id": nid,
                    "name": iface_item.get("name", ""),
                    "vlan": iface_item.get("vlan"),
                    "purpose": None,
                    "gatewaySubnet": iface_item.get("gatewaySubnet"),
                    "isolation": iface_item.get("isolation"),
                    "interfaceIsolation": iface_item.get("isolation"),
                    "existNetworkIsolation": None,
                    "accessControlRule": None,
                    "dhcpSettings": iface_item.get("dhcpSettings"),
                    "collection": None,
                    "interface": iface_item,
                })
        snapshot["networks"] = merged_networks

    if "acls" in selected:
        acl_disable, rules = _fetch_acls(client, site)
        warnings.append(_ACL_DISPATCH_NOTES)
        snapshot["acls"] = {
            "aclDisable": acl_disable,
            "aclDisableReliable": False,
            "warning": _ACL_DISPATCH_NOTES,
            "count": len(rules),
            "rules": rules,
        }

    if "groups" in selected:
        groups = _fetch_groups(client, site)
        ip_groups = [g for g in groups if _parse_group_type(g) == 0]
        other_groups = [g for g in groups if _parse_group_type(g) != 0]
        snapshot["groups"] = {
            "count": len(groups),
            "ipGroups": ip_groups,
            "otherGroups": other_groups,
            "all": groups,
        }

    if "wlans" in selected:
        snapshot["wlans"] = _list_wlans(client)

    if "devices" in selected:
        snapshot["devices"] = _list_devices(client)

    if "clients" in selected:
        snapshot["clients"] = _fetch_clients(client, limit=0)

    return snapshot

TOOLS: Tuple[Tool, ...] = (
    Tool(
        name="list_devices",
        title="List Omada devices",
        description=("List all managed network devices (APs, switches, gateways) on the site "
                    "with MAC, model, firmware, IP, uptime and client count."),
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_DEVICE_SCHEMA),
        handler=_list_devices,
    ),
    Tool(
        name="list_clients",
        title="List clients",
        description=("List connected clients (WiFi and wired) with MAC, IP, SSID, AP, VLAN, "
                    "traffic counters, session duration and last-seen time."),
        input_schema={"type": "object", "properties": {"limit": _LIMIT_PROP}},
        output_schema=_list_output_schema(_CLIENT_SCHEMA),
        handler=_list_clients,
    ),
    Tool(
        name="list_wifi_clients",
        title="List WiFi clients",
        description="List only wireless clients, same fields as list_clients.",
        input_schema={"type": "object", "properties": {"limit": _LIMIT_PROP}},
        output_schema=_list_output_schema(_CLIENT_SCHEMA),
        handler=_list_wifi_clients,
    ),
    Tool(
        name="list_wired_clients",
        title="List wired clients",
        description="List only wired clients, same fields as list_clients.",
        input_schema={"type": "object", "properties": {"limit": _LIMIT_PROP}},
        output_schema=_list_output_schema(_CLIENT_SCHEMA),
        handler=_list_wired_clients,
    ),
    Tool(
        name="get_device",
        title="Get device",
        description="Get one device by MAC address or device name.",
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string",
                        "description": "Device MAC (any format) or device name"},
            },
            "required": ["mac"],
        },
        output_schema=_DEVICE_SCHEMA,
        handler=_get_device,
    ),
    Tool(
        name="get_client",
        title="Get client",
        description="Get one client by MAC address, hostname or IP address.",
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string",
                        "description": "Client MAC (any format), hostname or IP address"},
            },
            "required": ["mac"],
        },
        output_schema=_CLIENT_SCHEMA,
        handler=_get_client,
    ),
    Tool(
        name="list_wlans",
        title="List WLANs",
        description=("List configured WLANs/SSIDs with band, VLAN, security type and guest "
                    "flag. Pre-shared keys are never returned; a boolean "
                    "hasPresharedKey reports whether one is set."),
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_WLAN_SCHEMA),
        handler=_list_wlans,
    ),
    Tool(
        name="get_site_info",
        title="Get site summary",
        description=("Site summary: name, id, WAN/LAN/WLAN state, device and client counts, "
                    "controller version."),
        input_schema=_EMPTY,
        output_schema=_SITE_INFO_SCHEMA,
        handler=_get_site_info,
    ),
    Tool(
        name="network_audit",
        title="Audit site network health",
        description=("One-call read-only health audit checking WAN state, offline devices, "
                    "pending firmware upgrades, 0-client APs, guest/unexpected VLAN clients, "
                    "unisolated VLANs, and DHCP pool utilization with stable finding codes."),
        input_schema=_EMPTY,
        output_schema=_NETWORK_AUDIT_SCHEMA,
        handler=_network_audit,
    ),
    Tool(
        name="explain_error",
        title="Explain Omada errorCode",
        description=("Decode an Omada Web API errorCode (e.g. -1600, -33717, -33726, -1505, -1001, "
                    "-30109, -41011, -44116) into its meaning, ambiguity notes, and fix."),
        input_schema={
            "type": "object",
            "properties": {
                "code": {"type": "integer",
                         "description": "Numeric Omada errorCode to explain (e.g. -1600, -33726)"},
                "endpoint": {"type": "string",
                             "description": "Optional API endpoint where the error occurred"},
            },
            "required": ["code"],
        },
        output_schema=_EXPLAIN_ERROR_SCHEMA,
        handler=_explain_error,
        open_world=False,
        requires_auth=False,
    ),
    Tool(
        name="get_config_snapshot",
        title="Get site configuration snapshot",
        description=(
            "Read-only snapshot of LAN networks (both collection and /interface endpoints), "
            "gateway ACLs, IP/port groups, PSK-redacted WLANs, devices, and optional clients."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "objects": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(_SNAPSHOT_ALL_OBJECTS)},
                    "description": (
                        "Optional subset of sections to fetch: networks, acls, groups, wlans, "
                        "devices, clients (defaults to all except clients)"
                    ),
                },
            },
        },
        output_schema=_SNAPSHOT_SCHEMA,
        handler=_get_config_snapshot,
    ),
    Tool(
        name="set_client_fixed_ip",
        title="Set client DHCP reservation",
        description=(
            "Assign a DHCP fixed IPv4 reservation on a client (PATCH clients/{MAC}). "
            "Lease-delayed; strips volatile keys and refuses managed device MACs (-41011). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC address"},
                "ip": {"type": "string", "description": "Fixed IPv4 address within target VLAN"},
                "vlan": {"type": "integer", "description": "Optional VLAN ID to resolve netId"},
                "netId": {"type": "string", "description": "Optional LAN network ID"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "ip"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_client_fixed_ip,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="release_client_fixed_ip",
        title="Release client DHCP reservation",
        description=(
            "Clear useFixedAddr on a client (PATCH clients/{MAC}). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC address"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=release_client_fixed_ip,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="set_vlan_dhcp_pools",
        title="Set VLAN DHCP pools",
        description=(
            "Update dhcpSettings.ipRangePool on a LAN/VLAN via full /interface PATCH with "
            "two-endpoint verification and controller/device overlap guards. "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "pools": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ipaddrStart": {"type": "string"},
                            "ipaddrEnd": {"type": "string"},
                        },
                        "required": ["ipaddrStart", "ipaddrEnd"],
                    },
                    "description": "Non-empty list of {ipaddrStart, ipaddrEnd} DHCP pools",
                },
                "vlan": {"type": "integer", "description": "Target VLAN ID (or provide netId)"},
                "netId": {"type": "string", "description": "Target LAN network ID (or provide vlan)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["pools"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_vlan_dhcp_pools,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="set_vlan_isolation",
        title="Set VLAN isolation",
        description=(
            "Toggle client/network isolation on a LAN/VLAN via the /interface endpoint and "
            "verify across both setting/lan/networks and setting/lan/networks/interface. "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "isolation": {
                    "type": "boolean",
                    "description": "True to enable VLAN isolation, false to disable",
                },
                "vlan": {"type": "integer", "description": "Target VLAN ID (or provide netId)"},
                "netId": {"type": "string", "description": "Target LAN network ID (or provide vlan)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["isolation"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_vlan_isolation,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="create_ip_group",
        title="Create IPv4 IP group",
        description=(
            "Create an IPv4 IP profile group (type=0), packing ranges into <=16 aligned CIDRs "
            "(-33726). Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique IPv4 IP group name"},
                "cidrs": {
                    "type": "array",
                    "description": "List of IPv4 CIDRs, IPs, ranges, or {ip, mask} objects",
                },
                "ipRange": {
                    "type": "string",
                    "description": "Optional comma-separated IPv4 ranges/CIDRs (e.g. '192.168.20.180-199')",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_ip_group,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="replace_ip_group",
        title="Replace IPv4 IP group",
        description=(
            "Replace an IPv4 IP group via delete+recreate, automatically running the 6-step "
            "temporary-group swap when ACL rules reference the group (-33717). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "group": {"type": "string", "description": "IP group ID or exact name"},
                "cidrs": {
                    "type": "array",
                    "description": "Replacement IPv4 CIDRs, IPs, ranges, or {ip, mask} objects",
                },
                "ipRange": {
                    "type": "string",
                    "description": "Replacement comma-separated IPv4 ranges/CIDRs",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["group"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=replace_ip_group,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="create_gateway_acl",
        title="Create gateway ACL rule",
        description=(
            "Create a gateway ACL rule (POST setting/firewall/acls?type=0) with anti-stranding "
            "checks for management hosts. Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique gateway ACL rule name"},
                "policy": {
                    "type": ["string", "integer"],
                    "description": "Rule policy: 'deny' (0) or 'permit' (1)",
                },
                "source": {
                    "type": "object",
                    "properties": {
                        "type": {"type": ["string", "integer"]},
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "Source selector: {'type': 'network'|'ip_group'|'port_group'|0|1|2, 'ids': [...]}",
                },
                "destination": {
                    "type": "object",
                    "properties": {
                        "type": {"type": ["string", "integer"]},
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "Destination selector: {'type': 'network'|'ip_group'|'port_group'|0|1|2, 'ids': [...]}",
                },
                "direction": {
                    "type": "object",
                    "properties": {
                        "lanToWan": {"type": "boolean"},
                        "lanToLan": {"type": "boolean"},
                        "wanInIds": {"type": "array", "items": {"type": "string"}},
                        "vpnInIds": {"type": "array", "items": {"type": "string"}},
                    },
                    "description": "Direction flags (at least one enabled, e.g. {'lanToWan': true, 'lanToLan': false})",
                },
                "status": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable rule immediately (default true)",
                },
                "protocols": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Protocol codes (default [256] for any)",
                },
                "biDirectional": {
                    "type": "boolean",
                    "default": False,
                    "description": "Apply rule in both directions (default false)",
                },
                "syslog": {
                    "type": "boolean",
                    "default": False,
                    "description": "Log matching packets to syslog (default false)",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "policy", "source", "destination", "direction"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_gateway_acl,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="set_acl_rule_status",
        title="Enable or disable gateway ACL rule",
        description=(
            "Toggle a single gateway ACL rule status (PATCH setting/firewall/acls/{id}?type=0); "
            "never relies on or flips aclDisable. Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "Gateway ACL rule ID or exact name"},
                "status": {"type": "boolean", "description": "True to enable, false to disable"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule", "status"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_acl_rule_status,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
)

TOOL_MAP: Dict[str, Tool] = {tool.name: tool for tool in TOOLS}


def get_tool(name: str) -> Optional[Tool]:
    return TOOL_MAP.get(str(name or ""))


def tool_descriptors(
    config: Optional[Config] = None,
    include_all: bool = False,
    write_tools: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    if include_all:
        return [tool.descriptor() for tool in TOOLS]
    enabled_writes = set()
    if config is not None:
        if not config.read_only:
            enabled_writes = set(config.write_tools)
    elif write_tools is not None:
        enabled_writes = set(write_tools)
    return [
        tool.descriptor()
        for tool in TOOLS
        if tool.read_only or tool.name in enabled_writes
    ]
