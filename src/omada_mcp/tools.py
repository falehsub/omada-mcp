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

The server enforces ``OMADA_READ_ONLY=true`` in the dispatcher for any tool
not declared read-only, gates writes behind ``OMADA_WRITE_TOOLS`` plus
``dryRun`` previews and confirmation tokens, and pairs every tool with a typed
``outputSchema``.
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .client import OmadaClient, OmadaError, SiteInfo, explain_error_code, redact_secrets
from .config import Config
from .write_tools import (
    WRITE_ENVELOPE_SCHEMA,
    _ACL_DISPATCH_NOTES,
    _fetch_acls,
    _fetch_clients_filtered,
    _fetch_devices,
    _fetch_dhcp_reservations,
    _fetch_groups,
    _fetch_insight_clients,
    _fetch_lan_collection,
    _fetch_lan_interfaces,
    _fetch_mdns_profiles,
    _fetch_mdns_rules,
    _fetch_port_forwards,
    _fetch_ssids,
    _fetch_static_routes,
    _fetch_wan_networks,
    create_gateway_acl,
    create_ip_group,
    create_lan_network,
    create_ssid,
    delete_dhcp_reservation,
    delete_gateway_acl,
    delete_ip_group,
    delete_lan_network,
    delete_mdns_rule,
    delete_port_forward,
    delete_ssid,
    delete_static_route,
    reboot_device,
    reconnect_client,
    release_client_fixed_ip,
    replace_ip_group,
    set_acl_rule_status,
    set_client_blocked,
    set_client_fixed_ip,
    set_upnp,
    set_vlan_dhcp_pools,
    set_vlan_isolation,
    update_client,
    update_device,
    update_gateway_acl,
    update_lan_network,
    update_ssid,
    upsert_dhcp_reservation,
    upsert_mdns_rule,
    upsert_port_forward,
    upsert_static_route,
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


def _as_int(value: Any, default: int = 0) -> int:
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def project_client(client: Dict[str, Any]) -> Dict[str, Any]:
    """Client projection, including the fields an admin actually asks for."""
    wireless = bool(client.get("wireless"))
    return {
        "mac": str(client.get("mac") or ""),
        "name": str(_pick(client, "name", "hostName", default="") or ""),
        "hostName": str(client.get("hostName") or ""),
        "ip": str(client.get("ip") or ""),
        "wireless": wireless,
        "guest": bool(client.get("guest")),
        "active": bool(client.get("active", True)),
        "ssid": str(client.get("ssid") or ""),
        "apName": str(_pick(client, "apName", "switchName", default="") or ""),
        "networkName": str(_pick(client, "networkName", "network", default="") or ""),
        "vlan": _as_int(_pick(client, "vid", "vlan", default=0), 0),
        "download": _as_int(client.get("download"), 0),
        "upload": _as_int(client.get("upload"), 0),
        "duration": _as_int(client.get("duration"), 0),
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
        vlan_cfg = wlan["vlanSetting"]
        vid = vlan_cfg.get("currentVlanId")
        if vid is None and isinstance(vlan_cfg.get("customConfig"), dict):
            vid = vlan_cfg["customConfig"].get("bridgeVlan")
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
    rows = _fetch_devices(client, site)
    return [project_device(row) for row in rows]


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
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/wlans")
    projected: List[Dict[str, Any]] = []
    for row in rows:
        if any(k in row for k in ("ssid", "band", "security", "securityKey", "pskSetting")):
            projected.append(project_wlan(row))
            continue
        group_id = row.get("id")
        if not group_id:
            projected.append(project_wlan(row))
            continue
        try:
            s_rows = _fetch_ssids(client, site, str(group_id))
        except OmadaError:
            s_rows = []
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

    raw_devices: List[Dict[str, Any]] = _fetch_devices(client, site)

    clients = _fetch_clients(client, limit=0)
    wlans = _list_wlans(client)

    lan_networks: List[Dict[str, Any]] = []
    try:
        lan_networks = _fetch_lan_collection(client, site)
    except OmadaError:
        lan_networks = []

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
    "dhcpReservations", "portForwards", "staticRoutes", "mdnsRules", "services",
)
_SNAPSHOT_OBJECT_CANONICAL: Dict[str, str] = {name.lower(): name for name in _SNAPSHOT_ALL_OBJECTS}

_SEARCH_CLIENT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        **_CLIENT_SCHEMA["properties"],
        "blocked": {"type": "boolean"},
        "fixedIp": {"type": "string"},
        "fixedNetId": {"type": "string"},
    },
    "required": list(_CLIENT_SCHEMA["required"]),
}

_LAN_NETWORK_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "vlan": {"type": ["integer", "null"]},
        "purpose": {"type": ["string", "null"]},
        "gatewaySubnet": {"type": ["string", "null"]},
        "isolation": {"type": ["boolean", "null"]},
        "interfaceIsolation": {"type": ["boolean", "null"]},
        "existNetworkIsolation": {"type": ["boolean", "null"]},
        "accessControlRule": {"type": ["boolean", "null"]},
        "dhcpEnabled": {"type": "boolean"},
        "dhcpPools": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "start": {"type": "string"},
                    "end": {"type": "string"},
                },
            },
        },
        "leaseTime": {"type": ["integer", "null"]},
        "domain": {"type": ["string", "null"]},
        "igmpSnoopEnable": {"type": ["boolean", "null"]},
    },
    "required": ["id", "name", "vlan", "dhcpEnabled", "dhcpPools"],
}

_DHCP_RES_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "mac": {"type": "string"},
        "ip": {"type": "string"},
        "netId": {"type": "string"},
        "networkName": {"type": "string"},
        "vlan": {"type": ["integer", "null"]},
        "description": {"type": "string"},
        "clientName": {"type": "string"},
        "status": {"type": "boolean"},
        "exportToIpMacBinding": {"type": "boolean"},
        "expired": {"type": ["integer", "boolean", "null"]},
    },
    "required": ["mac", "ip", "netId", "status"],
}

_ACL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "index": {"type": ["integer", "null"]},
        "name": {"type": "string"},
        "status": {"type": "boolean"},
        "policy": {"type": ["integer", "string"]},
        "policyLabel": {"type": "string"},
        "sourceType": {"type": ["integer", "string", "null"]},
        "sourceIds": {"type": "array", "items": {"type": "string"}},
        "destinationType": {"type": ["integer", "string", "null"]},
        "destinationIds": {"type": "array", "items": {"type": "string"}},
        "direction": {"type": ["object", "null"]},
        "protocols": {"type": "array", "items": {"type": ["integer", "string"]}},
        "biDirectional": {"type": "boolean"},
        "syslog": {"type": "boolean"},
    },
    "required": ["id", "name", "status", "policy", "sourceIds", "destinationIds"],
}

_IP_GROUP_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "type": {"type": ["integer", "null"]},
        "typeLabel": {"type": "string"},
        "entryCount": {"type": "integer"},
        "ipList": {"type": "array", "items": {"type": ["object", "string"]}},
        "referencedByAcls": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                },
            },
        },
    },
    "required": ["id", "name", "type", "entryCount"],
}

_PORT_FORWARD_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "status": {"type": "boolean"},
        "externalPort": {"type": "string"},
        "forwardIp": {"type": "string"},
        "forwardPort": {"type": "string"},
        "protocol": {"type": ["integer", "string"]},
        "from": {"type": ["integer", "string", "null"]},
        "limitedAddresses": {"type": "array", "items": {"type": "string"}},
        "interfaceWanPortId": {"type": "array", "items": {"type": "string"}},
        "dmz": {"type": "boolean"},
    },
    "required": ["id", "name", "status", "externalPort", "forwardIp", "forwardPort"],
}

_STATIC_ROUTE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "status": {"type": "boolean"},
        "routeType": {"type": ["integer", "null"]},
        "destinations": {"type": "array", "items": {"type": "string"}},
        "nextHopIp": {"type": "string"},
        "interfaceId": {"type": "string"},
        "metric": {"type": ["integer", "null"]},
    },
    "required": ["id", "name", "status", "destinations", "nextHopIp"],
}

_SERVICES_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "upnp": {"type": ["object", "null"]},
        "dnsProxy": {"type": ["object", "null"]},
        "mdns": {
            "type": "object",
            "properties": {
                "ruleCount": {"type": "integer"},
                "rules": {"type": "array", "items": {"type": "object"}},
                "profileCount": {"type": "integer"},
                "profiles": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["ruleCount", "rules", "profileCount", "profiles"],
        },
        "ddns": {"type": ["object", "null"]},
        "wan": {"type": ["object", "null"]},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["upnp", "dnsProxy", "mdns", "ddns", "wan", "warnings"],
}

_LOG_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "category": {"type": "string"},
        "time": {"type": "string"},
        "level": {"type": ["integer", "string", "null"]},
        "type": {"type": ["integer", "string", "null"]},
        "module": {"type": ["integer", "string", "null"]},
        "content": {"type": "string"},
        "target": {"type": "string"},
        "resolved": {"type": "boolean"},
    },
    "required": ["id", "category", "time", "content"],
}

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
        "dhcpReservations": {"type": "array", "items": _DHCP_RES_SCHEMA},
        "portForwards": {"type": "array", "items": _PORT_FORWARD_SCHEMA},
        "staticRoutes": {"type": "array", "items": _STATIC_ROUTE_SCHEMA},
        "mdnsRules": {"type": "array", "items": {"type": "object"}},
        "services": _SERVICES_SCHEMA,
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


def _extract_dhcp_pools(dhcp: Any) -> List[Dict[str, str]]:
    if not isinstance(dhcp, dict):
        return []
    pools: List[Dict[str, str]] = []
    raw_pool = dhcp.get("ipRangePool")
    if isinstance(raw_pool, list):
        for entry in raw_pool:
            if not isinstance(entry, dict):
                continue
            start = entry.get("ipaddrStart") or entry.get("start")
            end = entry.get("ipaddrEnd") or entry.get("end")
            if start or end:
                pools.append({
                    "start": str(start or ""),
                    "end": str(end or ""),
                })
    if not pools:
        fb_start = dhcp.get("ipaddrStart") or (
            dhcp.get("ipRangeStart") if isinstance(dhcp.get("ipRangeStart"), str) else ""
        )
        fb_end = dhcp.get("ipaddrEnd") or (
            dhcp.get("ipRangeEnd") if isinstance(dhcp.get("ipRangeEnd"), str) else ""
        )
        if fb_start or fb_end:
            pools.append({
                "start": str(fb_start or ""),
                "end": str(fb_end or ""),
            })
    return pools


def _merge_lan_networks(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    collection = _fetch_lan_collection(client, site)
    try:
        interfaces = _fetch_lan_interfaces(client, site)
    except OmadaError as exc:
        if exc.code == -1600:
            interfaces = []
        else:
            raise
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
            "name": str(base.get("name") or ""),
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
                "name": str(iface_item.get("name") or ""),
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
    return merged_networks


def _project_lan_network(merged: Dict[str, Any]) -> Dict[str, Any]:
    iface = merged.get("interface") or merged.get("collection") or {}
    dhcp = merged.get("dhcpSettings") if isinstance(merged.get("dhcpSettings"), dict) else {}
    lease = dhcp.get("leasetime") if dhcp.get("leasetime") is not None else dhcp.get("leaseTime")
    domain = (
        iface.get("domain")
        if isinstance(iface.get("domain"), str)
        else (dhcp.get("domain") if isinstance(dhcp.get("domain"), str) else None)
    )
    return {
        "id": str(merged.get("id") or ""),
        "name": str(merged.get("name") or ""),
        "vlan": _as_int(merged.get("vlan"), 0) if merged.get("vlan") is not None else None,
        "purpose": merged.get("purpose"),
        "gatewaySubnet": merged.get("gatewaySubnet"),
        "isolation": merged.get("isolation"),
        "interfaceIsolation": merged.get("interfaceIsolation"),
        "existNetworkIsolation": merged.get("existNetworkIsolation"),
        "accessControlRule": merged.get("accessControlRule"),
        "dhcpEnabled": bool(dhcp.get("enable", False)),
        "dhcpPools": _extract_dhcp_pools(dhcp),
        "leaseTime": _as_int(lease, 0) if lease is not None else None,
        "domain": domain,
        "igmpSnoopEnable": (
            bool(iface.get("igmpSnoopEnable")) if "igmpSnoopEnable" in iface else None
        ),
    }


def _project_dhcp_reservation(
    row: Dict[str, Any],
    net_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    net_id = str(row.get("netId") or "")
    net = (net_by_id or {}).get(net_id, {})
    raw_vlan = row.get("vlan", net.get("vlan"))
    return {
        "id": str(row.get("id") or ""),
        "mac": str(row.get("mac") or ""),
        "ip": str(row.get("ip") or ""),
        "netId": net_id,
        "networkName": str(row.get("networkName") or net.get("name") or ""),
        "vlan": _as_int(raw_vlan, 0) if raw_vlan is not None else None,
        "description": str(row.get("description") or ""),
        "clientName": str(row.get("clientName") or row.get("name") or ""),
        "status": bool(row.get("status", True)),
        "exportToIpMacBinding": bool(row.get("exportToIpMacBinding", False)),
        "expired": row.get("expired"),
    }


def _project_acl_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    raw_policy = rule.get("policy")
    policy_label = {0: "deny", 1: "permit"}.get(raw_policy, str(raw_policy))
    src_ids = rule.get("sourceIds") if rule.get("sourceIds") is not None else rule.get("sourceFilter")
    dst_ids = rule.get("destinationIds") if rule.get("destinationIds") is not None else rule.get("destinationFilter")
    protocols = rule.get("protocols") if rule.get("protocols") is not None else rule.get("protocol")
    if isinstance(protocols, (int, str)):
        proto_list: List[Any] = [protocols]
    elif isinstance(protocols, list):
        proto_list = list(protocols)
    else:
        proto_list = []
    return {
        "id": str(rule.get("id") or ""),
        "index": _as_int(rule.get("index"), 0) if rule.get("index") is not None else None,
        "name": str(rule.get("name") or ""),
        "status": bool(rule.get("status", False)),
        "policy": raw_policy if raw_policy is not None else 0,
        "policyLabel": policy_label,
        "sourceType": rule.get("sourceType"),
        "sourceIds": [str(x) for x in (src_ids or [])],
        "destinationType": rule.get("destinationType"),
        "destinationIds": [str(x) for x in (dst_ids or [])],
        "direction": rule.get("direction") if isinstance(rule.get("direction"), dict) else None,
        "protocols": proto_list,
        "biDirectional": bool(rule.get("biDirectional", False)),
        "syslog": bool(rule.get("syslog", False)),
    }


def _project_port_forward(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(row.get("id") or ""),
        "name": str(row.get("name") or ""),
        "status": bool(row.get("status", False)),
        "externalPort": str(row.get("externalPort") or ""),
        "forwardIp": str(row.get("forwardIp") or ""),
        "forwardPort": str(row.get("forwardPort") or ""),
        "protocol": row.get("protocol") if row.get("protocol") is not None else "all",
        "from": row.get("from"),
        "limitedAddresses": [str(x) for x in (row.get("limitedAddresses") or [])],
        "interfaceWanPortId": [str(x) for x in (row.get("interfaceWanPortId") or [])],
        "dmz": bool(row.get("dMZ", row.get("dmz", False))),
    }


def _project_static_route(row: Dict[str, Any]) -> Dict[str, Any]:
    dests = row.get("destinations")
    if isinstance(dests, str):
        dest_list = [dests] if dests else []
    elif isinstance(dests, list):
        dest_list = [str(x) for x in dests]
    else:
        single = row.get("destination")
        dest_list = [str(single)] if single else []
    return {
        "id": str(row.get("id") or ""),
        "name": str(row.get("name") or ""),
        "status": bool(row.get("status", False)),
        "routeType": _as_int(row.get("routeType"), 0) if row.get("routeType") is not None else None,
        "destinations": dest_list,
        "nextHopIp": str(row.get("nextHopIp") or row.get("nextHop") or ""),
        "interfaceId": str(row.get("interfaceId") or ""),
        "metric": _as_int(row.get("metric"), 0) if row.get("metric") is not None else None,
    }


def _list_lan_networks(client: OmadaClient) -> List[Dict[str, Any]]:
    site = _site(client)
    return [_project_lan_network(item) for item in _merge_lan_networks(client, site)]


def _list_dhcp_reservations(
    client: OmadaClient,
    vlan: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    site = _site(client)
    rows = _fetch_dhcp_reservations(client, site)
    net_by_id: Dict[str, Dict[str, Any]] = {}
    try:
        for net in _fetch_lan_collection(client, site):
            if net.get("id") is not None:
                net_by_id[str(net["id"])] = net
    except OmadaError:
        net_by_id = {}
    projected = [_project_dhcp_reservation(row, net_by_id) for row in rows]
    if vlan is not None and str(vlan).strip() != "":
        needle = str(vlan).strip().lower()
        projected = [
            item for item in projected
            if str(item.get("vlan") if item.get("vlan") is not None else "").lower() == needle
            or item["netId"].lower() == needle
            or item["networkName"].lower() == needle
        ]
    return projected


def _list_acls(client: OmadaClient) -> List[Dict[str, Any]]:
    site = _site(client)
    _, rules = _fetch_acls(client, site)
    return [_project_acl_rule(rule) for rule in rules]


_GROUP_TYPE_ALIASES = {"ip": 0, "port": 1, "mac": 2, "ipv6": 3}
_GROUP_TYPE_LABELS = {0: "ip", 1: "port", 2: "mac", 3: "ipv6"}


def _list_ip_groups(
    client: OmadaClient,
    groupType: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    site = _site(client)
    groups = _fetch_groups(client, site)
    filter_type: Optional[int] = None
    if groupType is not None and str(groupType).strip().lower() not in ("", "all"):
        raw_gt = str(groupType).strip().lower()
        if raw_gt in _GROUP_TYPE_ALIASES:
            filter_type = _GROUP_TYPE_ALIASES[raw_gt]
        else:
            try:
                filter_type = int(groupType)
            except (TypeError, ValueError):
                raise OmadaError(
                    f"invalid groupType {groupType!r}",
                    hint="valid values: 'ip' (0), 'port' (1), 'mac' (2), or 'all'",
                ) from None

    refs_by_group: Dict[str, List[Dict[str, str]]] = {}
    try:
        _, acls = _fetch_acls(client, site)
    except OmadaError:
        acls = []
    for rule in acls:
        ref = {"id": str(rule.get("id") or ""), "name": str(rule.get("name") or "")}
        for key in ("sourceIds", "destinationIds"):
            for gid in rule.get(key) or []:
                refs_by_group.setdefault(str(gid), []).append(ref)

    projected: List[Dict[str, Any]] = []
    for grp in groups:
        gtype = _parse_group_type(grp)
        if filter_type is not None and gtype != filter_type:
            continue
        gid = str(grp.get("id") or grp.get("groupId") or "")
        ip_list = grp.get("ipList") if isinstance(grp.get("ipList"), list) else []
        refs = refs_by_group.get(gid, [])
        unique_refs = list({r["id"]: r for r in refs}.values())
        projected.append({
            "id": gid,
            "name": str(grp.get("name") or ""),
            "type": gtype,
            "typeLabel": _GROUP_TYPE_LABELS.get(gtype, "unknown") if gtype is not None else "unknown",
            "entryCount": len(ip_list),
            "ipList": ip_list,
            "referencedByAcls": unique_refs,
        })
    return projected


def _list_port_forwards(client: OmadaClient) -> List[Dict[str, Any]]:
    site = _site(client)
    return [_project_port_forward(row) for row in _fetch_port_forwards(client, site)]


def _list_static_routes(client: OmadaClient) -> List[Dict[str, Any]]:
    site = _site(client)
    return [_project_static_route(row) for row in _fetch_static_routes(client, site)]


def _sanitize_wan_summary(raw_wan: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = redact_secrets(raw_wan)
    osg = cleaned.get("osgPortInfo") if isinstance(cleaned.get("osgPortInfo"), dict) else {}
    ports = osg.get("wanLanPortSettings") if isinstance(osg.get("wanLanPortSettings"), list) else []
    safe_ports = [
        {
            "portUuid": str(p.get("portUuid") or ""),
            "portName": str(p.get("portName") or p.get("name") or ""),
            "mode": p.get("mode"),
            "status": p.get("status"),
        }
        for p in ports if isinstance(p, dict)
    ]
    return {
        "wanMode": cleaned.get("wanMode"),
        "portCount": len(safe_ports),
        "ports": safe_ports,
    }


def _get_network_services(client: OmadaClient) -> Dict[str, Any]:
    site = _site(client)
    warnings: List[str] = []

    def _optional(label: str, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except OmadaError as exc:
            warnings.append(f"{label}: {exc.message}")
            return None

    upnp_raw = _optional("upnp", lambda: client.api_result(f"sites/{site.site_id}/setting/upnp"))
    dns_proxy_raw = _optional("dnsProxy", lambda: client.api_result(f"sites/{site.site_id}/setting/dns-proxy"))
    mdns_rules = _optional("mdnsRules", lambda: _fetch_mdns_rules(client, site))
    mdns_profiles = _optional("mdnsProfiles", lambda: _fetch_mdns_profiles(client, site))
    ddns_raw = _optional("ddns", lambda: client.api_result(f"sites/{site.site_id}/setting/service/ddns"))
    wan_raw = _optional("wan", lambda: _fetch_wan_networks(client, site))

    rules_list = [redact_secrets(r) for r in (mdns_rules or [])]
    profiles_list = [redact_secrets(p) for p in (mdns_profiles or [])]
    return {
        "upnp": redact_secrets(upnp_raw) if isinstance(upnp_raw, dict) else None,
        "dnsProxy": redact_secrets(dns_proxy_raw) if isinstance(dns_proxy_raw, dict) else None,
        "mdns": {
            "ruleCount": len(rules_list),
            "rules": rules_list,
            "profileCount": len(profiles_list),
            "profiles": profiles_list,
        },
        "ddns": redact_secrets(ddns_raw) if isinstance(ddns_raw, dict) else None,
        "wan": _sanitize_wan_summary(wan_raw) if isinstance(wan_raw, dict) else None,
        "warnings": warnings,
    }


def _search_clients(
    client: OmadaClient,
    query: Optional[str] = None,
    active: Optional[bool] = None,
    wireless: Optional[bool] = None,
    guest: Optional[bool] = None,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    site = _site(client)
    try:
        raw_rows = _fetch_clients_filtered(client, site, active=active)
    except OmadaError as exc:
        if exc.code in (-1007, -41011, -1600):
            raw_rows = _fetch_insight_clients(client, site)
        else:
            raise

    deduped: Dict[str, Dict[str, Any]] = {}
    ordered_without_mac: List[Dict[str, Any]] = []
    for row in raw_rows:
        norm = normalize_mac(row.get("mac", ""))
        if not norm:
            ordered_without_mac.append(row)
            continue
        prev = deduped.get(norm)
        if prev is None or (bool(row.get("active", True)) and not bool(prev.get("active", True))):
            deduped[norm] = row

    q_norm = str(query or "").strip().lower()
    q_mac = normalize_mac(q_norm) if q_norm else ""
    results: List[Dict[str, Any]] = []
    for row in list(deduped.values()) + ordered_without_mac:
        proj = project_client(row)
        if "blocked" in row:
            proj["blocked"] = bool(row.get("blocked"))
        ip_setting = row.get("ipSetting")
        if isinstance(ip_setting, dict) and ip_setting.get("useFixedAddr"):
            proj["fixedIp"] = str(ip_setting.get("ip") or "")
            if ip_setting.get("netId"):
                proj["fixedNetId"] = str(ip_setting.get("netId") or "")
        if active is not None and proj["active"] != bool(active):
            continue
        if wireless is not None and proj["wireless"] != bool(wireless):
            continue
        if guest is not None and proj["guest"] != bool(guest):
            continue
        if q_norm:
            mac_val = proj["mac"].lower()
            mac_norm = normalize_mac(mac_val)
            haystack = (
                mac_val,
                mac_norm,
                proj["name"].lower(),
                proj["hostName"].lower(),
                proj["ip"].lower(),
                proj["ssid"].lower(),
                proj["networkName"].lower(),
            )
            if not any(q_norm in field or (q_mac and q_mac in field) for field in haystack):
                continue
        results.append(proj)
        if limit and len(results) >= limit:
            break
    return results


def _list_logs(
    client: OmadaClient,
    category: str = "alerts",
    hours: int = 24,
    level: Optional[Any] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    site = _site(client)
    cat = str(category or "alerts").strip().lower()
    if cat not in ("alerts", "events", "audit"):
        raise OmadaError(
            f"unknown log category {category!r}",
            hint="valid categories: 'alerts', 'events', 'audit'",
        )
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 0:
        raise OmadaError("hours must be a non-negative integer")
    cap = max(1, min(1000, int(limit or 100)))
    now_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
    start_ms = 0 if hours == 0 else max(0, now_ms - hours * 3600 * 1000)

    if cat in ("alerts", "events"):
        time_query = (
            "filters.timeStart=0&filters.timeEnd=0"
            if hours == 0
            else f"filters.timeStart={start_ms}&filters.timeEnd={now_ms}"
        )
        endpoint = f"sites/{site.site_id}/logs/{cat}?{time_query}"
    else:
        endpoint = f"sites/{site.site_id}/audit/logs"

    rows, _ = client.paginate(
        endpoint,
        page_size=min(100, cap),
        max_pages=max(1, (cap + 99) // 100),
    )

    level_needle = str(level).strip().lower() if level is not None and str(level).strip() != "" else None
    out: List[Dict[str, Any]] = []
    for row in rows:
        raw_time = row.get("time") or row.get("timestamp") or row.get("createTime")
        if cat == "audit" and hours > 0 and isinstance(raw_time, (int, float)) and raw_time < start_ms:
            continue
        row_level = row.get("level") if row.get("level") is not None else row.get("severity")
        if level_needle is not None:
            if str(row_level if row_level is not None else "").strip().lower() != level_needle:
                continue
        cleaned = redact_secrets(row)
        content = _pick(
            cleaned,
            "content", "detail", "msg", "description", "operation", "logContent",
            default="",
        )
        if not content and cleaned.get("auditType") is not None:
            content = f"auditType={cleaned.get('auditType')}"
        target = _pick(
            cleaned,
            "target", "deviceName", "clientName", "operator", "userName", "mac",
            default="",
        )
        out.append({
            "id": str(cleaned.get("id") or cleaned.get("logId") or ""),
            "category": cat,
            "time": _iso(raw_time),
            "level": row_level,
            "type": cleaned.get("type") if cleaned.get("type") is not None else cleaned.get("auditType"),
            "module": cleaned.get("module"),
            "content": str(content or ""),
            "target": str(target or ""),
            "resolved": bool(cleaned.get("resolved", False)),
        })
        if len(out) >= cap:
            break
    return out


def _get_config_snapshot(
    client: OmadaClient,
    objects: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Read-only snapshot merging two-endpoint LAN data, ACLs, groups, WLANs, devices, and optional sections."""
    if objects is None:
        selected = list(_SNAPSHOT_DEFAULT_OBJECTS)
    else:
        if not isinstance(objects, list):
            raise OmadaError("objects must be an array of snapshot section names")
        selected = []
        seen = set()
        for raw in objects:
            raw_lower = str(raw or "").strip().lower()
            if not raw_lower:
                raise OmadaError("objects contains an empty entry")
            canonical = _SNAPSHOT_OBJECT_CANONICAL.get(raw_lower)
            if canonical is None:
                raise OmadaError(
                    f"unknown snapshot object {raw!r}",
                    hint="valid objects: " + ", ".join(_SNAPSHOT_ALL_OBJECTS),
                )
            if canonical not in seen:
                seen.add(canonical)
                selected.append(canonical)
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
        snapshot["networks"] = _merge_lan_networks(client, site)

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

    if "dhcpReservations" in selected:
        snapshot["dhcpReservations"] = _list_dhcp_reservations(client)

    if "portForwards" in selected:
        snapshot["portForwards"] = _list_port_forwards(client)

    if "staticRoutes" in selected:
        snapshot["staticRoutes"] = _list_static_routes(client)

    if "mdnsRules" in selected:
        snapshot["mdnsRules"] = [redact_secrets(r) for r in _fetch_mdns_rules(client, site)]

    if "services" in selected:
        snapshot["services"] = _get_network_services(client)

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
            "gateway ACLs, IP/port groups, PSK-redacted WLANs, devices, and optional "
            "clients, dhcpReservations, portForwards, staticRoutes, mdnsRules, and services."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "objects": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(_SNAPSHOT_ALL_OBJECTS)},
                    "description": (
                        "Optional subset of sections to fetch: networks, acls, groups, wlans, "
                        "devices, clients, dhcpReservations, portForwards, staticRoutes, "
                        "mdnsRules, services (defaults to networks, acls, groups, wlans, devices)"
                    ),
                },
            },
        },
        output_schema=_SNAPSHOT_SCHEMA,
        handler=_get_config_snapshot,
    ),
    Tool(
        name="search_clients",
        title="Search clients",
        description=(
            "Search online and offline/historical clients by MAC, name, hostname, IP, SSID, or "
            "VLAN/network, with active/wireless/guest filters. Automatically falls back to "
            "insight/clients for Viewer accounts."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Substring or MAC query matched against MAC, name, hostname, IP, SSID, or network",
                },
                "active": {
                    "type": "boolean",
                    "description": "Filter by online (true) or offline/historical (false) state; omit for all",
                },
                "wireless": {
                    "type": "boolean",
                    "description": "Filter by wireless (true) or wired (false) clients",
                },
                "guest": {
                    "type": "boolean",
                    "description": "Filter by guest flag",
                },
                "limit": _LIMIT_PROP,
            },
        },
        output_schema=_list_output_schema(_SEARCH_CLIENT_SCHEMA),
        handler=_search_clients,
    ),
    Tool(
        name="list_lan_networks",
        title="List LAN and VLAN networks",
        description=(
            "List configured LAN/VLAN networks merging setting/lan/networks and /interface "
            "(subnet, VLAN ID, isolation flags, DHCP pools, lease time, domain, IGMP snooping)."
        ),
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_LAN_NETWORK_SCHEMA),
        handler=_list_lan_networks,
    ),
    Tool(
        name="list_dhcp_reservations",
        title="List static DHCP reservations",
        description="List static DHCP reservations configured on the site (works for offline clients too).",
        input_schema={
            "type": "object",
            "properties": {
                "vlan": {
                    "type": ["string", "integer"],
                    "description": "Optional VLAN ID, netId, or network name filter",
                },
            },
        },
        output_schema=_list_output_schema(_DHCP_RES_SCHEMA),
        handler=_list_dhcp_reservations,
    ),
    Tool(
        name="list_acls",
        title="List gateway ACL rules",
        description=(
            "List gateway firewall ACL rules (setting/firewall/acls?type=0) with policy, "
            "source/destination IDs, direction, protocols, and per-rule status. "
            "Note: use get_config_snapshot(objects=['acls']) to inspect the advisory aclDisable flag."
        ),
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_ACL_SCHEMA),
        handler=_list_acls,
    ),
    Tool(
        name="list_ip_groups",
        title="List IP/port/MAC profile groups",
        description=(
            "List profile groups (IP groups type=0, port groups type=1, MAC groups type=2) "
            "with entry counts and ACL references."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "groupType": {
                    "type": ["string", "integer"],
                    "description": "Optional filter: 'ip' (0), 'port' (1), 'mac' (2), or 'all'",
                },
            },
        },
        output_schema=_list_output_schema(_IP_GROUP_SCHEMA),
        handler=_list_ip_groups,
    ),
    Tool(
        name="list_port_forwards",
        title="List port forwarding rules",
        description="List gateway NAT port forwarding and DMZ-mapped rules.",
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_PORT_FORWARD_SCHEMA),
        handler=_list_port_forwards,
    ),
    Tool(
        name="list_static_routes",
        title="List static routes",
        description="List configured gateway static routes (destinations, next hop, interface, metric).",
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_STATIC_ROUTE_SCHEMA),
        handler=_list_static_routes,
    ),
    Tool(
        name="get_network_services",
        title="Get network services",
        description=(
            "Summarize UPnP, DNS proxy, mDNS reflector rules and profiles, secret-redacted DDNS "
            "configuration, and sanitized WAN port status."
        ),
        input_schema=_EMPTY,
        output_schema=_SERVICES_SCHEMA,
        handler=_get_network_services,
    ),
    Tool(
        name="list_logs",
        title="List controller alerts, events, or audit logs",
        description=(
            "Query controller site logs ('alerts', 'events', or 'audit') with time window, "
            "optional level filter, and row cap."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["alerts", "events", "audit"],
                    "default": "alerts",
                    "description": "Log stream: 'alerts' (default), 'events', or 'audit'",
                },
                "hours": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 24,
                    "description": "Lookback window in hours (default 24; 0 for all available history)",
                },
                "level": {
                    "type": ["string", "integer"],
                    "description": "Optional severity/level filter",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 100,
                    "description": "Maximum log entries to return (default 100, max 1000)",
                },
            },
        },
        output_schema=_list_output_schema(_LOG_SCHEMA),
        handler=_list_logs,
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
            "Toggle a single gateway ACL rule status (PUT setting/firewall/acls/{id}?type=0); "
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
    Tool(
        name="upsert_dhcp_reservation",
        title="Create or update static DHCP reservation",
        description=(
            "Create or update a static DHCP reservation in setting/service/dhcp "
            "(works for offline MACs too; verifies pool/subnet bounds and checks silent no-op). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC address (any standard format)"},
                "ip": {"type": "string", "description": "Static IPv4 address within the target LAN subnet"},
                "vlan": {"type": ["string", "integer"], "description": "Target LAN VLAN ID or name"},
                "netId": {"type": "string", "description": "Target LAN network ID (optional when vlan is set)"},
                "description": {"type": "string", "description": "Optional reservation description"},
                "status": {"type": "boolean", "default": True, "description": "Enable reservation (default true)"},
                "exportToIpMacBinding": {"type": "boolean", "description": "Sync entry to IP-MAC binding table"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "ip"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_dhcp_reservation,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_dhcp_reservation",
        title="Delete static DHCP reservation",
        description=(
            "Delete a static DHCP reservation by MAC (DELETE setting/service/dhcp/{MAC}). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Reserved client MAC address"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_dhcp_reservation,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="create_lan_network",
        title="Create LAN or VLAN network",
        description=(
            "Create a routed LAN interface (purpose='interface', requires gatewaySubnet) or pure "
            "switch/AP VLAN (purpose='vlan') via POST setting/lan/networks. "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique LAN/VLAN network name"},
                "vlan": {"type": "integer", "minimum": 1, "maximum": 4094, "description": "IEEE 802.1Q VLAN ID (1-4094)"},
                "purpose": {
                    "type": "string",
                    "enum": ["interface", "vlan"],
                    "default": "interface",
                    "description": "'interface' (routed gateway VLAN, default) or 'vlan' (L2 VLAN only)",
                },
                "gatewaySubnet": {"type": "string", "description": "Gateway IP/prefix CIDR (e.g. '10.30.0.1/24') for purpose='interface'"},
                "dhcpEnable": {"type": "boolean", "default": True, "description": "Enable DHCP server on interface"},
                "pools": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"start": {"type": "string"}, "end": {"type": "string"}},
                        "required": ["start", "end"],
                    },
                    "description": "Optional DHCP pools [{'start': '...', 'end': '...'}]",
                },
                "leaseTime": {"type": "integer", "minimum": 1, "default": 120, "description": "DHCP lease time in minutes (default 120)"},
                "domain": {"type": "string", "description": "Optional local DNS domain suffix"},
                "isolation": {"type": "boolean", "default": False, "description": "Enable guest/network isolation"},
                "igmpSnoopEnable": {"type": "boolean", "default": False, "description": "Enable IGMP snooping"},
                "icmpPingEnable": {"type": "boolean", "default": True, "description": "Respond to ICMP ping on gateway"},
                "interfaceIds": {"type": "array", "items": {"type": "string"}, "description": "Optional LAN interface port UUIDs"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "vlan"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_lan_network,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="update_lan_network",
        title="Update LAN/VLAN settings",
        description=(
            "Update LAN/VLAN name, DHCP server, lease time, DNS servers, domain, IGMP snooping, "
            "or ICMP ping on /interface using full-object read-modify-write. "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "vlan": {"type": ["string", "integer"], "description": "Target VLAN ID or network name"},
                "netId": {"type": "string", "description": "Target LAN network ID"},
                "name": {"type": "string", "description": "New network name"},
                "dhcpEnable": {"type": "boolean", "description": "Enable or disable DHCP server"},
                "leaseTime": {"type": "integer", "minimum": 1, "description": "DHCP lease time in minutes"},
                "dnsMode": {"type": "string", "enum": ["auto", "manual"], "description": "DHCP DNS mode: 'auto' or 'manual'"},
                "dnsServers": {"type": "array", "items": {"type": "string"}, "description": "1 or 2 manual IPv4 DNS server addresses"},
                "domain": {"type": "string", "description": "Local DNS domain suffix"},
                "igmpSnoopEnable": {"type": "boolean", "description": "Enable or disable IGMP snooping"},
                "icmpPingEnable": {"type": "boolean", "description": "Enable or disable gateway ICMP ping"},
                **_WRITE_CONTROL_PROPS,
            },
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_lan_network,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_lan_network",
        title="Delete LAN/VLAN network",
        description=(
            "Delete a non-primary LAN/VLAN network (refuses Default VLAN and the network holding "
            "the MCP host/management IP). Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "vlan": {"type": ["string", "integer"], "description": "VLAN ID or network name"},
                "netId": {"type": "string", "description": "LAN network ID"},
                **_WRITE_CONTROL_PROPS,
            },
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_lan_network,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="update_gateway_acl",
        title="Update gateway ACL rule",
        description=(
            "Modify name, status, policy, source, destination, direction, protocols, biDirectional, "
            "or syslog on an existing gateway ACL (with anti-lockout checks). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "Gateway ACL rule ID or exact name"},
                "name": {"type": "string", "description": "New ACL rule name"},
                "status": {"type": "boolean", "description": "Enable or disable rule"},
                "policy": {"type": ["string", "integer"], "description": "'deny' (0) or 'permit' (1)"},
                "source": {
                    "type": "object",
                    "properties": {"type": {"type": ["string", "integer"]}, "ids": {"type": "array", "items": {"type": "string"}}},
                    "required": ["type", "ids"],
                    "description": "Updated source selector",
                },
                "destination": {
                    "type": "object",
                    "properties": {"type": {"type": ["string", "integer"]}, "ids": {"type": "array", "items": {"type": "string"}}},
                    "required": ["type", "ids"],
                    "description": "Updated destination selector",
                },
                "direction": {
                    "type": "object",
                    "properties": {
                        "lanToWan": {"type": "boolean"},
                        "lanToLan": {"type": "boolean"},
                        "wanInIds": {"type": "array", "items": {"type": "string"}},
                        "vpnInIds": {"type": "array", "items": {"type": "string"}},
                    },
                    "description": "Updated direction flags",
                },
                "protocols": {"type": "array", "items": {"type": "integer"}, "description": "Protocol codes"},
                "biDirectional": {"type": "boolean", "description": "Apply rule in both directions"},
                "syslog": {"type": "boolean", "description": "Log matching traffic to syslog"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_gateway_acl,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_gateway_acl",
        title="Delete gateway ACL rule",
        description=(
            "Delete a gateway ACL rule by ID or exact name (DELETE setting/firewall/acls/{id}?type=0). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "Gateway ACL rule ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_gateway_acl,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_ip_group",
        title="Delete IPv4 IP group",
        description=(
            "Delete an unreferenced IPv4 IP group (DELETE setting/profiles/groups/0/{id}); "
            "pre-checks gateway ACL references before deletion. "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "group": {"type": "string", "description": "IP group ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["group"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_ip_group,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="create_ssid",
        title="Create Wi-Fi SSID",
        description=(
            "Create a Wi-Fi SSID in a WLAN group with band selection, security mode (open or "
            "WPA2/WPA3 PSK), optional VLAN binding, PMF, and 802.11r. PSKs are never returned "
            "in diffs, snapshots, or outputs. Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Broadcast SSID name"},
                "wlanGroup": {"type": "string", "description": "WLAN group name or ID (defaults to site default group)"},
                "bands": {
                    "type": ["array", "integer", "string"],
                    "description": "Bands: ['2g', '5g'] (or '6g'), comma string, or Omada bitmask (default ['2g', '5g'])",
                },
                "security": {
                    "type": "string",
                    "default": "wpa2-psk",
                    "description": "Security mode: 'open', 'wpa2-psk', 'wpa-wpa2-psk', 'wpa3-sae', or 'wpa2-wpa3-psk'",
                },
                "psk": {"type": "string", "description": "Passphrase (8-63 chars, required unless security='open'; never echoed)"},
                "vlanId": {"type": "integer", "minimum": 1, "maximum": 4094, "description": "Optional custom VLAN tag for this SSID"},
                "guest": {"type": "boolean", "default": False, "description": "Enable guest network mode"},
                "broadcast": {"type": "boolean", "default": True, "description": "Enable/broadcast SSID (default true)"},
                "pmfMode": {"type": ["string", "integer"], "default": "disable", "description": "'disable' (3), 'capable' (2), or 'mandatory' (1)"},
                "enable11r": {"type": "boolean", "default": False, "description": "Enable 802.11r fast roaming"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_ssid,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="update_ssid",
        title="Update Wi-Fi SSID",
        description=(
            "Update an SSID via full-object PATCH (setting/wlans/{wlanId}/ssids/{ssidId}) with "
            "PSK redaction in snapshots/outputs. Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "ssid": {"type": "string", "description": "Existing SSID ID or exact name"},
                "wlanGroup": {"type": "string", "description": "Optional WLAN group ID or name"},
                "name": {"type": "string", "description": "New SSID broadcast name"},
                "bands": {"type": ["array", "integer", "string"], "description": "Updated bands (['2g', '5g', '6g'] or bitmask)"},
                "psk": {"type": "string", "description": "New Wi-Fi passphrase (8-63 chars; never echoed)"},
                "vlanId": {"type": "integer", "minimum": 1, "maximum": 4094, "description": "Bind SSID to VLAN ID"},
                "clearVlan": {"type": "boolean", "default": False, "description": "Reset SSID VLAN binding to default"},
                "guest": {"type": "boolean", "description": "Toggle guest network mode"},
                "broadcast": {"type": "boolean", "description": "Enable/disable SSID broadcast"},
                "pmfMode": {"type": ["string", "integer"], "description": "'disable', 'capable', or 'mandatory'"},
                "enable11r": {"type": "boolean", "description": "Toggle 802.11r fast roaming"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["ssid"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_ssid,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_ssid",
        title="Delete Wi-Fi SSID",
        description=(
            "Delete a Wi-Fi SSID from its WLAN group (redacts PSKs in snapshots). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "ssid": {"type": "string", "description": "SSID ID or exact name"},
                "wlanGroup": {"type": "string", "description": "Optional WLAN group ID or name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["ssid"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_ssid,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_port_forward",
        title="Create or update port forwarding rule",
        description=(
            "Create or update a NAT port forwarding rule (setting/transmission/portForwardings). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Existing rule ID when updating (omit to create or match by name)"},
                "name": {"type": "string", "description": "Rule name"},
                "externalPort": {"type": "string", "description": "External port or range (e.g. '443' or '8000-8010')"},
                "forwardIp": {"type": "string", "description": "Internal LAN target IPv4 address"},
                "forwardPort": {"type": "string", "description": "Internal target port or range"},
                "protocol": {"type": ["string", "integer"], "default": "all", "description": "'all', 'tcp', 'udp', or Omada protocol integer"},
                "status": {"type": "boolean", "default": True, "description": "Enable rule (default true)"},
                "fromIp": {"type": "string", "description": "Optional source IP/CIDR restriction (empty = any)"},
                "interfaceWanPortIds": {"type": "array", "items": {"type": "string"}, "description": "Optional WAN port UUIDs"},
                "dmz": {"type": "boolean", "default": False, "description": "Enable DMZ-style forwarding (default false)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "externalPort", "forwardIp", "forwardPort"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_port_forward,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_port_forward",
        title="Delete port forwarding rule",
        description=(
            "Delete a port forwarding rule by ID or exact name. "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "Port forward rule ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_port_forward,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_static_route",
        title="Create or update static route",
        description=(
            "Create or update a gateway static route (setting/transmission/staticRoutings). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Existing route ID when updating"},
                "name": {"type": "string", "description": "Route name"},
                "destination": {"type": "string", "description": "Destination IPv4 CIDR (e.g. '192.168.50.0/24')"},
                "nextHop": {"type": "string", "description": "Next-hop IPv4 address"},
                "interfaceId": {"type": "string", "description": "Optional LAN/WAN interface UUID"},
                "routeType": {"type": "integer", "default": 0, "description": "Route type (default 0 = Next Hop)"},
                "metric": {"type": "integer", "minimum": 1, "default": 1, "description": "Route metric/distance (default 1)"},
                "status": {"type": "boolean", "default": True, "description": "Enable route (default true)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "destination", "nextHop"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_static_route,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_static_route",
        title="Delete static route",
        description=(
            "Delete a gateway static route by ID or exact name. "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "Static route ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_static_route,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_mdns_rule",
        title="Create or update mDNS reflector rule",
        description=(
            "Create or update an mDNS reflector rule across VLANs (AirPlay, Chromecast, printers, etc.). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Existing rule ID when updating"},
                "name": {"type": "string", "description": "mDNS rule name"},
                "profiles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Built-in or custom mDNS profile names or IDs (e.g. ['AirPlay', 'Printers'])",
                },
                "serviceNetworks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Service-hosting VLAN IDs, network names, or IDs",
                },
                "clientNetworks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Client VLAN IDs, network names, or IDs allowed to discover services",
                },
                "ruleType": {"type": "string", "enum": ["gateway", "ap"], "default": "gateway", "description": "'gateway' (default) or 'ap'"},
                "status": {"type": "boolean", "default": True, "description": "Enable rule (default true)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "profiles", "serviceNetworks", "clientNetworks"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_mdns_rule,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_mdns_rule",
        title="Delete mDNS reflector rule",
        description=(
            "Delete an mDNS reflector rule by ID or exact name. "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "mDNS rule ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_mdns_rule,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="set_upnp",
        title="Enable or disable UPnP",
        description=(
            "Enable or disable UPnP on the site gateway (PUT setting/upnp). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "enable": {"type": "boolean", "description": "True to enable UPnP, false to disable"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["enable"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_upnp,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="set_client_blocked",
        title="Block or unblock client",
        description=(
            "Block or unblock a client MAC on the site (refuses the MCP management host and "
            "managed devices). Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC address"},
                "blocked": {"type": "boolean", "description": "True to block client, false to unblock"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "blocked"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_client_blocked,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="reconnect_client",
        title="Reconnect wireless client",
        description=(
            "Force an active wireless client to reassociate/reconnect to an AP "
            "(POST cmd/clients/{MAC}/reconnect). Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Active wireless client MAC address"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=reconnect_client,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="update_client",
        title="Rename client",
        description=(
            "Rename a client alias using volatile-key-stripped PATCH clients/{MAC}. "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC address"},
                "name": {"type": "string", "description": "New client alias/name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_client,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="update_device",
        title="Update Omada device settings",
        description=(
            "Rename an adopted AP/switch/gateway, set LED mode ('on'/'off'/'site'), or toggle "
            "device locator blink (POST cmd/devices/{MAC}/locate). "
            "Requires OMADA_READ_ONLY=false and OMADA_WRITE_TOOLS allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Managed Omada device MAC address or exact name"},
                "name": {"type": "string", "description": "New device name"},
                "ledSetting": {"type": ["string", "integer"], "description": "LED setting: 'off' (0), 'on' (1), or 'site' (2)"},
                "locate": {"type": "boolean", "description": "Toggle device locator LED blinking"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_device,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="reboot_device",
        title="Reboot Omada device",
        description=(
            "Reboot an adopted Omada AP, switch, or gateway (POST cmd/devices/{MAC}/reboot). "
            "Disruptive action; requires OMADA_READ_ONLY=false, OMADA_WRITE_TOOLS allowlist, and confirmation."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Managed Omada device MAC address or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=reboot_device,
        read_only=False,
        destructive=True,
        idempotent=False,
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
