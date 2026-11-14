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
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ._helpers import (
    ACL_TYPE_MAP,
    PROFILE_TYPE_LABELS,
    as_float as _as_float,
    collect_ap_radios_data,
    collect_rf_scan_data,
    collect_security_status_data,
    collect_switch_ports_data,
    collect_topology_data,
    collect_vpn_tunnels_data,
    collect_wan_status_data,
    deep_redact,
    dhcp_pool_capacity,
    extra_network_audit_findings,
    omada_mac,
    resolve_raw_device,
    try_api_result,
    try_paginate,
)
from ._projections import project_controller_row
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
    assign_ap_wlan_group,
    create_eap_acl,
    create_gateway_acl,
    create_ip_group,
    create_lan_network,
    create_ssid,
    create_switch_acl,
    cycle_poe_port,
    delete_dhcp_reservation,
    delete_gateway_acl,
    delete_ip_group,
    delete_lan_dns_rule,
    delete_lan_network,
    delete_mdns_rule,
    delete_policy_route,
    delete_port_forward,
    delete_port_profile,
    delete_ssid,
    delete_static_route,
    reboot_device,
    reconnect_client,
    release_client_fixed_ip,
    replace_ip_group,
    rollback_from_snapshot,
    set_acl_rule_status,
    set_client_blocked,
    set_client_fixed_ip,
    set_client_lock_to_ap,
    set_client_rate_limit,
    set_upnp,
    set_vlan_dhcp_pools,
    set_vlan_isolation,
    start_rf_scan,
    update_ap_radio,
    update_client,
    update_device,
    update_gateway_acl,
    update_lan_network,
    update_ssid,
    update_switch_port,
    upsert_dhcp_reservation,
    upsert_lan_dns_rule,
    upsert_mdns_rule,
    upsert_policy_route,
    upsert_port_forward,
    upsert_port_profile,
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


def _as_num_or_none(value: Any) -> Optional[Any]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return _as_float(value)


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
        "rssi": _as_num_or_none(client.get("rssi")),
        "signalLevel": _as_num_or_none(client.get("signalLevel")),
        "snr": _as_num_or_none(client.get("snr")),
        "txRate": as_int_or_none(client.get("txRate")),
        "rxRate": as_int_or_none(client.get("rxRate")),
        "uptime": as_int_or_none(client.get("uptime")),
        "connectType": str(client.get("connectType") or ""),
        "radioId": as_int_or_none(client.get("radioId")),
        "channel": as_int_or_none(client.get("channel")),
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


def _coerce_vlan(value: Any) -> Optional[int]:
    """Validate a caller-supplied VLAN id, refusing the ambiguous cases."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise OmadaError("vlan must be an integer, not a boolean")
    try:
        vlan = int(str(value).strip())
    except (TypeError, ValueError):
        raise OmadaError(
            f"vlan must be an integer, got {value!r}",
            hint="pass the VLAN id, e.g. 20",
        )
    if not 0 <= vlan <= 4094:
        raise OmadaError(f"vlan {vlan} is outside the valid range 0-4094")
    return vlan


def _paginate_client_rows(client: OmadaClient, site: Any, endpoint: str) -> List[Dict[str, Any]]:
    """Page a single client endpoint, deduping by normalised MAC."""
    collected: List[Dict[str, Any]] = []
    seen = set()
    previous_rows = None
    separator = "&" if "?" in endpoint else "?"
    for page in range(1, _MAX_CLIENT_PAGES + 1):
        payload = client.api(
            f"sites/{site.site_id}/{endpoint}"
            f"{separator}currentPage={page}&currentPageSize=100"
        )
        if payload.get("errorCode") != 0:
            raise OmadaError(
                f"client query failed: {payload.get('msg', 'unknown')}",
                code=payload.get("errorCode"),
                hint="clients needs Admin; insight/clients accepts any role",
                endpoint=f"sites/{{id}}/{endpoint}",
            )
        result = payload.get("result") or {}
        rows = result.get("data") or []
        if not rows or rows == previous_rows:
            break
        previous_rows = rows
        for row in rows:
            mac = normalize_mac(row.get("mac", ""))
            if mac and mac in seen:
                continue
            if mac:
                seen.add(mac)
            collected.append(row)
        total = int(result.get("totalRows") or 0)
        if total and len(collected) >= total:
            break
        if not total and len(rows) < 100:
            break
    return collected


def _fetch_client_rows(client: OmadaClient, site: Any) -> List[Dict[str, Any]]:
    """Client rows from the richest endpoint this account may use.

    ``clients?filters.active=true`` carries ``ssid``, ``ip``, ``apName`` and
    ``signalLevel``. ``insight/clients`` is the role-safe fallback, but on
    6.2.10.x it omits all four, which left list_clients and friends with blank
    columns while the controller held the data (issue #1).
    """
    first_error: Optional[OmadaError] = None
    for endpoint in ("clients?filters.active=true", "insight/clients"):
        try:
            return _paginate_client_rows(client, site, endpoint)
        except OmadaError as exc:
            if first_error is None:
                first_error = exc
            continue
    if first_error is not None:
        raise first_error
    return []


def _fetch_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    site = _site(client)
    collected: List[Dict[str, Any]] = []
    seen = set()
    for row in _fetch_client_rows(client, site):
        mac = normalize_mac(row.get("mac", ""))
        if mac and mac in seen:
            continue
        if mac:
            seen.add(mac)
        collected.append(project_client(row))
        if limit and len(collected) >= limit:
            break
    return collected


def _list_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    client.authenticate()
    return _fetch_clients(client, limit=limit)


def _list_wifi_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    return [c for c in _list_clients(client, limit=0) if c.get("wireless")][:limit or None]


def _list_wired_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    return [c for c in _list_clients(client, limit=0) if not c.get("wireless")][:limit or None]


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


def _findings_healthy(findings: List[Dict[str, Any]]) -> bool:
    """The one definition of audit health: no critical and no warning findings.

    Both ``_network_audit`` and ``_network_audit_enriched`` must use this. The
    wrapper previously recomputed health as ``critical == 0``, so the same tool
    reported a different meaning depending on whether enrichment appended
    findings (issue #3).
    """
    return not any(f.get("severity") in ("critical", "warning") for f in findings)


def _dhcp_pool_capacity(dhcp: Dict[str, Any]) -> int:
    """Total IPv4 addresses across ``dhcpSettings.ipRangePool`` (or start/end fallback)."""
    return dhcp_pool_capacity(dhcp)


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
        "healthy": _findings_healthy(findings),
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
        "rssi": {"type": ["integer", "number", "null"]},
        "signalLevel": {"type": ["integer", "number", "null"]},
        "snr": {"type": ["integer", "number", "null"]},
        "txRate": {"type": ["integer", "null"]},
        "rxRate": {"type": ["integer", "null"]},
        "uptime": {"type": ["integer", "null"]},
        "connectType": {"type": "string"},
        "radioId": {"type": ["integer", "null"]},
        "channel": {"type": ["integer", "null"]},
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


from copy import deepcopy as _deepcopy
from .config import ConfigError

_TOOL_CATEGORIES: Dict[str, str] = {
    # core
    "list_devices": "core",
    "list_clients": "core",
    "list_wifi_clients": "core",
    "list_wired_clients": "core",
    "get_device": "core",
    "get_client": "core",
    "list_wlans": "core",
    "get_site_info": "core",
    "explain_error": "core",
    "get_config_snapshot": "core",
    "search_clients": "core",
    "list_lan_networks": "core",
    "list_dhcp_reservations": "core",
    "set_client_fixed_ip": "core",
    "release_client_fixed_ip": "core",
    "upsert_dhcp_reservation": "core",
    "delete_dhcp_reservation": "core",
    "create_lan_network": "core",
    "update_lan_network": "core",
    "delete_lan_network": "core",
    "set_vlan_dhcp_pools": "core",
    "set_vlan_isolation": "core",
    "set_client_blocked": "core",
    "reconnect_client": "core",
    "update_client": "core",
    "update_device": "core",
    "reboot_device": "core",
    "set_client_rate_limit": "core",
    # diagnostics
    "network_audit": "diagnostics",
    "list_logs": "diagnostics",
    "get_topology": "diagnostics",
    "get_wan_status": "diagnostics",
    "diagnose_client": "diagnostics",
    "diagnose_wan": "diagnostics",
    # switch
    "get_switch_ports": "switch",
    "list_port_profiles": "switch",
    "update_switch_port": "switch",
    "cycle_poe_port": "switch",
    "upsert_port_profile": "switch",
    "delete_port_profile": "switch",
    # wifi
    "get_ap_radios": "wifi",
    "get_rf_scan": "wifi",
    "list_wlan_groups": "wifi",
    "create_ssid": "wifi",
    "update_ssid": "wifi",
    "delete_ssid": "wifi",
    "update_ap_radio": "wifi",
    "start_rf_scan": "wifi",
    "assign_ap_wlan_group": "wifi",
    "set_client_lock_to_ap": "wifi",
    # routing
    "list_port_forwards": "routing",
    "list_static_routes": "routing",
    "get_network_services": "routing",
    "list_vpn_tunnels": "routing",
    "list_policy_routes": "routing",
    "list_lan_dns_rules": "routing",
    "upsert_port_forward": "routing",
    "delete_port_forward": "routing",
    "upsert_static_route": "routing",
    "delete_static_route": "routing",
    "upsert_mdns_rule": "routing",
    "delete_mdns_rule": "routing",
    "set_upnp": "routing",
    "upsert_policy_route": "routing",
    "delete_policy_route": "routing",
    "upsert_lan_dns_rule": "routing",
    "delete_lan_dns_rule": "routing",
    # security
    "list_acls": "security",
    "list_ip_groups": "security",
    "get_security_status": "security",
    "create_ip_group": "security",
    "replace_ip_group": "security",
    "delete_ip_group": "security",
    "create_gateway_acl": "security",
    "update_gateway_acl": "security",
    "delete_gateway_acl": "security",
    "set_acl_rule_status": "security",
    "create_switch_acl": "security",
    "create_eap_acl": "security",
    # rollback
    "rollback_from_snapshot": "rollback",
}

_SLIM_WRITE_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "applied": {"type": "boolean"},
        "dryRun": {"type": "boolean"},
        "verified": {"type": "boolean"},
        "target": {"type": "string"},
    },
    "required": ["applied", "dryRun", "verified", "target"],
}


def _slim_prop_type(prop_schema: Any) -> Dict[str, Any]:
    if not isinstance(prop_schema, dict):
        return {}
    t = prop_schema.get("type")
    if t is not None:
        return {"type": t}
    return {}


def _slim_output_schema(schema: Dict[str, Any], *, read_only: bool) -> Dict[str, Any]:
    """Collapse deep nested trees while preserving MCP 2025-06-18 required invariants."""
    if not read_only:
        return _deepcopy(_SLIM_WRITE_OUTPUT_SCHEMA)
    req = list(schema.get("required") or [])
    props = schema.get("properties") or {}
    if set(req) == {"items", "count"} and "items" in props:
        return {
            "type": "object",
            "properties": {
                "items": {"type": "array", "items": {"type": "object"}},
                "count": {"type": "integer"},
            },
            "required": ["items", "count"],
        }
    slim_props = {k: _slim_prop_type(props[k]) for k in req if k in props}
    if not slim_props:
        for k, v in list(props.items())[:1]:
            slim_props[k] = _slim_prop_type(v)
    return {"type": "object", "properties": slim_props, "required": req}


_ABBREV_DOT_RE = re.compile(r"(?:^|\W)(?:e\.g|i\.e|etc|vs)$", re.IGNORECASE)
_CODE_HINT_QUOTED_RE = re.compile(r"'[^']+'")
_CODE_HINT_DIGIT_MAP_RE = re.compile(r"\b\d+=")
_CODE_HINT_TOKEN_RE = re.compile(r"\b(?:code|codes|hex|bitmask)\b", re.IGNORECASE)
_SLIM_CODE_HINT_REWRITES: Dict[str, str] = {
    "Maximum number of clients to return (default 500, max 5000)": "Max clients (1-5000, default 500)",
    "Maximum log entries to return (default 100, max 1000)": "Max log entries (1-1000, default 100)",
    "Lookback window in hours (default 24; 0 for all available history)": "Lookback hours (0 = all history)",
    "Numeric Omada errorCode to explain (e.g. -1600, -33726)": "Omada errorCode (e.g. -1600, -33726)",
    "Optional VLAN ID, netId, or network name filter": "VLAN ID, netId, or network name",
    "Optional filter: 'ip' (0), 'port' (1), 'mac' (2), or 'all'": "'ip'(0), 'port'(1), 'mac'(2), or 'all'",
    "Bands: ['2g', '5g'] (or '6g'), comma string, or Omada bitmask (default ['2g', '5g'])": "['2g','5g','6g'], CSV, or bitmask",
    "'disable' (3), 'capable' (2), or 'mandatory' (1)": "'disable'(3), 'capable'(2), 'mandatory'(1)",
    "'all', 'tcp', 'udp', or Omada protocol integer": "'all', 'tcp', 'udp', or protocol int",
    "LED setting: 'off' (0), 'on' (1), or 'site' (2)": "'off' (0), 'on' (1), or 'site' (2)",
    "'auto', '10m', '100m', '1000m', '2500m', '10g' or code": "auto/10m/100m/1000m/2500m/10g or code",
    "Width: 'auto', '20', '40', '80', '160', '320' (or 20MHz..320MHz)": "'auto'|'20'|'40'|'80'|'160'|'320' (or MHz)",
    "'low' (0), 'medium' (1), 'high' (2), 'custom' (3), 'auto' (4)": "0=low, 1=med, 2=high, 3=custom, 4=auto",
    "Custom dBm TX power when txPowerLevel='custom'": "Custom dBm when txPowerLevel='custom'",
    "'all_ports' (0), 'custom_ports' (1), 'all_switches' (2), 'vlan' (3)": "0=all_ports,1=custom,2=switches,3=vlan",
}


def _needs_code_hint(prop: Dict[str, Any]) -> bool:
    """Return True when an input property relies on numeric/string codes without an enum."""
    items = prop.get("items")
    if "enum" in prop or (isinstance(items, dict) and "enum" in items):
        return False
    ptype = prop.get("type")
    if ptype == "integer" or (isinstance(ptype, list) and "integer" in ptype):
        return True
    if isinstance(items, dict) and items.get("type") == "integer":
        return True
    if ptype == "string" or (isinstance(ptype, list) and "string" in ptype):
        desc = str(prop.get("description") or "")
        return bool(
            _CODE_HINT_DIGIT_MAP_RE.search(desc)
            or "|" in desc
            or len(_CODE_HINT_QUOTED_RE.findall(desc)) >= 3
            or _CODE_HINT_TOKEN_RE.search(desc)
        )
    return False


def _snap_words(text: str, limit: int) -> str:
    """Snap text strictly within ``limit`` characters at full word/token boundaries."""
    clean = " ".join(text.strip().split())
    if len(clean) <= limit:
        return clean
    max_body = max(1, limit - 1)
    if len(clean) > max_body and clean[max_body] == " ":
        prefix = clean[:max_body]
    else:
        window = clean[:max_body]
        space = window.rfind(" ")
        prefix = window[:space] if space > 0 else window
    prefix = prefix.rstrip(" ,;:-([{")
    if prefix.count("(") > prefix.count(")"):
        last_open = prefix.rfind("(")
        if last_open >= 24:
            prefix = prefix[:last_open].rstrip(" ,;:-")
    return prefix + "…"


def _slim_code_hint(desc: str, limit: int = 45) -> str:
    clean = " ".join(str(desc or "").strip().split())
    clean = _SLIM_CODE_HINT_REWRITES.get(clean, clean)
    if len(clean) <= limit:
        return clean
    return _snap_words(clean, limit)


def _slim_schema_node(node: Any, *, key: Optional[str] = None) -> None:
    if not isinstance(node, dict):
        return
    if key not in ("dryRun", "confirm"):
        desc = node.get("description")
        if _needs_code_hint(node) and desc:
            node["description"] = _slim_code_hint(desc, 45)
        else:
            node.pop("description", None)
    props = node.get("properties")
    if isinstance(props, dict):
        for child_key, child in props.items():
            _slim_schema_node(child, key=child_key)
    items = node.get("items")
    if isinstance(items, dict):
        items.pop("description", None)
        _slim_schema_node(items)


def _slim_input_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Preserve exact parameter constraints, enums, and <=45-char code hints."""
    out = _deepcopy(schema)
    props = out.get("properties")
    if isinstance(props, dict):
        for key, prop in props.items():
            _slim_schema_node(prop, key=key)
    return out


def _slim_description(text: str, limit: int = 110) -> str:
    """Shorten a tool description cleanly at complete sentence or full-word boundaries."""
    clean = " ".join(text.strip().split())
    if len(clean) <= limit:
        return clean
    ends: List[int] = []
    depth = 0
    n = len(clean)
    for idx, ch in enumerate(clean):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif depth == 0 and ch == "." and idx + 1 < n and clean[idx + 1] == " ":
            if _ABBREV_DOT_RE.search(clean[:idx]):
                continue
            ends.append(idx + 1)
    fitting = [end for end in ends if end <= limit]
    if fitting:
        return clean[: fitting[-1]].rstrip()
    first_sentence = clean[: ends[0]].rstrip() if ends else clean
    if len(first_sentence) <= limit:
        return first_sentence
    return _snap_words(first_sentence, limit)


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

    @property
    def category(self) -> str:
        return _TOOL_CATEGORIES.get(self.name, "core")

    def descriptor(self, schema_mode: str = "slim") -> Dict[str, Any]:
        slim = str(schema_mode or "slim").strip().lower() != "full"
        desc = _slim_description(self.description) if slim else self.description
        in_schema = _slim_input_schema(self.input_schema) if slim else self.input_schema
        out_schema = (
            _slim_output_schema(self.output_schema, read_only=self.read_only)
            if slim
            else self.output_schema
        )
        return {
            "name": self.name,
            "title": self.title,
            "description": desc,
            "inputSchema": in_schema,
            "outputSchema": out_schema,
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
        "aclType": {"type": "string"},
        "status": {"type": "boolean"},
        "policy": {"type": ["integer", "string"]},
        "policyLabel": {"type": "string"},
        "sourceType": {"type": ["integer", "string", "null"]},
        "sourceIds": {"type": "array", "items": {"type": "string"}},
        "destinationType": {"type": ["integer", "string", "null"]},
        "destinationIds": {"type": "array", "items": {"type": "string"}},
        "direction": {"type": ["object", "null"]},
        "bindingType": {"type": ["integer", "string", "null"]},
        "customAclPorts": {"type": "array", "items": {"type": "object"}},
        "networkId": {"type": ["string", "null"]},
        "protocols": {"type": "array", "items": {"type": ["integer", "string"]}},
        "biDirectional": {"type": "boolean"},
        "syslog": {"type": "boolean"},
    },
    "required": ["id", "name", "status", "policy", "sourceIds", "destinationIds"],
}

_SWITCH_PORTS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "model": {"type": "string"},
        "online": {"type": "boolean"},
        "poe": {"type": "object"},
        "uplinkPorts": {"type": "array", "items": {"type": "integer"}},
        "lagGroups": {"type": "array", "items": {"type": "object"}},
        "cableTestSupported": {"type": ["boolean", "null"]},
        "cableTestStatus": {"type": ["integer", "null"]},
        "ports": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "port": {"type": "integer"},
                    "standardPort": {"type": "string"},
                    "name": {"type": "string"},
                    "disabled": {"type": "boolean"},
                    "operation": {"type": "string"},
                    "profileId": {"type": "string"},
                    "profileName": {"type": "string"},
                    "linkUp": {"type": "boolean"},
                    "speed": {"type": "string"},
                    "speedMbps": {"type": "integer"},
                    "maxSpeed": {"type": "string"},
                    "maxSpeedMbps": {"type": "integer"},
                    "duplex": {"type": "string"},
                    "isUplink": {"type": "boolean"},
                    "isLagMember": {"type": "boolean"},
                    "carriesController": {"type": "boolean"},
                    "poeSupported": {"type": "boolean"},
                    "poeDelivering": {"type": "boolean"},
                    "poePowerW": {"type": "number"},
                },
                "required": ["port", "name", "linkUp", "isUplink", "isLagMember"],
            },
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["mac", "name", "poe", "uplinkPorts", "ports", "warnings"],
}

_AP_RADIOS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "model": {"type": "string"},
        "online": {"type": "boolean"},
        "wlanGroupId": {"type": "string"},
        "supportRfScan": {"type": "boolean"},
        "radios": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "band": {"type": "string"},
                    "enabled": {"type": "boolean"},
                    "channel": {"type": ["integer", "string", "null"]},
                    "channelWidth": {"type": "string"},
                    "txPower": {"type": ["integer", "number", "null"]},
                    "txPowerMode": {"type": "string"},
                    "txUtilPct": {"type": ["number", "null"]},
                    "rxUtilPct": {"type": ["number", "null"]},
                    "interferencePct": {"type": ["number", "null"]},
                    "txRetryRatePct": {"type": ["number", "null"]},
                    "rxRetryRatePct": {"type": ["number", "null"]},
                    "clientCount": {"type": ["integer", "null"]},
                    "availableChannels": {"type": "array", "items": {"type": "object"}},
                },
                "required": ["band", "enabled", "channel", "channelWidth"],
            },
        },
        "rfScan": {"type": ["object", "null"]},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["mac", "name", "radios", "warnings"],
}

_RF_SCAN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "model": {"type": "string"},
        "supportRfScan": {"type": "boolean"},
        "scanTime": {"type": ["integer", "string", "null"]},
        "status": {"type": ["integer", "string", "null"]},
        "bandStatuses": {"type": "object"},
        "radioUtilization": {"type": "array", "items": {"type": "object"}},
        "channels": {"type": "array", "items": {"type": "object"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["mac", "name", "supportRfScan", "radioUtilization", "channels", "warnings"],
}

_WAN_STATUS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "hasGateway": {"type": "boolean"},
        "gatewayMac": {"type": "string"},
        "gatewayName": {"type": "string"},
        "gatewayModel": {"type": "string"},
        "wanMode": {"type": "string"},
        "loadBalanceEnabled": {"type": "boolean"},
        "failoverConfigured": {"type": "boolean"},
        "totalWanPorts": {"type": "integer"},
        "linkUpCount": {"type": "integer"},
        "internetUpCount": {"type": "integer"},
        "ports": {"type": "array", "items": {"type": "object"}},
        "speedTest": {"type": ["object", "null"]},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["hasGateway", "wanMode", "totalWanPorts", "linkUpCount", "internetUpCount", "ports", "warnings"],
}

_VPN_TUNNELS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "tunnels": {"type": "array", "items": {"type": "object"}},
        "configuredVpns": {"type": "array", "items": {"type": "object"}},
        "counts": {"type": "object"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["tunnels", "configuredVpns", "counts", "warnings"],
}

_TOPOLOGY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "roots": {"type": "array", "items": {"type": "object"}},
        "unattachedDevices": {"type": "array", "items": {"type": "object"}},
        "counts": {"type": "object"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["roots", "unattachedDevices", "counts", "warnings"],
}

_SECURITY_STATUS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "ips": {"type": ["object", "null"]},
        "attackDefense": {"type": ["object", "null"]},
        "wids": {"type": ["object", "null"]},
        "threatAlerts": {"type": "array", "items": {"type": "object"}},
        "rogueAps": {"type": "array", "items": {"type": "object"}},
        "counts": {"type": "object"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["ips", "threatAlerts", "rogueAps", "counts", "warnings"],
}

_DIAGNOSTIC_FINDING_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "code": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
        "detail": {"type": "string"},
    },
    "required": ["code", "severity", "detail"],
}

_DIAGNOSE_CLIENT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "client": {"type": "object"},
        "parentRadio": {"type": ["object", "null"]},
        "parentSwitchPort": {"type": ["object", "null"]},
        "pastConnections": {"type": "array", "items": {"type": "object"}},
        "recentLogs": {"type": "array", "items": {"type": "object"}},
        "findings": {"type": "array", "items": _DIAGNOSTIC_FINDING_SCHEMA},
        "nextSteps": {"type": "array", "items": {"type": "string"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["client", "pastConnections", "recentLogs", "findings", "nextSteps", "warnings"],
}

_DIAGNOSE_WAN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "wan": _WAN_STATUS_SCHEMA,
        "vpnSummary": {"type": "object"},
        "recentLogs": {"type": "array", "items": {"type": "object"}},
        "findings": {"type": "array", "items": _DIAGNOSTIC_FINDING_SCHEMA},
        "nextSteps": {"type": "array", "items": {"type": "string"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["wan", "vpnSummary", "recentLogs", "findings", "nextSteps", "warnings"],
}

_PORT_PROFILE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "type": {"type": ["integer", "null"]},
        "typeLabel": {"type": "string"},
        "prohibitModify": {"type": "boolean"},
        "poe": {"type": ["integer", "null"]},
        "vlanConfigEnable": {"type": "boolean"},
        "nativeNetworkId": {"type": "string"},
        "tagNetworkIds": {"type": "array", "items": {"type": "string"}},
        "untagNetworkIds": {"type": "array", "items": {"type": "string"}},
        "portIsolationEnable": {"type": "boolean"},
    },
    "required": ["id", "name", "type", "prohibitModify"],
}

_WLAN_GROUP_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "primary": {"type": "boolean"},
        "clone": {"type": "boolean"},
        "ssidCount": {"type": "integer"},
        "ssids": {"type": "array", "items": {"type": "object"}},
    },
    "required": ["id", "name", "primary", "ssidCount", "ssids"],
}

_SUPPORTED_ITEMS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "items": {"type": "array", "items": {"type": "object"}},
        "count": {"type": "integer", "minimum": 0},
        "supported": {"type": "boolean"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["items", "count", "supported", "warnings"],
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
        "description": "Preview without applying (default true)",
    },
    "confirm": {
        "type": "string",
        "description": "Required '<tool>:<target>' when dryRun=false",
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


def _project_acl_rule(
    rule: Dict[str, Any],
    *,
    acl_type: Optional[str] = None,
) -> Dict[str, Any]:
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
    projected: Dict[str, Any] = {
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
    if acl_type is not None:
        projected["aclType"] = acl_type
    if acl_type in ("switch", "eap") or "bindingType" in rule:
        if rule.get("bindingType") is not None:
            projected["bindingType"] = rule.get("bindingType")
        if rule.get("customAclPorts") is not None:
            projected["customAclPorts"] = [dict(p) for p in (rule.get("customAclPorts") or []) if isinstance(p, dict)]
        if rule.get("networkId") is not None:
            projected["networkId"] = str(rule.get("networkId") or "")
    return projected


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


def _list_acls(client: OmadaClient, aclType: str = "gateway") -> List[Dict[str, Any]]:
    site = _site(client)
    kind = str(aclType or "gateway").strip().lower()
    if kind == "gateway":
        _, rules = _fetch_acls(client, site)
        return [_project_acl_rule(rule) for rule in rules]
    if kind in ("switch", "eap"):
        code = ACL_TYPE_MAP[kind]
        rows, _ = client.paginate(f"sites/{site.site_id}/setting/firewall/acls?type={code}")
        return [_project_acl_rule(rule, acl_type=kind) for rule in rows]
    if kind == "all":
        combined: List[Dict[str, Any]] = []
        tmp_warnings: List[str] = []
        for tname in ("gateway", "switch", "eap"):
            code = ACL_TYPE_MAP[tname]
            if tname == "gateway":
                try:
                    _, g_rules = _fetch_acls(client, site)
                    combined.extend(_project_acl_rule(r, acl_type="gateway") for r in g_rules)
                    continue
                except OmadaError:
                    rows, _, ok = try_paginate(
                        client, f"sites/{site.site_id}/setting/firewall/acls?type={code}",
                        tmp_warnings, label=f"ACL {tname}",
                    )
                    if ok:
                        combined.extend(_project_acl_rule(r, acl_type=tname) for r in rows)
            else:
                rows, _, ok = try_paginate(
                    client, f"sites/{site.site_id}/setting/firewall/acls?type={code}",
                    tmp_warnings, label=f"ACL {tname}",
                )
                if ok:
                    combined.extend(_project_acl_rule(r, acl_type=tname) for r in rows)
        return combined
    raise OmadaError(
        f"invalid aclType {aclType!r}",
        hint="valid values: 'gateway' (0), 'switch' (1), 'eap' (2), or 'all'",
    )


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
            "ipList": project_controller_row("groups", {"ipList": ip_list})["ipList"],
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

    rules_list = [project_controller_row("mdnsRules", r) for r in (mdns_rules or [])]
    profiles_list = [project_controller_row("mdnsProfiles", p) for p in (mdns_profiles or [])]
    return {
        "upnp": project_controller_row("upnp", upnp_raw) if isinstance(upnp_raw, dict) else None,
        "dnsProxy": project_controller_row("dnsProxy", dns_proxy_raw) if isinstance(dns_proxy_raw, dict) else None,
        "mdns": {
            "ruleCount": len(rules_list),
            "rules": rules_list,
            "profileCount": len(profiles_list),
            "profiles": profiles_list,
        },
        "ddns": project_controller_row("ddns", ddns_raw) if isinstance(ddns_raw, dict) else None,
        "wan": _sanitize_wan_summary(wan_raw) if isinstance(wan_raw, dict) else None,
        "warnings": warnings,
    }


def _search_clients(
    client: OmadaClient,
    query: Optional[str] = None,
    active: Optional[bool] = None,
    wireless: Optional[bool] = None,
    guest: Optional[bool] = None,
    vlan: Optional[Any] = None,
    ssid: Optional[str] = None,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    site = _site(client)
    vlan = _coerce_vlan(vlan)
    ssid_needle = str(ssid).strip().lower() if ssid is not None else None
    if ssid_needle == "":
        ssid_needle = None
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
        if vlan is not None and _as_int(proj.get("vlan"), -1) != vlan:
            continue
        if ssid_needle is not None:
            have = str(proj.get("ssid") or "").strip().lower()
            if not have or (have != ssid_needle and ssid_needle not in have):
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
    # Omada 6.2 treats timeStart=0&timeEnd=0 as an empty range and rejects
    # missing timeStart/timeEnd with -1001/-1; timeStart=1 queries all history.
    start_ms = 1 if hours == 0 else max(1, now_ms - hours * 3600 * 1000)

    if cat in ("alerts", "events"):
        endpoint = (
            f"sites/{site.site_id}/logs/{cat}"
            f"?filters.timeStart={start_ms}&filters.timeEnd={now_ms}"
        )
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
    with client.scoped_cache():
        return _get_config_snapshot_impl(client, objects=objects)


def _get_config_snapshot_impl(
    client: OmadaClient,
    objects: Optional[List[str]] = None,
) -> Dict[str, Any]:
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
        snapshot["networks"] = [project_controller_row("networks", row) for row in _merge_lan_networks(client, site)]

    if "acls" in selected:
        acl_disable, rules = _fetch_acls(client, site)
        warnings.append(_ACL_DISPATCH_NOTES)
        snapshot["acls"] = {
            "aclDisable": acl_disable,
            "aclDisableReliable": False,
            "warning": _ACL_DISPATCH_NOTES,
            "count": len(rules),
            "rules": [project_controller_row("acls", rule) for rule in rules],
        }

    if "groups" in selected:
        groups = [project_controller_row("groups", group) for group in _fetch_groups(client, site)]
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
        snapshot["mdnsRules"] = [project_controller_row("mdnsRules", r) for r in _fetch_mdns_rules(client, site)]

    if "services" in selected:
        snapshot["services"] = _get_network_services(client)

    return snapshot


# -- Milestone 1 diagnostics & Milestone 2 read helpers ----------------------


def _network_audit_enriched(client: OmadaClient) -> Dict[str, Any]:
    """Run core network_audit plus non-fatal switch/AP/WAN telemetry findings."""
    with client.scoped_cache():
        audit = _network_audit(client)
        site = _site(client)
        try:
            raw_devices = _fetch_devices(client, site)
        except OmadaError:
            raw_devices = []
        extra = extra_network_audit_findings(client, site, raw_devices)
    if not extra:
        return audit

    findings = list(audit.get("findings") or [])
    findings.extend(extra)
    findings.sort(key=lambda item: _SEVERITY_ORDER.get(item["severity"], 99))

    critical = sum(1 for f in findings if f["severity"] == "critical")
    warning = sum(1 for f in findings if f["severity"] == "warning")
    info = sum(1 for f in findings if f["severity"] == "info")
    counts = dict(audit.get("counts") or {})
    counts.update({
        "findings": len(findings),
        "critical": critical,
        "warnings": warning,
        "info": info,
    })
    return {
        "healthy": _findings_healthy(findings),
        "controller": audit.get("controller"),
        "site": audit.get("site"),
        "counts": counts,
        "dhcpPools": audit.get("dhcpPools") or [],
        "findings": findings,
    }


def _get_network_services_enriched(client: OmadaClient) -> Dict[str, Any]:
    """Preserve get_network_services schema while enriching ``wan`` with live state."""
    with client.scoped_cache():
        res = _get_network_services(client)
        site = _site(client)
        try:
            wan_live = collect_wan_status_data(client, site, include_speedtest=False)
        except OmadaError:
            return res
    if wan_live.get("ports") or wan_live.get("hasGateway"):
        wan_block = dict(res.get("wan") or {})
        wan_block["live"] = {
            "hasGateway": wan_live.get("hasGateway"),
            "gatewayMac": wan_live.get("gatewayMac"),
            "wanMode": wan_live.get("wanMode"),
            "loadBalanceEnabled": wan_live.get("loadBalanceEnabled"),
            "failoverConfigured": wan_live.get("failoverConfigured"),
            "totalWanPorts": wan_live.get("totalWanPorts"),
            "linkUpCount": wan_live.get("linkUpCount"),
            "internetUpCount": wan_live.get("internetUpCount"),
            "ports": wan_live.get("ports") or [],
        }
        res["wan"] = wan_block
    return res


def _get_switch_ports(
    client: OmadaClient,
    mac: str,
    includeCounters: bool = True,
    includeCableTest: bool = True,
    includeDownPorts: bool = True,
    compact: bool = False,
) -> Dict[str, Any]:
    with client.scoped_cache():
        site = _site(client)
        sw = resolve_raw_device(client, site, mac, expected_type="switch")
        return collect_switch_ports_data(
            client, site, sw,
            include_counters=bool(includeCounters),
            include_cable_test=bool(includeCableTest),
            include_down_ports=bool(includeDownPorts),
            compact=bool(compact),
        )


def _get_ap_radios(
    client: OmadaClient,
    mac: str,
    includeRfScan: bool = True,
    includeAvailableChannels: bool = True,
) -> Dict[str, Any]:
    with client.scoped_cache():
        site = _site(client)
        ap = resolve_raw_device(client, site, mac, expected_type="ap")
        client_rows: Optional[List[Dict[str, Any]]] = None
        try:
            rows = _fetch_client_rows(client, site)
            wireless_rows = [r for r in rows if r.get("wireless")]
            # Viewer insight/clients on 6.2.10.x strips AP identity and radioId;
            # keep clientCount as None rather than misleading 0 when blind.
            if not wireless_rows or any(
                r.get("radioId") is not None and (r.get("apMac") or r.get("apName"))
                for r in wireless_rows
            ):
                client_rows = rows
        except OmadaError:
            client_rows = None
        return collect_ap_radios_data(
            client, site, ap,
            include_rf_scan=bool(includeRfScan),
            include_available_channels=bool(includeAvailableChannels),
            client_rows=client_rows,
        )


def _get_rf_scan(client: OmadaClient, mac: str) -> Dict[str, Any]:
    site = _site(client)
    ap = resolve_raw_device(client, site, mac, expected_type="ap")
    return collect_rf_scan_data(client, site, ap)


def _get_wan_status(
    client: OmadaClient,
    includeSpeedtest: bool = True,
    maskWanIp: bool = False,
) -> Dict[str, Any]:
    with client.scoped_cache():
        site = _site(client)
        return collect_wan_status_data(
            client, site,
            include_speedtest=bool(includeSpeedtest),
            mask_wan_ip=bool(maskWanIp),
        )


def _list_vpn_tunnels(client: OmadaClient) -> Dict[str, Any]:
    with client.scoped_cache():
        return collect_vpn_tunnels_data(client, _site(client))


def _get_topology(client: OmadaClient, includeClients: bool = False) -> Dict[str, Any]:
    return collect_topology_data(client, _site(client), include_clients=bool(includeClients))


def _get_security_status(
    client: OmadaClient,
    hours: int = 24,
    limit: int = 20,
) -> Dict[str, Any]:
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 0:
        raise OmadaError("hours must be a non-negative integer")
    site = _site(client)
    data = collect_security_status_data(client, site, limit=limit)
    if hours > 0 and isinstance(data.get("warnings"), list):
        data["windowHours"] = hours
    return data


def _safe_recent_logs(
    client: OmadaClient,
    hours: int,
    warnings: List[str],
    limit: int = 50,
) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for cat in ("alerts", "events"):
        try:
            events.extend(_list_logs(client, category=cat, hours=hours, limit=limit))
        except OmadaError as exc:
            warnings.append(f"logs/{cat}: unavailable ({exc.code}: {exc})")
    return events


def _diagnose_client(
    client: OmadaClient,
    mac: str,
    hours: int = 24,
) -> Dict[str, Any]:
    with client.scoped_cache():
        return _diagnose_client_impl(client, mac, hours=hours)


def _diagnose_client_impl(
    client: OmadaClient,
    mac: str,
    hours: int = 24,
) -> Dict[str, Any]:
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 0:
        raise OmadaError("hours must be a non-negative integer")
    site = _site(client)
    warnings: List[str] = []
    wanted_mac = normalize_mac(mac)
    needle = str(mac or "").strip().lower()

    matched_live: Optional[Dict[str, Any]] = None
    for entry in _fetch_clients(client, limit=0):
        if normalize_mac(entry.get("mac", "")) == wanted_mac:
            matched_live = entry
            break
        if needle and needle in (
            str(entry.get("name", "")).lower(),
            str(entry.get("hostName", "")).lower(),
            str(entry.get("ip", "")).lower(),
        ):
            matched_live = entry
            break

    target_mac = normalize_mac(matched_live["mac"]) if matched_live else wanted_mac
    detail_raw: Dict[str, Any] = {}
    if len(target_mac) == 17 and ":" in target_mac:
        raw_d, ok_d = try_api_result(
            client, f"sites/{site.site_id}/clients/{omada_mac(target_mac)}",
            warnings, label="client detail",
        )
        if ok_d and isinstance(raw_d, dict):
            detail_raw = raw_d

    search_key = omada_mac(target_mac) if ":" in target_mac else str(mac).strip()
    past_rows, _, ok_past = try_paginate(
        client, f"sites/{site.site_id}/insight/pastConnection?searchKey={search_key}",
        warnings, label="client connection history", page_size=20, max_pages=1,
    )
    past_connections = [deep_redact(r) for r in past_rows[:20]] if ok_past else []

    if matched_live is None and not detail_raw and not past_connections:
        raise OmadaError(
            f"no client matches {mac!r}",
            hint="check list_clients; accepts MAC, hostname, or IP",
        )

    base = matched_live or {}
    c_mac = normalize_mac(str(detail_raw.get("mac") or base.get("mac") or target_mac))
    c_name = str(detail_raw.get("name") or base.get("name") or detail_raw.get("hostName") or c_mac)
    c_host = str(detail_raw.get("hostName") or base.get("hostName") or "")
    c_ip = str(detail_raw.get("ip") or base.get("ip") or "")
    is_wireless = bool(detail_raw.get("wireless") if "wireless" in detail_raw else base.get("wireless", False))
    if not matched_live and not detail_raw and past_connections:
        latest = past_connections[0]
        is_wireless = bool(latest.get("ssid"))
        c_name = str(latest.get("name") or latest.get("hostName") or c_name)
        c_ip = str(latest.get("ip") or c_ip)

    rssi = detail_raw.get("rssi") if detail_raw.get("rssi") is not None else detail_raw.get("signalLevel")
    if rssi is None:
        rssi = base.get("signal")
    snr = detail_raw.get("snr")
    radio_id = detail_raw.get("radioId")
    channel = detail_raw.get("channel")
    ap_mac = normalize_mac(str(detail_raw.get("apMac") or ""))
    ap_name = str(detail_raw.get("apName") or (base.get("apName") if is_wireless else "") or "")
    switch_mac = normalize_mac(str(detail_raw.get("switchMac") or ""))
    switch_name = str(detail_raw.get("switchName") or (base.get("apName") if not is_wireless else "") or "")
    switch_port = detail_raw.get("port")
    rate_limit = detail_raw.get("rateLimit") if isinstance(detail_raw.get("rateLimit"), dict) else {}

    client_summary: Dict[str, Any] = {
        "mac": c_mac,
        "name": c_name,
        "hostName": c_host,
        "ip": c_ip,
        "active": bool(detail_raw.get("active", bool(matched_live or detail_raw))),
        "wireless": is_wireless,
        "ssid": str(detail_raw.get("ssid") or base.get("ssid") or ""),
        "apMac": ap_mac,
        "apName": ap_name,
        "switchMac": switch_mac,
        "switchName": switch_name,
        "port": switch_port,
        "vlan": _as_int(_pick(detail_raw, "vid", "vlan", default=base.get("vlan") or 0), 0),
        "radioId": radio_id,
        "channel": channel,
        "rssi": rssi,
        "signalLevel": detail_raw.get("signalLevel") if detail_raw.get("signalLevel") is not None else base.get("signal"),
        "snr": snr,
        "rxRateKbps": detail_raw.get("rxRate"),
        "txRateKbps": detail_raw.get("txRate"),
        "uptimeSec": detail_raw.get("uptime") if detail_raw.get("uptime") is not None else base.get("duration"),
        "rateLimitEnabled": bool(rate_limit.get("enable", False)),
        "rateLimit": deep_redact(rate_limit) if rate_limit else None,
        "lockToApMac": normalize_mac(str(detail_raw.get("lockToApMac") or "")) if detail_raw.get("lockToApMac") else "",
    }

    try:
        raw_devices = _fetch_devices(client, site)
    except OmadaError:
        raw_devices = []

    parent_radio: Optional[Dict[str, Any]] = None
    parent_switch_port: Optional[Dict[str, Any]] = None

    if is_wireless and (ap_mac or ap_name):
        ap_dev = next(
            (d for d in raw_devices
             if str(d.get("type") or "").lower() == "ap"
             and ((ap_mac and normalize_mac(str(d.get("mac") or "")) == ap_mac)
                  or (ap_name and str(d.get("name") or "").lower() == ap_name.lower()))),
            None,
        )
        if ap_dev is not None:
            ap_data = collect_ap_radios_data(
                client, site, ap_dev, include_rf_scan=False, include_available_channels=False,
            )
            warnings.extend(ap_data.get("warnings") or [])
            band_hint = {0: "2g", 1: "5g", 2: "5g2", 3: "6g"}.get(as_int_or_none(radio_id))
            for r in ap_data.get("radios") or []:
                if (band_hint and r["band"] == band_hint) or (channel is not None and r.get("channel") == channel):
                    parent_radio = r
                    break
            if parent_radio is None and ap_data.get("radios"):
                parent_radio = ap_data["radios"][0]

    elif not is_wireless and (switch_mac or switch_name):
        sw_dev = next(
            (d for d in raw_devices
             if str(d.get("type") or "").lower() == "switch"
             and ((switch_mac and normalize_mac(str(d.get("mac") or "")) == switch_mac)
                  or (switch_name and str(d.get("name") or "").lower() == switch_name.lower()))),
            None,
        )
        if sw_dev is not None:
            sw_data = collect_switch_ports_data(
                client, site, sw_dev, include_counters=True, include_cable_test=True, include_topology=False,
            )
            warnings.extend(sw_data.get("warnings") or [])
            if switch_port is not None:
                pnum = _as_int(switch_port, -1)
                parent_switch_port = next(
                    (p for p in (sw_data.get("ports") or []) if p.get("port") == pnum), None,
                )

    match_tokens = {
        tok.lower()
        for tok in (
            c_mac, omada_mac(c_mac), c_name, c_host, c_ip,
            ap_mac, omada_mac(ap_mac), ap_name, switch_mac, switch_name,
        )
        if tok
    }
    all_logs = _safe_recent_logs(client, hours, warnings)
    recent_logs = [
        entry for entry in all_logs
        if any(
            tok in f"{entry.get('target', '')} {entry.get('content', '')}".lower()
            for tok in match_tokens
        )
    ][:25]

    findings: List[Dict[str, str]] = []
    next_steps: List[str] = []

    if not client_summary["active"]:
        findings.append({
            "code": "CLIENT_OFFLINE",
            "severity": "warning",
            "detail": f"Client {c_name} ({c_mac}) is not currently active on the live client table.",
        })
        next_steps.append("Check physical link/Wi-Fi radio availability or review recent pastConnection entries.")

    if is_wireless:
        rssi_val = _as_float(rssi)
        if rssi_val is not None and rssi_val < 0:
            if rssi_val <= -82:
                findings.append({
                    "code": "CLIENT_CRITICAL_RSSI",
                    "severity": "critical",
                    "detail": f"Client RSSI is critically weak ({rssi_val} dBm on {ap_name or ap_mac}).",
                })
                next_steps.append("Move client closer to an AP, check AP TX power, or bind client to a closer AP with set_client_lock_to_ap.")
            elif rssi_val <= -75:
                findings.append({
                    "code": "CLIENT_WEAK_RSSI",
                    "severity": "warning",
                    "detail": f"Client RSSI is marginal ({rssi_val} dBm on {ap_name or ap_mac}).",
                })
                next_steps.append("Evaluate 2.4GHz fallback vs closer AP placement to improve RSSI above -72 dBm.")
        snr_val = _as_float(snr)
        if snr_val is not None and snr_val < 15:
            findings.append({
                "code": "CLIENT_LOW_SNR",
                "severity": "warning",
                "detail": f"Client SNR is low ({snr_val} dB), indicating noise or weak signal.",
            })

    if parent_radio:
        inter = _as_float(parent_radio.get("interferencePct"))
        tx_ret = _as_float(parent_radio.get("txRetryRatePct"))
        rx_ret = _as_float(parent_radio.get("rxRetryRatePct"))
        if inter is not None and inter >= 30.0:
            findings.append({
                "code": "AP_RADIO_HIGH_INTERFERENCE",
                "severity": "warning",
                "detail": f"Parent AP {parent_radio['band']} radio channel {parent_radio['channel']} reports {inter}% interference.",
            })
            next_steps.append(f"Run start_rf_scan on AP {ap_name or ap_mac} and move to a cleaner channel with update_ap_radio.")
        if (tx_ret is not None and tx_ret >= 15.0) or (rx_ret is not None and rx_ret >= 20.0):
            findings.append({
                "code": "AP_RADIO_HIGH_RETRIES",
                "severity": "warning",
                "detail": f"Parent AP {parent_radio['band']} retry rate is high (tx={tx_ret}%, rx={rx_ret}%).",
            })

    if parent_switch_port:
        if not parent_switch_port.get("linkUp"):
            findings.append({
                "code": "SWITCH_PORT_LINK_DOWN",
                "severity": "critical",
                "detail": f"Parent switch port {parent_switch_port['port']} link is down.",
            })
        elif parent_switch_port.get("maxSpeedMbps", 0) >= 1000 and 0 < parent_switch_port.get("speedMbps", 0) <= 100:
            findings.append({
                "code": "SWITCH_PORT_SPEED_DOWNGRADED",
                "severity": "warning",
                "detail": f"Switch port {parent_switch_port['port']} negotiated {parent_switch_port['speed']} on a {parent_switch_port['maxSpeed']} port.",
            })
            next_steps.append("Inspect Ethernet cable/termination or check switch port speed/duplex configuration.")
        if parent_switch_port.get("stpDiscarding"):
            findings.append({
                "code": "SWITCH_PORT_STP_DISCARDING",
                "severity": "critical",
                "detail": f"Switch port {parent_switch_port['port']} is in STP discarding state (loop protection active).",
            })
        cnt = parent_switch_port.get("counters") or {}
        errs = _as_int(cnt.get("rxErrors"), 0) + _as_int(cnt.get("txErrors"), 0)
        drops = _as_int(cnt.get("rxDrops"), 0) + _as_int(cnt.get("txDrops"), 0)
        if errs > 0 or drops > 0:
            findings.append({
                "code": "SWITCH_PORT_PACKET_ERRORS",
                "severity": "warning",
                "detail": f"Switch port {parent_switch_port['port']} counters show errors={errs}, drops={drops}.",
            })

    if client_summary["rateLimitEnabled"]:
        findings.append({
            "code": "CLIENT_RATE_LIMITED",
            "severity": "info",
            "detail": "A client bandwidth rate limit is active on this client.",
        })

    if not next_steps:
        next_steps.append("No critical link faults detected; monitor recentLogs and pastConnections for intermittent drops.")

    return {
        "client": client_summary,
        "parentRadio": parent_radio,
        "parentSwitchPort": parent_switch_port,
        "pastConnections": past_connections,
        "recentLogs": recent_logs,
        "findings": findings,
        "nextSteps": next_steps,
        "warnings": warnings,
    }


def as_int_or_none(val: Any) -> Optional[int]:
    if val is None or isinstance(val, bool):
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _diagnose_wan(
    client: OmadaClient,
    includeSpeedtest: bool = True,
    hours: int = 24,
) -> Dict[str, Any]:
    with client.scoped_cache():
        return _diagnose_wan_impl(client, includeSpeedtest=includeSpeedtest, hours=hours)


def _diagnose_wan_impl(
    client: OmadaClient,
    includeSpeedtest: bool = True,
    hours: int = 24,
) -> Dict[str, Any]:
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 0:
        raise OmadaError("hours must be a non-negative integer")
    site = _site(client)
    warnings: List[str] = []
    wan = collect_wan_status_data(client, site, include_speedtest=bool(includeSpeedtest))
    warnings.extend(wan.get("warnings") or [])

    vpn = collect_vpn_tunnels_data(client, site, has_gateway=bool(wan.get("hasGateway")))
    vpn_counts = vpn.get("counts") or {}
    vpn_summary = {
        "activeOrStatTunnels": vpn_counts.get("activeOrStatTunnels", 0),
        "upTunnels": vpn_counts.get("upTunnels", 0),
        "configuredEntries": vpn_counts.get("configuredEntries", 0),
    }

    gw_tokens = {
        tok.lower()
        for tok in ("wan", "gateway", "internet", "pppoe", "failover", "vpn", "speedtest",
                    wan.get("gatewayName", ""), wan.get("gatewayMac", ""))
        if tok
    }
    all_logs = _safe_recent_logs(client, hours, warnings)
    recent_logs = [
        entry for entry in all_logs
        if any(
            tok in f"{entry.get('target', '')} {entry.get('module', '')} {entry.get('content', '')}".lower()
            for tok in gw_tokens
        )
    ][:25]

    findings: List[Dict[str, str]] = []
    next_steps: List[str] = []
    ports = wan.get("ports") or []

    if not wan.get("hasGateway"):
        findings.append({
            "code": "WAN_NO_GATEWAY",
            "severity": "info",
            "detail": "No Omada gateway is adopted on this site; WAN diagnostics are limited.",
        })
    else:
        if ports and wan.get("internetUpCount", 0) == 0:
            findings.append({
                "code": "WAN_ALL_LINKS_DOWN",
                "severity": "critical",
                "detail": "All gateway WAN ports report internet offline.",
            })
            next_steps.append("Check ISP modem/fiber link, physical WAN cable, and gateway PPPoE/DHCP authentication.")
        for p in ports:
            if p.get("enabled", True) and not p.get("linkUp"):
                findings.append({
                    "code": "WAN_PORT_LINK_DOWN",
                    "severity": "warning",
                    "detail": f"WAN port {p['port']} ({p['name']}) physical link is down.",
                })
            elif p.get("linkUp") and not p.get("internetUp"):
                findings.append({
                    "code": "WAN_PORT_INTERNET_OFFLINE",
                    "severity": "warning",
                    "detail": f"WAN port {p['port']} ({p['name']}) is linked up ({p['speed']}) but online detection reports internet offline.",
                })
                next_steps.append(f"Check gateway online detection target and upstream ISP routing on {p['name']}.")
            lat = _as_float(p.get("latencyMs"))
            if lat is not None and lat >= 100.0:
                findings.append({
                    "code": "WAN_HIGH_LATENCY",
                    "severity": "warning",
                    "detail": f"WAN port {p['name']} reports elevated latency ({lat} ms).",
                })
            loss = _as_float(p.get("lossPct"))
            if loss is not None and loss > 0.5:
                findings.append({
                    "code": "WAN_PACKET_LOSS",
                    "severity": "warning" if loss < 5.0 else "critical",
                    "detail": f"WAN port {p['name']} reports {loss}% packet loss.",
                })
            errs = _as_int(p.get("rxErrorPkts"), 0) + _as_int(p.get("txErrorPkts"), 0)
            if errs > 0:
                findings.append({
                    "code": "WAN_INTERFACE_ERRORS",
                    "severity": "warning",
                    "detail": f"WAN port {p['name']} reports {errs} packet errors.",
                })

    if not next_steps:
        next_steps.append("WAN links look operational; inspect latency, packet loss, and recent gateway logs if users report intermittent drops.")

    return {
        "wan": wan,
        "vpnSummary": vpn_summary,
        "recentLogs": recent_logs,
        "findings": findings,
        "nextSteps": next_steps,
        "warnings": warnings,
    }


def _list_port_profiles(client: OmadaClient) -> List[Dict[str, Any]]:
    site = _site(client)
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/lan/profiles")
    projected: List[Dict[str, Any]] = []
    for row in rows:
        ptype = row.get("type")
        projected.append({
            "id": str(row.get("id") or ""),
            "name": str(row.get("name") or ""),
            "type": ptype,
            "typeLabel": PROFILE_TYPE_LABELS.get(as_int_or_none(ptype) if ptype is not None else -1, str(ptype)),
            "prohibitModify": bool(row.get("prohibitModify", False)),
            "poe": row.get("poe"),
            "vlanConfigEnable": bool(row.get("vlanConfigEnable", False)),
            "nativeNetworkId": str(row.get("nativeNetworkId") or ""),
            "tagNetworkIds": [str(x) for x in (row.get("tagNetworkIds") or [])],
            "untagNetworkIds": [str(x) for x in (row.get("untagNetworkIds") or [])],
            "portIsolationEnable": bool(row.get("portIsolationEnable", False)),
            "lldpMedEnable": bool(row.get("lldpMedEnable", False)),
            "spanningTreeEnable": bool(row.get("spanningTreeEnable", False)),
            "dot1x": row.get("dot1x"),
        })
    return projected


def _list_wlan_groups(client: OmadaClient) -> List[Dict[str, Any]]:
    site = _site(client)
    groups, _ = client.paginate(f"sites/{site.site_id}/setting/wlans")
    warnings: List[str] = []
    ssid_groups, _, ok_ws = try_paginate(
        client, f"sites/{site.site_id}/wlanSsid", warnings, label="wlanSsid",
    )
    ssids_by_gid: Dict[str, List[Dict[str, Any]]] = {}
    if ok_ws:
        for entry in ssid_groups:
            gid = str(entry.get("wlanId") or "")
            raw_ssids = entry.get("ssids") or []
            if gid and isinstance(raw_ssids, list):
                ssids_by_gid[gid] = [
                    {
                        "id": str(s.get("id") or ""),
                        "name": str(s.get("name") or s.get("ssid") or ""),
                        "band": s.get("band"),
                        "enabled": bool(s.get("broadcast", s.get("enabled", True))),
                    }
                    for s in raw_ssids if isinstance(s, dict)
                ]
    out: List[Dict[str, Any]] = []
    for grp in groups:
        gid = str(grp.get("id") or "")
        slist = ssids_by_gid.get(gid, [])
        if not slist:
            try:
                raw_s = _fetch_ssids(client, site, gid)
                slist = [
                    {
                        "id": str(s.get("id") or ""),
                        "name": str(s.get("name") or s.get("ssid") or ""),
                        "band": s.get("band"),
                        "enabled": bool(s.get("broadcast", s.get("enabled", True))),
                    }
                    for s in raw_s
                ]
            except OmadaError:
                slist = []
        out.append({
            "id": gid,
            "name": str(grp.get("name") or ""),
            "primary": bool(grp.get("primary", False)),
            "clone": bool(grp.get("clone", False)),
            "ssidCount": len(slist),
            "ssids": slist,
        })
    return out


def _list_policy_routes(client: OmadaClient) -> Dict[str, Any]:
    site = _site(client)
    warnings: List[str] = []
    rows, _, ok = try_paginate(
        client, f"sites/{site.site_id}/setting/transmission/policyRoutings",
        warnings, label="policy routes",
    )
    cleaned = [project_controller_row("policyRoutes", r) for r in rows] if ok else []
    return {
        "items": cleaned,
        "count": len(cleaned),
        "supported": ok,
        "warnings": warnings,
    }


def _list_lan_dns_rules(client: OmadaClient) -> Dict[str, Any]:
    site = _site(client)
    warnings: List[str] = []
    rows, _, ok = try_paginate(
        client, f"sites/{site.site_id}/setting/lan/dns",
        warnings, label="LAN DNS rules",
    )
    cleaned = [project_controller_row("lanDnsRules", r) for r in rows] if ok else []
    return {
        "items": cleaned,
        "count": len(cleaned),
        "supported": ok,
        "warnings": warnings,
    }


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
        description=("One-call read-only health audit checking WAN state/packet loss, offline "
                    "devices, pending firmware upgrades, switch PoE budget and downgraded "
                    "uplinks, AP retry/interference spikes, 0-client APs, guest/unexpected "
                    "VLAN clients, unisolated VLANs, and DHCP pool utilization."),
        input_schema=_EMPTY,
        output_schema=_NETWORK_AUDIT_SCHEMA,
        handler=_network_audit_enriched,
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
            "VLAN/network, with active/wireless/guest filters plus exact vlan and ssid "
            "filters. Prefers the rich clients endpoint (ssid, ip, apName, signal) and falls "
            "back to insight/clients for Viewer accounts."
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
                "vlan": {
                    "type": "integer",
                    "description": "Filter by VLAN id (exact), e.g. 20",
                },
                "ssid": {
                    "type": "string",
                    "description": "Filter by SSID name (case-insensitive; exact match preferred)",
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
        title="List firewall ACL rules",
        description=(
            "List gateway, switch, or EAP ACL rules (setting/firewall/acls?type=0|1|2) with "
            "policy, source/destination IDs, direction, protocols, and per-rule status. "
            "Defaults to gateway ACLs for backward compatibility; pass aclType='all' for all scopes. "
            "Note: use get_config_snapshot(objects=['acls']) to inspect the advisory aclDisable flag."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "aclType": {
                    "type": "string",
                    "enum": ["gateway", "switch", "eap", "all"],
                    "default": "gateway",
                    "description": "ACL scope: 'gateway' (default), 'switch', 'eap', or 'all'",
                },
            },
        },
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
            "configuration, and sanitized WAN port status (enriched with live WAN link/latency metrics)."
        ),
        input_schema=_EMPTY,
        output_schema=_SERVICES_SCHEMA,
        handler=_get_network_services_enriched,
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
        name="get_switch_ports",
        title="Get switch ports, PoE & diagnostics",
        description=(
            "Inspect per-port link status, speed/duplex, PoE delivery & switch budget, active "
            "port profile/VLANs, error/drop counters, cable test results, LAGs, uplinks, and controller port."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Managed switch MAC address or exact name"},
                "includeCounters": {
                    "type": "boolean", "default": True,
                    "description": "Fetch RX/TX byte, frame, and error counters (default true)",
                },
                "includeCableTest": {
                    "type": "boolean", "default": True,
                    "description": "Include cached cable-test results if supported and previously triggered on the switch (default true)",
                },
                "includeDownPorts": {
                    "type": "boolean", "default": True,
                    "description": "Include down/unlinked ports in output (default true)",
                },
                "compact": {
                    "type": "boolean", "default": False,
                    "description": "Trim zero counters and empty cableTest/VLAN fields (default false)",
                },
            },
            "required": ["mac"],
        },
        output_schema=_SWITCH_PORTS_SCHEMA,
        handler=_get_switch_ports,
    ),
    Tool(
        name="get_ap_radios",
        title="Get AP radio & channel state",
        description=(
            "Inspect an AP's 2.4G/5G/5G2/6G radios: channel, width, TX power, channel utilization, "
            "interference, retry/drop counters, supported channels, and latest RF scan."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Managed access point MAC address or exact name"},
                "includeRfScan": {"type": "boolean", "default": True},
                "includeAvailableChannels": {"type": "boolean", "default": True},
            },
            "required": ["mac"],
        },
        output_schema=_AP_RADIOS_SCHEMA,
        handler=_get_ap_radios,
    ),
    Tool(
        name="get_rf_scan",
        title="Get AP RF scan results",
        description="Read the latest cached RF scan status/neighbor results (empty channels list if no scan was triggered) and per-radio utilization for an AP.",
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Managed access point MAC address or exact name"},
            },
            "required": ["mac"],
        },
        output_schema=_RF_SCAN_SCHEMA,
        handler=_get_rf_scan,
    ),
    Tool(
        name="get_wan_status",
        title="Get live WAN link & health status",
        description=(
            "Inspect gateway WAN link state, gateway/DNS/WAN IP, failover/load-balance mode, "
            "latency/packet loss health metrics, and latest speedtest results."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "includeSpeedtest": {"type": "boolean", "default": True},
                "maskWanIp": {
                    "type": "boolean", "default": False,
                    "description": "Mask public WAN host octets when sharing diagnostics (default false)",
                },
            },
        },
        output_schema=_WAN_STATUS_SCHEMA,
        handler=_get_wan_status,
    ),
    Tool(
        name="list_vpn_tunnels",
        title="List VPN tunnels & secret-redacted configs",
        description=(
            "List WireGuard, OpenVPN, IPsec, and SSL/L2TP VPN tunnel state and configured profiles "
            "(all private keys, PSKs, and passwords redacted)."
        ),
        input_schema=_EMPTY,
        output_schema=_VPN_TUNNELS_SCHEMA,
        handler=_list_vpn_tunnels,
    ),
    Tool(
        name="get_topology",
        title="Get site uplink topology tree",
        description="Build the site's Gateway -> Switch(port) -> AP/Switch uplink tree with device counts.",
        input_schema={
            "type": "object",
            "properties": {
                "includeClients": {
                    "type": "boolean", "default": False,
                    "description": "Include leaf client nodes in the tree (default false)",
                },
            },
        },
        output_schema=_TOPOLOGY_SCHEMA,
        handler=_get_topology,
    ),
    Tool(
        name="get_security_status",
        title="Get IPS/IDS, WIDS & rogue AP status",
        description=(
            "Summarize IPS/IDS enablement, recent threat events, attack defense limits, WIDS/WIPS, "
            "and rogue AP detections (gracefully warns when hardware/feature is unavailable)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 0, "default": 24},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
            },
        },
        output_schema=_SECURITY_STATUS_SCHEMA,
        handler=_get_security_status,
    ),
    Tool(
        name="diagnose_client",
        title="Diagnose a WiFi or wired client",
        description=(
            "Correlate client signal/link state, connection history, parent AP radio or switch port "
            "telemetry, and recent logs into actionable diagnostic findings."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC (any format), hostname, or IP"},
                "hours": {"type": "integer", "minimum": 0, "default": 24},
            },
            "required": ["mac"],
        },
        output_schema=_DIAGNOSE_CLIENT_SCHEMA,
        handler=_diagnose_client,
    ),
    Tool(
        name="diagnose_wan",
        title="Diagnose gateway WAN & VPN health",
        description=(
            "Correlate live WAN link state, latency/packet loss, speedtest, VPN tunnel health, "
            "and gateway alerts/events into deterministic findings."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "includeSpeedtest": {"type": "boolean", "default": True},
                "hours": {"type": "integer", "minimum": 0, "default": 24},
            },
        },
        output_schema=_DIAGNOSE_WAN_SCHEMA,
        handler=_diagnose_wan,
    ),
    Tool(
        name="list_port_profiles",
        title="List switch LAN port profiles",
        description="List switch port profiles (All, Disable, custom VLAN/PoE profiles).",
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_PORT_PROFILE_SCHEMA),
        handler=_list_port_profiles,
    ),
    Tool(
        name="list_wlan_groups",
        title="List WLAN groups & SSID bindings",
        description="List configured WLAN groups and their SSIDs for assigning APs cleanly.",
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_WLAN_GROUP_SCHEMA),
        handler=_list_wlan_groups,
    ),
    Tool(
        name="list_policy_routes",
        title="List gateway policy routing rules",
        description="List policy routing rules (gracefully reports unavailability if no gateway exists).",
        input_schema=_EMPTY,
        output_schema=_SUPPORTED_ITEMS_SCHEMA,
        handler=_list_policy_routes,
    ),
    Tool(
        name="list_lan_dns_rules",
        title="List local LAN DNS rules",
        description="List local LAN DNS records (gracefully warns on controller versions without LAN DNS).",
        input_schema=_EMPTY,
        output_schema=_SUPPORTED_ITEMS_SCHEMA,
        handler=_list_lan_dns_rules,
    ),
    Tool(
        name="set_client_fixed_ip",
        title="Set client DHCP reservation",
        description=(
            "Assign a DHCP fixed IPv4 reservation on a client (PATCH clients/{MAC}). "
            "Lease-delayed; strips volatile keys and refuses managed device MACs (-41011). "
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
                            "start": {"type": "string"},
                            "end": {"type": "string"},
                        },
                        "anyOf": [
                            {"required": ["ipaddrStart", "ipaddrEnd"]},
                            {"required": ["start", "end"]},
                        ],
                    },
                    "description": (
                        "Non-empty list of DHCP pools. Either the controller field names "
                        "{ipaddrStart, ipaddrEnd} or the shorthand {start, end} that "
                        "list_lan_networks returns is accepted (issue #4)."
                    ),
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
            "(-33726)."
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
            "checks for management hosts."
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
                        "type": {
                            "type": ["string", "integer"],
                            "description": "0=network, 1=ip_group, 2=port_group",
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "Source selector: {'type': 'network'|'ip_group'|'port_group'|0|1|2, 'ids': [...]}",
                },
                "destination": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": ["string", "integer"],
                            "description": "0=network, 1=ip_group, 2=port_group",
                        },
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
        title="Enable or disable ACL rule (gateway, switch, or EAP)",
        description=(
            "Enable or disable a gateway, switch, or EAP ACL rule status without changing aclDisable."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "ACL rule ID or exact name"},
                "status": {"type": "boolean", "description": "True to enable, false to disable"},
                "aclType": {
                    "type": "string",
                    "enum": ["gateway", "switch", "eap"],
                    "description": "ACL scope (auto-detected if omitted)",
                },
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
                        "properties": {
                            "ipaddrStart": {"type": "string"},
                            "ipaddrEnd": {"type": "string"},
                            "start": {"type": "string"},
                            "end": {"type": "string"},
                        },
                        "anyOf": [
                            {"required": ["ipaddrStart", "ipaddrEnd"]},
                            {"required": ["start", "end"]},
                        ],
                    },
                    "description": (
                        "Optional DHCP pools. Either the controller field names "
                        "{ipaddrStart, ipaddrEnd} or the shorthand {start, end} that "
                        "list_lan_networks returns is accepted, so a reader's output can be "
                        "fed straight into a create."
                    ),
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
            "the MCP host/management IP)."
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
        title="Update ACL rule (gateway, switch, or EAP)",
        description=(
            "Modify name, status, policy, endpoints, protocols, or syslog on an existing gateway, switch, or EAP ACL."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "ACL rule ID or exact name"},
                "aclType": {
                    "type": "string",
                    "enum": ["gateway", "switch", "eap"],
                    "description": "ACL scope (auto-detected if omitted)",
                },
                "name": {"type": "string", "description": "New ACL rule name"},
                "status": {"type": "boolean", "description": "Enable or disable rule"},
                "policy": {"type": ["string", "integer"], "description": "'deny' (0) or 'permit' (1)"},
                "source": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": ["string", "integer"],
                            "description": "0=net,1=ip_grp,2=port_grp,3=mac_grp,4=ssid",
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "Updated source selector",
                },
                "destination": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": ["string", "integer"],
                            "description": "0=net,1=ip_grp,2=port_grp,3=mac_grp,4=ssid",
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
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
        title="Delete ACL rule (gateway, switch, or EAP)",
        description=(
            "Delete a gateway, switch, or EAP ACL rule by ID or exact name (DELETE setting/firewall/acls/{id}?type=0|1|2)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "ACL rule ID or exact name"},
                "aclType": {
                    "type": "string",
                    "enum": ["gateway", "switch", "eap"],
                    "description": "ACL scope (auto-detected if omitted)",
                },
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
            "in diffs, snapshots, or outputs."
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
                    "enum": ["open", "wpa-psk", "wpa2-psk", "wpa-wpa2-psk", "wpa3-sae"],
                    "default": "wpa2-psk",
                    "description": "Security mode: 'open', 'wpa-psk', 'wpa2-psk', 'wpa-wpa2-psk', or 'wpa3-sae'",
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
            "PSK redaction in snapshots/outputs."
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
            "Enable or disable UPnP on the site gateway (PUT setting/upnp; auto-selects WAN port and LANs when enabled)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "enable": {"type": "boolean", "description": "True to enable UPnP, false to disable"},
                "wanPortIds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional WAN port UUIDs when enabling UPnP",
                },
                "networkIds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional LAN IDs, VLANs, or names when enabling UPnP",
                },
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
            "managed devices)."
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
            "(POST cmd/clients/{MAC}/reconnect)."
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
            "Disruptive action; requires confirmation."
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
    Tool(
        name="rollback_from_snapshot",
        title="Rollback change from pre-mutation snapshot",
        description=(
            "Replay or revert a prior write operation from a snapshot JSON inside OMADA_SNAPSHOT_DIR. "
            "dryRun=true diffs stored pre-mutation state against current live controller state; "
            "dryRun=false applies the restore/delete and verifies read-back."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "snapshotId": {"type": "string", "description": "Snapshot filename (.json) inside OMADA_SNAPSHOT_DIR"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["snapshotId"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=rollback_from_snapshot,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="update_switch_port",
        title="Update switch port configuration",
        description=(
            "Configure switch port status, name, port profile, PoE, speed/duplex, VLAN overrides, or isolation. "
            "Refuses mutating uplink, LAG member, or controller-hosting ports unless allowUplinkMutation=true. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Managed switch MAC address or exact name"},
                "port": {"type": "integer", "minimum": 1, "description": "1-based switch port number"},
                "enabled": {"type": "boolean", "description": "Enable/disable port link (disabling switches to Disable profile)"},
                "name": {"type": "string", "description": "Port label/description"},
                "profileId": {"type": "string", "description": "Port profile UUID to assign"},
                "profileName": {"type": "string", "description": "Port profile name to assign"},
                "profileOverrideEnable": {"type": "boolean", "description": "Enable per-port profile override"},
                "poeEnabled": {"type": "boolean", "description": "Enable/disable PoE on this port (sets override mode)"},
                "linkSpeed": {"type": ["string", "integer"], "description": "'auto', '10m', '100m', '1000m', '2500m', '10g' or code"},
                "duplex": {"type": ["string", "integer"], "description": "'auto', 'half', 'full' or code"},
                "nativeNetworkId": {"type": "string", "description": "Override native/untagged network ID"},
                "taggedNetworkIds": {"type": "array", "items": {"type": "string"}, "description": "Override tagged network IDs"},
                "untaggedNetworkIds": {"type": "array", "items": {"type": "string"}, "description": "Override additional untagged network IDs"},
                "portIsolationEnable": {"type": "boolean", "description": "Enable/disable L2 port isolation"},
                "lldpMedEnable": {"type": "boolean", "description": "Enable/disable LLDP-MED"},
                "spanningTreeEnable": {"type": "boolean", "description": "Enable/disable STP on port"},
                "allowUplinkMutation": {"type": "boolean", "default": False, "description": "Explicitly allow mutating detected uplink/LAG/controller port"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "port"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_switch_port,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="cycle_poe_port",
        title="Power-cycle PoE switch port",
        description=(
            "Momentarily power-cycle PoE output on a switch port (POST cmd/switches/{MAC}/ports/{port}/restart). "
            "Warns when downstream adopted AP/switch is powered, and guards uplink/controller-host ports unless allowUplinkMutation=true."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Managed switch MAC address or exact name"},
                "port": {"type": "integer", "minimum": 1, "description": "1-based switch port number"},
                "allowUplinkMutation": {"type": "boolean", "default": False, "description": "Override uplink/LAG/controller-port guard"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "port"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=cycle_poe_port,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="upsert_port_profile",
        title="Create or update switch port profile",
        description=(
            "Create or update a wired LAN switch port profile (setting/lan/profiles). "
            "Refuses modifying protected built-in profiles (prohibitModify=true). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Port profile name"},
                "profileId": {"type": "string", "description": "Existing profile UUID when updating/renaming"},
                "poeMode": {"type": ["string", "integer"], "description": "'off' (0), 'on'/'poe' (1), 'poe+'/'keep' (2)"},
                "nativeNetworkId": {"type": "string", "description": "Native LAN/VLAN network ID"},
                "nativeNetworkName": {"type": "string", "description": "Native LAN/VLAN network name"},
                "taggedNetworkIds": {"type": "array", "items": {"type": "string"}, "description": "Tagged VLAN network IDs"},
                "untaggedNetworkIds": {"type": "array", "items": {"type": "string"}, "description": "Untagged VLAN network IDs"},
                "portIsolationEnable": {"type": "boolean"},
                "lldpMedEnable": {"type": "boolean"},
                "spanningTreeEnable": {"type": "boolean"},
                "loopbackDetectEnable": {"type": "boolean"},
                "flowControlEnable": {"type": "boolean"},
                "eeeEnable": {"type": "boolean"},
                "dot1x": {"type": "integer"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_port_profile,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_port_profile",
        title="Delete switch port profile",
        description=(
            "Delete a custom wired LAN switch port profile by ID or exact name "
            "(DELETE setting/lan/profiles/{id}). Refuses built-in protected profiles."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "profile": {"type": "string", "description": "Port profile ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["profile"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_port_profile,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="update_ap_radio",
        title="Update AP radio channel, width, or TX power",
        description=(
            "Update one band ('2g', '5g', '5g2', '6g') of an adopted AP while preserving sibling band blocks "
            "(PUT eaps/{MAC}/config/radios). Validates channel/channelWidth against AP channelInfo first."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Adopted AP MAC address or exact name"},
                "band": {"type": "string", "enum": ["2g", "5g", "5g1", "5g2", "6g"], "description": "Target radio band"},
                "enabled": {"type": "boolean", "description": "Enable/disable this radio band"},
                "channel": {"type": ["string", "integer"], "description": "Channel number or 'auto'"},
                "channelWidth": {"type": "string", "description": "Width: 'auto', '20', '40', '80', '160', '320' (or 20MHz..320MHz)"},
                "txPowerLevel": {"type": ["string", "integer"], "description": "'low' (0), 'medium' (1), 'high' (2), 'custom' (3), 'auto' (4)"},
                "txPower": {"type": "integer", "description": "Custom dBm TX power when txPowerLevel='custom'"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "band"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_ap_radio,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="start_rf_scan",
        title="Start AP RF environment scan",
        description=(
            "Trigger an RF spectrum scan on an adopted AP (POST cmd/eaps/{MAC}/tools/rfScan). "
            "Briefly interrupts client service while scanning."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Adopted AP MAC address or exact name"},
                "bands": {"type": "array", "items": {"type": "string"}, "description": "Optional list of bands e.g. ['2g','5g']"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=start_rf_scan,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="assign_ap_wlan_group",
        title="Assign WLAN group to AP",
        description=(
            "Assign a WLAN group by ID or exact name to an adopted AP (PUT eaps/{MAC}/config/wlans) "
            "while preserving existing ssidOverrides."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Adopted AP MAC address or exact name"},
                "wlanGroup": {"type": "string", "description": "Target WLAN group ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "wlanGroup"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=assign_ap_wlan_group,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="upsert_policy_route",
        title="Create or update gateway policy route",
        description=(
            "Create or update a gateway PBR / policy routing rule (setting/transmission/policyRoutings). "
            "Requires an adopted gateway."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Policy route name"},
                "routeId": {"type": "string", "description": "Existing policy route ID when updating"},
                "status": {"type": "boolean", "default": True},
                "protocols": {"type": "array", "items": {"type": "integer"}, "description": "IP protocol numbers e.g. [6, 17]"},
                "sourceType": {"type": "integer", "default": 0, "description": "0=Network, 1=IP Group"},
                "sourceIds": {"type": "array", "items": {"type": "string"}},
                "destinationType": {"type": "integer", "default": 1, "description": "0=Network, 1=IP Group, 2=IP-Port Group"},
                "destinationIds": {"type": "array", "items": {"type": "string"}},
                "interfaceIds": {"type": "array", "items": {"type": "string"}, "description": "WAN/interface IDs for egress"},
                "backupInterface": {"type": "boolean", "default": True},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_policy_route,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_policy_route",
        title="Delete gateway policy route",
        description=(
            "Delete a gateway policy route by ID or exact name (DELETE setting/transmission/policyRoutings/{id})."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "routeId": {"type": "string", "description": "Policy route ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["routeId"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_policy_route,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_lan_dns_rule",
        title="Create or update local LAN DNS rule",
        description=(
            "Create or update a local LAN DNS record/CNAME/forward rule (setting/lan/dns; Omada v5.14+/v6.x gateway)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "DNS rule name"},
                "domain": {"type": "string", "description": "Hostname or domain name"},
                "ruleType": {"type": ["string", "integer"], "default": "ip", "description": "'ip' (0), 'cname' (1), 'forward' (2)"},
                "ruleId": {"type": "string", "description": "Existing rule ID when updating"},
                "enable": {"type": "boolean", "default": True},
                "ipAddresses": {"type": "array", "items": {"type": "string"}, "description": "IPv4 A record addresses for ruleType='ip'"},
                "ipv6Addresses": {"type": "array", "items": {"type": "string"}, "description": "IPv6 AAAA addresses for ruleType='ip'"},
                "cname": {"type": "string", "description": "Canonical target hostname for ruleType='cname'"},
                "dnsServers": {"type": "array", "items": {"type": "string"}, "description": "Upstream forward DNS servers for ruleType='forward'"},
                "lanNetworkIds": {"type": "array", "items": {"type": "string"}, "description": "LAN network IDs (type 0/1)"},
                "aliases": {"type": "array", "items": {"type": "string"}},
                "customTtl": {"type": "boolean", "default": False},
                "ttl": {"type": "integer", "minimum": 1, "maximum": 86400, "default": 3600},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "domain"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_lan_dns_rule,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_lan_dns_rule",
        title="Delete local LAN DNS rule",
        description=(
            "Delete a local LAN DNS rule by ID or exact name (DELETE setting/lan/dns/{id})."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "ruleId": {"type": "string", "description": "LAN DNS rule ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["ruleId"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_lan_dns_rule,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="create_switch_acl",
        title="Create switch ACL rule",
        description=(
            "Create a switch ACL rule (POST setting/firewall/acls?type=1) with anti-stranding checks. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique switch ACL rule name"},
                "policy": {"type": ["string", "integer"], "description": "'deny' (0) or 'permit' (1)"},
                "source": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["network", "ip_group", "port_group", "mac_group"],
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "{'type': 'network'|'ip_group'|'port_group'|'mac_group', 'ids': [...]}",
                },
                "destination": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["network", "ip_group", "port_group", "mac_group"],
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "{'type': 'network'|'ip_group'|'port_group'|'mac_group', 'ids': [...]}",
                },
                "bindingType": {"type": ["string", "integer"], "default": "all_ports", "description": "'all_ports' (0), 'custom_ports' (1), 'all_switches' (2), 'vlan' (3)"},
                "customAclPorts": {"type": "array", "items": {"type": ["object", "string"]}},
                "networkId": {"type": "string", "description": "VLAN/network ID when bindingType='vlan' (3)"},
                "status": {"type": "boolean", "default": True},
                "protocols": {"type": "array", "items": {"type": "integer"}},
                "biDirectional": {"type": "boolean", "default": False},
                "etherType": {"type": "string", "description": "Optional EtherType hex e.g. '0x0800'"},
                "syslog": {"type": "boolean", "default": False},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "policy", "source", "destination"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_switch_acl,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="create_eap_acl",
        title="Create EAP wireless ACL rule",
        description=(
            "Create an EAP ACL rule (POST setting/firewall/acls?type=2) with anti-stranding checks. "
            "Supports source/destination type 'ssid' in addition to network/group selectors."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique EAP ACL rule name"},
                "policy": {"type": ["string", "integer"], "description": "'deny' (0) or 'permit' (1)"},
                "source": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["network", "ip_group", "port_group", "mac_group", "ssid"],
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "{'type': 'network'|'ip_group'|'port_group'|'mac_group'|'ssid', 'ids': [...]}",
                },
                "destination": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["network", "ip_group", "port_group", "mac_group", "ssid"],
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "{'type': 'network'|'ip_group'|'port_group'|'mac_group'|'ssid', 'ids': [...]}",
                },
                "status": {"type": "boolean", "default": True},
                "protocols": {"type": "array", "items": {"type": "integer"}},
                "syslog": {"type": "boolean", "default": False},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "policy", "source", "destination"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_eap_acl,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="set_client_lock_to_ap",
        title="Lock or unlock wireless client to AP(s)",
        description=(
            "Configure clientLockToApSetting on a wireless client (PATCH clients/{MAC}) using volatile-stripped RMW "
            "and wire AP MAC string normalization."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "clientMac": {"type": "string", "description": "Client MAC address"},
                "enabled": {"type": "boolean", "description": "Enable or disable lock-to-AP"},
                "apMacs": {"type": "array", "items": {"type": "string"}, "description": "Allowed AP MAC addresses or exact names (required when enabled=true)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["clientMac", "enabled"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_client_lock_to_ap,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="set_client_rate_limit",
        title="Configure client bandwidth rate limit",
        description=(
            "Apply or disable a client rate-limit profile or custom Kbps upload/download limits via PATCH clients/{MAC}."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "clientMac": {"type": "string", "description": "Client MAC address"},
                "enabled": {"type": "boolean", "description": "Enable or disable rate limit"},
                "rateLimitProfileId": {"type": "string", "description": "Rate limit profile UUID"},
                "rateLimitProfileName": {"type": "string", "description": "Rate limit profile exact name"},
                "downLimitKbps": {"type": "integer", "minimum": 1, "description": "Custom download cap in Kbps"},
                "upLimitKbps": {"type": "integer", "minimum": 1, "description": "Custom upload cap in Kbps"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["clientMac", "enabled"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_client_rate_limit,
        read_only=False,
        destructive=False,
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
    *,
    schema_mode: Optional[str] = None,
    categories: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Return MCP tool descriptors filtered by config/allowlist, schema mode, and categories."""
    eff_mode = (
        schema_mode
        if schema_mode is not None
        else (getattr(config, "schema_mode", "slim") if config is not None else "slim")
    )
    if str(eff_mode or "slim").strip().lower() not in ("slim", "full"):
        raise ConfigError(
            f"invalid schema_mode {eff_mode!r}; expected 'slim' or 'full'",
            key="OMADA_SCHEMA_MODE",
        )
    eff_cats_raw = (
        categories
        if categories is not None
        else (getattr(config, "tool_categories", ()) if config is not None else ())
    )
    eff_cats = {str(c).strip().lower() for c in eff_cats_raw if str(c).strip()}
    unknown_cats = eff_cats - set(_TOOL_CATEGORIES.values())
    if unknown_cats:
        raise ConfigError(
            f"unknown tool category filter: {', '.join(sorted(unknown_cats))}",
            hint="valid categories: core, diagnostics, switch, wifi, routing, security, rollback",
            key="OMADA_TOOL_CATEGORIES",
        )

    if include_all:
        selected = TOOLS
    else:
        enabled_writes: set[str] = set()
        if config is not None:
            if not config.read_only:
                enabled_writes = set(config.write_tools)
        elif write_tools is not None:
            enabled_writes = set(write_tools)
        selected = tuple(
            tool for tool in TOOLS
            if tool.read_only or tool.name in enabled_writes
        )

    return [
        tool.descriptor(schema_mode=eff_mode)
        for tool in selected
        if not eff_cats or tool.category in eff_cats
    ]
