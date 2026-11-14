"""Read domain module: networks_read."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .._projections import project_controller_row
from ..client import OmadaClient, OmadaError, SiteInfo, redact_secrets
from ._common import as_mapping
from ._network_helpers import (
    collect_topology_data,
    collect_vpn_tunnels_data,
    collect_wan_status_data,
)
from ._tool_model import _as_int, _site
from ._write_fetchers import (
    _fetch_dhcp_reservations,
    _fetch_lan_collection,
    _fetch_lan_interfaces,
    _fetch_mdns_profiles,
    _fetch_mdns_rules,
    _fetch_wan_networks,
)
from .clients_read import _fetch_clients
from .devices_read import _list_devices


def _get_site_info(client: OmadaClient) -> dict[str, Any]:
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


def _parse_group_type(group: dict[str, Any]) -> int | None:
    raw = group.get("type")
    if raw is None or isinstance(raw, bool):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _extract_dhcp_pools(dhcp: Any) -> list[dict[str, str]]:
    if not isinstance(dhcp, dict):
        return []
    pools: list[dict[str, str]] = []
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


def _merge_lan_networks(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
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
    merged_networks: list[dict[str, Any]] = []
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


def _project_lan_network(merged: dict[str, Any]) -> dict[str, Any]:
    iface = merged.get("interface") or merged.get("collection") or {}
    dhcp = as_mapping(merged.get("dhcpSettings"))
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
    row: dict[str, Any],
    net_by_id: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
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


def _list_lan_networks(client: OmadaClient) -> list[dict[str, Any]]:
    site = _site(client)
    return [_project_lan_network(item) for item in _merge_lan_networks(client, site)]


def _list_dhcp_reservations(
    client: OmadaClient,
    vlan: Any | None = None,
) -> list[dict[str, Any]]:
    site = _site(client)
    rows = _fetch_dhcp_reservations(client, site)
    net_by_id: dict[str, dict[str, Any]] = {}
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


def _sanitize_wan_summary(raw_wan: dict[str, Any]) -> dict[str, Any]:
    cleaned = redact_secrets(raw_wan)
    osg = as_mapping(cleaned.get("osgPortInfo"))
    ports_raw = osg.get("wanLanPortSettings")
    ports: list[Any] = ports_raw if isinstance(ports_raw, list) else []
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


def _get_network_services(client: OmadaClient) -> dict[str, Any]:
    site = _site(client)
    warnings: list[str] = []

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


def _get_network_services_enriched(client: OmadaClient) -> dict[str, Any]:
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


def _get_wan_status(
    client: OmadaClient,
    includeSpeedtest: bool = True,
    maskWanIp: bool = False,
) -> dict[str, Any]:
    with client.scoped_cache():
        site = _site(client)
        return collect_wan_status_data(
            client, site,
            include_speedtest=bool(includeSpeedtest),
            mask_wan_ip=bool(maskWanIp),
        )


def _list_vpn_tunnels(client: OmadaClient) -> dict[str, Any]:
    with client.scoped_cache():
        return collect_vpn_tunnels_data(client, _site(client))


def _get_topology(client: OmadaClient, includeClients: bool = False) -> dict[str, Any]:
    return collect_topology_data(client, _site(client), include_clients=bool(includeClients))


_SITE_INFO_SCHEMA: dict[str, Any] = {
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


_LAN_NETWORK_SCHEMA: dict[str, Any] = {
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


_DHCP_RES_SCHEMA: dict[str, Any] = {
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


_WAN_STATUS_SCHEMA: dict[str, Any] = {
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


_VPN_TUNNELS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "tunnels": {"type": "array", "items": {"type": "object"}},
        "configuredVpns": {"type": "array", "items": {"type": "object"}},
        "counts": {"type": "object"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["tunnels", "configuredVpns", "counts", "warnings"],
}


_TOPOLOGY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "roots": {"type": "array", "items": {"type": "object"}},
        "unattachedDevices": {"type": "array", "items": {"type": "object"}},
        "counts": {"type": "object"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["roots", "unattachedDevices", "counts", "warnings"],
}


_SERVICES_SCHEMA: dict[str, Any] = {
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

