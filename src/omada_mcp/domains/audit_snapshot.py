"""Read domain module: audit_snapshot."""

from __future__ import annotations

from typing import Any

from .._projections import project_controller_row
from ..client import OmadaClient, OmadaError
from ._network_helpers import dhcp_pool_capacity, extra_network_audit_findings
from ._tool_model import _site
from ._write_common import _ACL_DISPATCH_NOTES
from ._write_fetchers import (
    _fetch_acls,
    _fetch_devices,
    _fetch_groups,
    _fetch_lan_collection,
    _fetch_mdns_rules,
)
from .clients_read import _fetch_clients
from .devices_read import _list_devices, _list_wlans
from .networks_read import (
    _DHCP_RES_SCHEMA,
    _SERVICES_SCHEMA,
    _get_network_services,
    _list_dhcp_reservations,
    _merge_lan_networks,
    _parse_group_type,
)
from .routing_dns_read import (
    _PORT_FORWARD_SCHEMA,
    _STATIC_ROUTE_SCHEMA,
    _list_port_forwards,
    _list_static_routes,
)

_ISOLATED_VLAN_KEYWORDS = ("iot", "guest", "kids", "camera", "security", "untrusted", "dmz")


_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _findings_healthy(findings: list[dict[str, Any]]) -> bool:
    """The one definition of audit health: no critical and no warning findings.

    Both ``_network_audit`` and ``_network_audit_enriched`` must use this. The
    wrapper previously recomputed health as ``critical == 0``, so the same tool
    reported a different meaning depending on whether enrichment appended
    findings (issue #3).
    """
    return not any(f.get("severity") in ("critical", "warning") for f in findings)


def _dhcp_pool_capacity(dhcp: dict[str, Any]) -> int:
    """Total IPv4 addresses across ``dhcpSettings.ipRangePool`` (or start/end fallback)."""
    return dhcp_pool_capacity(dhcp)


def _network_audit(client: OmadaClient) -> dict[str, Any]:
    """Composite, idempotent read-only health audit of the resolved Omada site."""
    site = _site(client)

    site_res = client.api(f"sites/{site.site_id}")
    site_detail = site_res.get("result") if site_res.get("errorCode") == 0 else {}
    site_detail = site_detail if isinstance(site_detail, dict) else {}

    raw_devices: list[dict[str, Any]] = _fetch_devices(client, site)

    clients = _fetch_clients(client, limit=0)
    wlans = _list_wlans(client)

    lan_networks: list[dict[str, Any]] = []
    try:
        lan_networks = _fetch_lan_collection(client, site)
    except OmadaError:
        lan_networks = []

    findings: list[dict[str, str]] = []

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

    clients_by_vlan: dict[int, int] = {}
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

    dhcp_pools: list[dict[str, Any]] = []
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


def _network_audit_enriched(client: OmadaClient) -> dict[str, Any]:
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


_SNAPSHOT_DEFAULT_OBJECTS: tuple[str, ...] = ("networks", "acls", "groups", "wlans", "devices")


_SNAPSHOT_ALL_OBJECTS: tuple[str, ...] = (
    "networks", "acls", "groups", "wlans", "devices", "clients",
    "dhcpReservations", "portForwards", "staticRoutes", "mdnsRules", "services",
)


_SNAPSHOT_OBJECT_CANONICAL: dict[str, str] = {name.lower(): name for name in _SNAPSHOT_ALL_OBJECTS}


def _get_config_snapshot(
    client: OmadaClient,
    objects: list[str] | None = None,
) -> dict[str, Any]:
    """Read-only snapshot merging two-endpoint LAN data, ACLs, groups, WLANs, devices, and optional sections."""
    with client.scoped_cache():
        return _get_config_snapshot_impl(client, objects=objects)


def _get_config_snapshot_impl(
    client: OmadaClient,
    objects: list[str] | None = None,
) -> dict[str, Any]:
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
    warnings: list[str] = []
    snapshot: dict[str, Any] = {
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


_NETWORK_AUDIT_SCHEMA: dict[str, Any] = {
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


_SNAPSHOT_SCHEMA: dict[str, Any] = {
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

