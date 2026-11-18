"""Read domain module: audit_snapshot."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from .._projections import project_controller_row
from ..client import OmadaClient, OmadaError
from ._common import (
    IncompleteCollectionError,
    PaginatedList,
    deep_redact,
    require_complete_collection,
)
from ._network_helpers import dhcp_pool_capacity, extra_network_audit_findings, read_audit_source
from ._tool_model import _site, normalize_mac
from ._write_common import _ACL_DISPATCH_NOTES
from ._write_fetchers import (
    _fetch_acls,
    _fetch_devices,
    _fetch_groups,
    _fetch_lan_collection,
    _fetch_mdns_rules,
    _fetch_schedules,
)
from .clients_read import _fetch_clients
from .devices_read import _list_devices, _list_ssids_detail, _list_wlans
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
_NETWORK_AUDIT_REQUEST_LIMIT = 64


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


def _network_audit(client: OmadaClient) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Composite, idempotent read-only health audit of the resolved Omada site."""
    site = _site(client)

    coverage: dict[str, str] = {}
    warnings: list[str] = []
    site_detail = read_audit_source(
        lambda: client.api_result(f"sites/{site.site_id}"),
        "site", "Site connectivity", coverage, warnings,
    )
    site_detail = site_detail if isinstance(site_detail, dict) else {}

    def connectivity(key: str) -> bool | None:
        value = site_detail.get(key)
        return bool(value) if value in (True, False) else None

    wan_up, lan_up, wlan_up = (connectivity(key) for key in ("wan", "lan", "wlan"))
    if coverage["site"] == "complete" and None in (wan_up, lan_up, wlan_up):
        coverage["site"] = "partial"
        warnings.append("Site connectivity: some states were not reported.")

    raw_devices = read_audit_source(
        lambda: _fetch_devices(client, site), "devices", "Devices", coverage, warnings,
    ) or []
    lan_networks = read_audit_source(
        lambda: _fetch_lan_collection(client, site), "lanNetworks", "LAN networks", coverage, warnings,
    ) or []
    wlans = read_audit_source(
        lambda: _list_wlans(client, strict=True), "wlans", "WLANs", coverage, warnings,
    ) or []
    clients: list[dict[str, Any]] = read_audit_source(
        lambda: _fetch_clients(client, limit=0), "clients", "Active clients", coverage, warnings,
    ) or []

    findings: list[dict[str, str]] = []

    if wan_up is False:
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
            observed = clients_by_vlan.get(vlan, 0) if coverage["clients"] != "unavailable" else None
            observed_ratio = round(100.0 * observed / capacity, 1) if capacity > 0 and observed is not None else None
            dhcp_pools.append({
                "network": net_name,
                "vlan": vlan,
                "subnet": net.get("gatewaySubnet") or "",
                "poolSize": capacity,
                "observedClients": observed,
                "observedClientToPoolPct": observed_ratio,
                "clientCoverage": coverage["clients"],
            })
            if observed_ratio is not None and observed_ratio >= 80:
                findings.append({
                    "code": "DHCP_CLIENT_COUNT_HIGH_RELATIVE_TO_POOL",
                    "severity": "info",
                    "target": net_name,
                    "detail": (f"VLAN {vlan} has {observed} observed active clients and {capacity} configured "
                               "DHCP pool addresses. Check the gateway's lease table to measure occupancy."),
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
            "wanConnected": wan_up,
            "lanConnected": lan_up,
            "wlanConnected": wlan_up,
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
        "coverage": coverage,
        "warnings": warnings,
    }, raw_devices


def _network_audit_enriched(client: OmadaClient) -> dict[str, Any]:
    """Run core network_audit plus non-fatal switch/AP/WAN telemetry findings."""
    with client.request_budget(_NETWORK_AUDIT_REQUEST_LIMIT) as budget, client.scoped_cache():
        audit, raw_devices = _network_audit(client)
        supplemental_warnings: list[str] = []
        extra = extra_network_audit_findings(
            client, _site(client), raw_devices, budget=budget, warnings=supplemental_warnings,
        )
    if budget.used >= budget.limit:
        supplemental_warnings.append("The request budget limited supplemental network checks.")
    audit["warnings"].extend(supplemental_warnings)
    audit["coverage"]["supplemental"] = (
        "unavailable" if audit["coverage"]["devices"] != "complete"
        else "partial" if supplemental_warnings else "complete"
    )
    complete = all(status == "complete" for status in audit["coverage"].values())

    findings = audit["findings"] + extra
    findings.sort(key=lambda item: (_SEVERITY_ORDER[item["severity"]], item["code"], item["target"]))

    critical = sum(1 for f in findings if f["severity"] == "critical")
    warning = sum(1 for f in findings if f["severity"] == "warning")
    info = sum(1 for f in findings if f["severity"] == "info")
    audit["counts"].update({
        "findings": len(findings),
        "critical": critical,
        "warnings": warning,
        "info": info,
    })
    healthy = _findings_healthy(findings)
    audit.update({
        "healthy": healthy if complete or not healthy else None,
        "complete": complete,
        "controllerRequests": budget.used,
        "requestLimit": budget.limit,
        "findings": findings,
    })
    return audit


_SNAPSHOT_DEFAULT_OBJECTS: tuple[str, ...] = ("networks", "acls", "groups", "wlans", "devices")


_SNAPSHOT_ALL_OBJECTS: tuple[str, ...] = (
    "networks", "acls", "groups", "schedules", "wlans", "ssids", "devices", "clients",
    "dhcpReservations", "portForwards", "staticRoutes", "mdnsRules", "services",
    "rateLimitProfiles", "poeSchedules", "wirelessFeature", "rfPlanning",
    "vpns", "wireguard", "wireguardPeers", "ddns", "trafficRules", "qos",
)


_SNAPSHOT_OBJECT_CANONICAL: dict[str, str] = {name.lower(): name for name in _SNAPSHOT_ALL_OBJECTS}


def _resolve_snapshot_objects(
    objects: list[str] | None,
    *,
    default: tuple[str, ...] = _SNAPSHOT_DEFAULT_OBJECTS,
) -> list[str]:
    if objects is None:
        return list(default)
    if not isinstance(objects, list):
        raise OmadaError("objects must be an array of snapshot section names")
    selected: list[str] = []
    seen: set[str] = set()
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
            hint="omit objects for default snapshot (" + ", ".join(default) + ")",
        )
    return selected


def _get_config_snapshot(
    client: OmadaClient,
    objects: list[str] | None = None,
) -> dict[str, Any]:
    """Read-only snapshot merging two-endpoint LAN data, ACLs, groups, WLANs, devices, and optional sections."""
    with client.scoped_cache():
        return _get_config_snapshot_impl(client, objects=objects)


_PROJECTED_SNAPSHOT_COLLECTIONS = {
    "vpns": ("setting/vpns", "vpns"),
    "wireguard": ("setting/wireguard", "wireguard"),
    "wireguardPeers": ("setting/wireguard/peer", "wireguardPeers"),
    "ddns": ("setting/service/ddns", "ddnsEntry"),
}


def _get_config_snapshot_impl(
    client: OmadaClient,
    objects: list[str] | None = None,
) -> dict[str, Any]:
    from .fleet_vpn_read import _list_qos_rules, _list_traffic_rules
    from .security_read import _list_rate_limit_profiles
    from .switch_wifi_read import (
        _get_wifi_radio_features,
        _get_wlan_optimization_status,
        _list_poe_schedules,
    )

    selected = _resolve_snapshot_objects(objects)
    site = _site(client)
    warnings: list[str] = []
    status: dict[str, dict[str, str]] = {
        section: {"status": "skipped", "reason": "section was not requested"}
        for section in _SNAPSHOT_ALL_OBJECTS if section not in selected
    }
    snapshot: dict[str, Any] = {
        "site": {"name": site.name, "id": site.site_id},
        "capturedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "objects": selected,
        "warnings": warnings,
        "sectionStatus": status,
    }

    def _acls() -> dict[str, Any]:
        acl_disable, rules = _fetch_acls(client, site)
        warnings.append(_ACL_DISPATCH_NOTES)
        return {
            "aclDisable": acl_disable,
            "aclDisableReliable": False,
            "warning": _ACL_DISPATCH_NOTES,
            "count": len(rules),
            "rules": [project_controller_row("acls", rule) for rule in rules],
        }

    def _groups() -> dict[str, Any]:
        rows = [project_controller_row("groups", row) for row in _fetch_groups(client, site)]
        return {
            "count": len(rows),
            "ipGroups": [row for row in rows if _parse_group_type(row) == 0],
            "portGroups": [row for row in rows if _parse_group_type(row) == 1],
            "macGroups": [row for row in rows if _parse_group_type(row) == 2],
            "otherGroups": [row for row in rows if _parse_group_type(row) != 0],
            "all": rows,
        }

    collectors: dict[str, Callable[[], Any]] = {
        "networks": lambda: [
            project_controller_row("networks", row)
            for row in _merge_lan_networks(client, site, strict=True)
        ],
        "acls": _acls,
        "groups": _groups,
        "schedules": lambda: [project_controller_row("schedules", row) for row in _fetch_schedules(client, site)],
        "wlans": lambda: _list_wlans(client, strict=True),
        "ssids": lambda: _list_ssids_detail(client, strict=True),
        "devices": lambda: _list_devices(client),
        "clients": lambda: _fetch_clients(client, limit=0),
        "dhcpReservations": lambda: _list_dhcp_reservations(client, strict=True),
        "portForwards": lambda: _list_port_forwards(client),
        "staticRoutes": lambda: _list_static_routes(client),
        "mdnsRules": lambda: [project_controller_row("mdnsRules", row) for row in _fetch_mdns_rules(client, site)],
        "services": lambda: _get_network_services(client),
        "rateLimitProfiles": lambda: _list_rate_limit_profiles(client),
        "poeSchedules": lambda: _list_poe_schedules(client, strict=True),
        "wirelessFeature": lambda: _get_wifi_radio_features(client),
        "rfPlanning": lambda: _get_wlan_optimization_status(client),
        "trafficRules": lambda: _list_traffic_rules(client),
        "qos": lambda: _list_qos_rules(client),
    }
    for section in selected:
        try:
            if section in _PROJECTED_SNAPSHOT_COLLECTIONS:
                endpoint, shape = _PROJECTED_SNAPSHOT_COLLECTIONS[section]
                rows, _ = require_complete_collection(client, f"sites/{site.site_id}/{endpoint}")
                value: Any = [project_controller_row(shape, row) for row in rows]
            else:
                value = collectors[section]()
        except IncompleteCollectionError as exc:
            status[section] = {"status": "partial", "reason": exc.message}
        except OmadaError as exc:
            reason = f"controller collection unavailable (code {exc.code})" if exc.code else "controller collection unavailable"
            status[section] = {"status": "unavailable", "reason": reason}
        else:
            snapshot[section] = value
            if isinstance(value, PaginatedList) and value.truncated:
                reason = str(value.pagination.get("truncationReason") or "controller collection incomplete")
                status[section] = {"status": "partial", "reason": reason}
            elif isinstance(value, Mapping) and value.get("warnings"):
                status[section] = {"status": "partial", "reason": "one or more source reads were unavailable"}
            else:
                status[section] = {"status": "ok"}
        if status[section]["status"] != "ok":
            warnings.append(f"{section} skipped: {status[section]['reason']}")

    return snapshot


_NETWORK_AUDIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "healthy": {"type": ["boolean", "null"]},
        "complete": {"type": "boolean"},
        "controllerRequests": {"type": "integer", "minimum": 0},
        "requestLimit": {"type": "integer", "minimum": 1},
        "coverage": {
            "type": "object",
            "additionalProperties": {"enum": ["complete", "partial", "unavailable"]},
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
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
                "wanConnected": {"type": ["boolean", "null"]},
                "lanConnected": {"type": ["boolean", "null"]},
                "wlanConnected": {"type": ["boolean", "null"]},
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
                    "observedClients": {"type": ["integer", "null"]},
                    "observedClientToPoolPct": {"type": ["number", "null"]},
                    "clientCoverage": {"enum": ["complete", "partial", "unavailable"]},
                },
                "required": [
                    "network", "vlan", "subnet", "poolSize",
                    "observedClients", "observedClientToPoolPct", "clientCoverage",
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
    "required": [
        "healthy", "complete", "controllerRequests", "requestLimit", "coverage", "warnings",
        "controller", "site", "counts", "dhcpPools", "findings",
    ],
}


_SECTION_STATUS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": ["ok", "partial", "skipped", "unavailable"]},
        "reason": {"type": "string"},
    },
    "required": ["status"],
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
        "capturedAt": {"type": "string"},
        "objects": {"type": "array", "items": {"type": "string"}},
        "sectionStatus": {"type": "object", "additionalProperties": _SECTION_STATUS_SCHEMA},
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
                "portGroups": {"type": "array", "items": {"type": "object"}},
                "macGroups": {"type": "array", "items": {"type": "object"}},
                "otherGroups": {"type": "array", "items": {"type": "object"}},
                "all": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["count", "ipGroups", "otherGroups", "all"],
        },
        "schedules": {"type": "array", "items": {"type": "object"}},
        "wlans": {"type": "array", "items": {"type": "object"}},
        "ssids": {"type": "array", "items": {"type": "object"}},
        "devices": {"type": "array", "items": {"type": "object"}},
        "clients": {"type": "array", "items": {"type": "object"}},
        "dhcpReservations": {"type": "array", "items": _DHCP_RES_SCHEMA},
        "portForwards": {"type": "array", "items": _PORT_FORWARD_SCHEMA},
        "staticRoutes": {"type": "array", "items": _STATIC_ROUTE_SCHEMA},
        "mdnsRules": {"type": "array", "items": {"type": "object"}},
        "services": _SERVICES_SCHEMA,
        "rateLimitProfiles": {"type": "array", "items": {"type": "object"}},
        "poeSchedules": {"type": "array", "items": {"type": "object"}},
        "wirelessFeature": {"type": "object"},
        "rfPlanning": {"type": "object"},
        "vpns": {"type": "array", "items": {"type": "object"}},
        "wireguard": {"type": "array", "items": {"type": "object"}},
        "wireguardPeers": {"type": "array", "items": {"type": "object"}},
        "ddns": {"type": "array", "items": {"type": "object"}},
        "trafficRules": {"type": "object"},
        "qos": {"type": "object"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["site", "objects", "warnings", "sectionStatus"],
}


_DIFF_VOLATILE_KEYS: frozenset[str] = frozenset({
    "uptime", "uptimeSec", "duration", "lastSeen", "cpuUtil", "memUtil",
    "rxRate", "txRate", "rxRateKbps", "txRateKbps", "rxBytes", "txBytes",
    "download", "upload", "trafficDown", "trafficUp", "clientCount", "userNum",
    "txUtil", "rxUtil", "interUtil", "rssi", "signal", "signalLevel", "snr",
    "channel", "noiseLevel", "activity", "power", "poePower", "temperature",
    "temp", "speed", "rxPackets", "txPackets", "rxErrors", "txErrors",
    "rxDrops", "txDrops", "rxRetryPkts", "txRetryPkts", "expired",
    "warnings", "aclDisableReliable", "warning", "capturedAt",
})


def _strip_volatile_and_redact(value: Any) -> Any:
    cleaned = deep_redact(value)
    if isinstance(cleaned, dict):
        return {
            k: _strip_volatile_and_redact(v)
            for k, v in cleaned.items()
            if k not in _DIFF_VOLATILE_KEYS
        }
    if isinstance(cleaned, list):
        return [_strip_volatile_and_redact(item) for item in cleaned]
    return cleaned


def _diff_item_identity(section: str, item: Any) -> tuple[str, str]:
    if not isinstance(item, dict):
        canon = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
        return canon, canon
    raw_id = item.get("id") or item.get("groupId")
    label = str(item.get("name") or item.get("ssid") or item.get("mac") or raw_id or "")
    if raw_id not in (None, ""):
        return f"id:{raw_id}", label or str(raw_id)
    if section in ("devices", "clients", "dhcpReservations") and item.get("mac"):
        mac = normalize_mac(str(item["mac"]))
        if section == "dhcpReservations" and item.get("netId"):
            return f"res:{mac}:{item['netId']}", label or mac
        return f"mac:{mac}", label or mac
    if section == "networks" and item.get("vlan") is not None:
        return f"vlan:{item['vlan']}:{item.get('name') or ''}", label or f"vlan-{item['vlan']}"
    if section in ("wlans", "ssids"):
        grp = str(item.get("wlanGroup") or item.get("wlanId") or "")
        name = str(item.get("name") or "")
        if grp or name:
            return f"wlan:{grp}:{name}", name or grp
    if item.get("name"):
        return f"name:{item['name']}", str(item["name"])
    canon = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
    return canon, label or canon[:48]


def _diff_field_changes(before: Any, after: Any, prefix: str = "") -> dict[str, dict[str, Any]]:
    if isinstance(before, dict) and isinstance(after, dict):
        changes: dict[str, dict[str, Any]] = {}
        for key in sorted(set(before) | set(after)):
            path = f"{prefix}.{key}" if prefix else str(key)
            if key not in before:
                changes[path] = {"before": None, "after": after[key]}
            elif key not in after:
                changes[path] = {"before": before[key], "after": None}
            elif before[key] != after[key]:
                if isinstance(before[key], dict) and isinstance(after[key], dict):
                    changes.update(_diff_field_changes(before[key], after[key], path))
                else:
                    changes[path] = {"before": before[key], "after": after[key]}
        return changes
    if before != after:
        return {prefix or "value": {"before": before, "after": after}}
    return {}


def _materialized_keys(delta: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Return fields that transitioned from omitted (None) to an explicit empty/false default."""
    return sorted(
        path
        for path, entry in delta.items()
        if entry.get("before") is None
        and (entry.get("after") is False or entry.get("after") == "" or entry.get("after") == {})
    )


def _diff_object_list(
    section: str,
    before_items: list[Any],
    after_items: list[Any],
) -> dict[str, Any]:
    before_map: dict[str, tuple[str, Any]] = {}
    for item in before_items:
        key, label = _diff_item_identity(section, item)
        while key in before_map:
            key = f"{key}#dup"
        before_map[key] = (label, item)

    after_map: dict[str, tuple[str, Any]] = {}
    for item in after_items:
        key, label = _diff_item_identity(section, item)
        while key in after_map:
            key = f"{key}#dup"
        after_map[key] = (label, item)

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []

    for key in sorted(after_map):
        if key not in before_map:
            label, item = after_map[key]
            added.append({"key": key, "label": label, "value": item})
    for key in sorted(before_map):
        if key not in after_map:
            label, item = before_map[key]
            removed.append({"key": key, "label": label, "value": item})
    for key in sorted(set(before_map) & set(after_map)):
        _, before_val = before_map[key]
        label, after_val = after_map[key]
        delta = _diff_field_changes(before_val, after_val)
        if delta:
            entry: dict[str, Any] = {"key": key, "label": label, "changes": delta}
            mat = _materialized_keys(delta)
            if mat:
                entry["materializedKeys"] = mat
            changed.append(entry)

    return {
        "hasChanges": bool(added or removed or changed),
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def _extract_section_items(section: str, snapshot: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
    raw = snapshot[section]
    if section in _PROJECTED_SNAPSHOT_COLLECTIONS:
        shape = _PROJECTED_SNAPSHOT_COLLECTIONS[section][1]
        raw = [project_controller_row(shape, row) for row in raw]
    cleaned = _strip_volatile_and_redact(raw)
    if section == "acls" and isinstance(cleaned, dict):
        meta = {k: v for k, v in cleaned.items() if k not in ("rules", "count")}
        return list(cleaned.get("rules") or []), meta
    if section == "groups" and isinstance(cleaned, dict):
        all_rows = cleaned.get("all")
        if all_rows is None:
            all_rows = list(cleaned.get("ipGroups") or []) + list(cleaned.get("otherGroups") or [])
        return list(all_rows or []), {}
    if isinstance(cleaned, list):
        return cleaned, {}
    return [], {"value": cleaned}


_DIFF_OBJECT_SECTIONS = ("services", "wirelessFeature", "rfPlanning", "trafficRules", "qos")


def _section_evidence(snapshot: Mapping[str, Any], section: str) -> dict[str, str]:
    """Validate a section's evidence, including legacy snapshots without statuses."""
    if isinstance(snapshot.get("objects"), list) and not any(
        str(name).strip().lower() == section.lower() for name in snapshot["objects"]
    ):
        return {"status": "skipped", "reason": "section was not requested"}
    statuses = snapshot.get("sectionStatus")
    if isinstance(statuses, Mapping):
        evidence = statuses.get(section)
        status = evidence.get("status") if isinstance(evidence, Mapping) else None
        if status in ("partial", "skipped", "unavailable"):
            return {"status": status, "reason": f"section marked {status} by snapshot"}
        if status != "ok":
            return {"status": "unavailable", "reason": "section lacks collection evidence"}
    else:
        warnings = snapshot.get("warnings")
        if isinstance(warnings, list) and any(
            isinstance(msg, str) and msg.startswith(f"{section} skipped:") for msg in warnings
        ):
            return {"status": "unavailable", "reason": "legacy snapshot reports this section was skipped"}

    value = snapshot.get(section)
    if value is None:
        return {"status": "skipped", "reason": "section data was omitted"}
    if section in _DIFF_OBJECT_SECTIONS:
        if isinstance(value, Mapping) and value and not value.get("warnings"):
            return {"status": "ok"}
    else:
        rows = value
        if section == "acls" and isinstance(value, Mapping):
            rows = value.get("rules")
        if section == "groups" and isinstance(value, Mapping):
            rows = value.get("all")
            if rows is None and isinstance(value.get("ipGroups"), list) and isinstance(value.get("otherGroups"), list):
                rows = value["ipGroups"] + value["otherGroups"]
        if isinstance(rows, list) and all(isinstance(item, Mapping) for item in rows):
            return {"status": "ok"}
    return {"status": "partial", "reason": "section data is incomplete or has an unexpected shape"}


def _diff_config_snapshots(
    client: OmadaClient,
    baseline: dict[str, Any],
    current: dict[str, Any] | None = None,
    objects: list[str] | None = None,
) -> dict[str, Any]:
    """Deterministically compare two snapshots (or *baseline* against the live site)."""
    if not isinstance(baseline, dict) or not any(k in baseline for k in (*_SNAPSHOT_ALL_OBJECTS, "objects", "site")):
        raise OmadaError(
            "baseline must be a snapshot object produced by get_config_snapshot",
            hint="pass the JSON object returned by get_config_snapshot",
        )

    if current is not None and not isinstance(current, dict):
        raise OmadaError("current must be a snapshot object or omitted to query the live controller")

    if objects is not None:
        sections_list = _resolve_snapshot_objects(objects)
    else:
        sections_list = []
        for candidate in (baseline, current):
            if candidate is None:
                continue
            names = candidate.get("objects")
            if isinstance(names, list) and names:
                sections_list.extend(_resolve_snapshot_objects([str(name) for name in names]))
            else:
                sections_list.extend(section for section in _SNAPSHOT_ALL_OBJECTS if section in candidate)
        sections_list = list(dict.fromkeys(sections_list)) or list(_SNAPSHOT_DEFAULT_OBJECTS)

    live_used = current is None
    if current is None:
        with client.scoped_cache():
            target_snapshot = _get_config_snapshot_impl(client, objects=sections_list)
    else:
        target_snapshot = current

    base_site = baseline.get("site") if isinstance(baseline.get("site"), dict) else None
    curr_site = target_snapshot.get("site") if isinstance(target_snapshot.get("site"), dict) else None
    cross_site = bool(
        base_site and curr_site and base_site.get("id") and curr_site.get("id")
        and str(base_site["id"]) != str(curr_site["id"])
    )

    sections_out: dict[str, dict[str, Any]] = {}
    sections_skipped: dict[str, dict[str, dict[str, str]]] = {}
    materialized_defaults: list[dict[str, Any]] = []
    total_added = 0
    total_removed = 0
    total_changed = 0
    sections_changed = 0

    for section in sections_list:
        baseline_evidence = _section_evidence(baseline, section)
        current_evidence = _section_evidence(target_snapshot, section)
        if baseline_evidence["status"] != "ok" or current_evidence["status"] != "ok":
            sections_skipped[section] = {"baseline": baseline_evidence, "current": current_evidence}
            continue
        if section in _DIFF_OBJECT_SECTIONS:
            b_clean = _strip_volatile_and_redact(baseline.get(section) or {})
            c_clean = _strip_volatile_and_redact(target_snapshot.get(section) or {})
            delta = _diff_field_changes(b_clean, c_clean)
            sec_changed: list[dict[str, Any]] = []
            if delta:
                obj_entry: dict[str, Any] = {"key": section, "label": section, "changes": delta}
                mat = _materialized_keys(delta)
                if mat:
                    obj_entry["materializedKeys"] = mat
                sec_changed.append(obj_entry)
            sec_diff: dict[str, Any] = {
                "hasChanges": bool(sec_changed),
                "added": [],
                "removed": [],
                "changed": sec_changed,
            }
        else:
            b_items, b_meta = _extract_section_items(section, baseline)
            c_items, c_meta = _extract_section_items(section, target_snapshot)
            sec_diff = _diff_object_list(section, b_items, c_items)
            meta_delta = _diff_field_changes(b_meta, c_meta)
            if meta_delta:
                meta_entry: dict[str, Any] = {"key": f"{section}:settings", "label": "settings", "changes": meta_delta}
                mat_meta = _materialized_keys(meta_delta)
                if mat_meta:
                    meta_entry["materializedKeys"] = mat_meta
                sec_diff["changed"].append(meta_entry)
                sec_diff["hasChanges"] = True

        for ch_item in sec_diff["changed"]:
            mat_fields = ch_item.get("materializedKeys")
            if mat_fields:
                materialized_defaults.append({
                    "section": section,
                    "key": ch_item["key"],
                    "label": ch_item["label"],
                    "fields": list(mat_fields),
                })

        sections_out[section] = sec_diff
        total_added += len(sec_diff["added"])
        total_removed += len(sec_diff["removed"])
        total_changed += len(sec_diff["changed"])
        if sec_diff["hasChanges"]:
            sections_changed += 1

    return {
        "comparedSource": "live" if live_used else "snapshot",
        "baselineSite": deep_redact(base_site),
        "currentSite": deep_redact(curr_site),
        "baselineCapturedAt": baseline.get("capturedAt") if isinstance(baseline.get("capturedAt"), str) else None,
        "currentCapturedAt": target_snapshot.get("capturedAt") if isinstance(target_snapshot.get("capturedAt"), str) else None,
        "crossSite": cross_site,
        "sectionsCompared": list(sections_out),
        "sectionsSkipped": sections_skipped,
        "hasChanges": bool(total_added or total_removed or total_changed),
        "summary": {
            "sectionsChanged": sections_changed,
            "added": total_added,
            "removed": total_removed,
            "changed": total_changed,
        },
        "materializedDefaults": materialized_defaults,
        "sections": sections_out,
    }


_DIFF_CONFIG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "comparedSource": {"type": "string", "enum": ["live", "snapshot"]},
        "baselineSite": {"type": ["object", "null"]},
        "currentSite": {"type": ["object", "null"]},
        "baselineCapturedAt": {"type": ["string", "null"]},
        "currentCapturedAt": {"type": ["string", "null"]},
        "crossSite": {"type": "boolean"},
        "sectionsCompared": {"type": "array", "items": {"type": "string"}},
        "sectionsSkipped": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "properties": {"baseline": _SECTION_STATUS_SCHEMA, "current": _SECTION_STATUS_SCHEMA},
                "required": ["baseline", "current"],
            },
        },
        "hasChanges": {"type": "boolean"},
        "summary": {
            "type": "object",
            "properties": {
                "sectionsChanged": {"type": "integer", "minimum": 0},
                "added": {"type": "integer", "minimum": 0},
                "removed": {"type": "integer", "minimum": 0},
                "changed": {"type": "integer", "minimum": 0},
            },
            "required": ["sectionsChanged", "added", "removed", "changed"],
        },
        "materializedDefaults": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "section": {"type": "string"},
                    "key": {"type": "string"},
                    "label": {"type": "string"},
                    "fields": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["section", "key", "label", "fields"],
            },
        },
        "sections": {"type": "object"},
    },
    "required": ["comparedSource", "crossSite", "sectionsCompared", "sectionsSkipped", "hasChanges", "summary", "sections"],
}

