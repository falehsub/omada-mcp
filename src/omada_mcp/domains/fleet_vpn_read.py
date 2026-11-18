"""Read domain module: fleet, WAN IPv4/IPv6, traffic/QoS, backups, and hotspot vouchers."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ..client import OmadaClient, OmadaError, SiteInfo
from ._common import (
    as_int,
    as_mapping,
    deep_redact,
    is_device_online,
    mask_ipv4_middle,
    pagination_status,
    try_api_result,
)
from ._network_helpers import collect_wan_status_data, read_audit_source
from ._tool_model import _site
from ._write_fetchers import _fetch_devices, _fetch_lan_interfaces
from .networks_read import _extract_lan_ipv6

_DDNS_SERVICE_NAMES: dict[int, str] = {
    0: "DynDNS",
    1: "No-IP",
    2: "Peanuthull",
    3: "Comexe",
}

_FLEET_AUDIT_REQUEST_LIMIT = 128
_FLEET_SITE_REQUEST_LIMIT = 8


def _rows_from_result(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [dict(item) for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        data = raw.get("data")
        if isinstance(data, list):
            return [dict(item) for item in data if isinstance(item, dict)]
        table = raw.get("table")
        if isinstance(table, dict) and isinstance(table.get("data"), list):
            return [dict(item) for item in table["data"] if isinstance(item, dict)]
    return []


def _get_wan_ip_details(client: OmadaClient, maskWanIp: bool = True) -> dict[str, Any]:
    """Return detailed WAN IPv4/IPv6 config, DNS, WAN-port settings, and DDNS bindings."""
    site = _site(client)
    warnings: list[str] = []
    with client.scoped_cache():
        wan_data = collect_wan_status_data(
            client, site, mask_wan_ip=bool(maskWanIp)
        )
        warnings.extend(wan_data.get("warnings") or [])
        wan_ports_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/wan-ports?filters.function=WAN",
            warnings,
            label="WAN port config",
        )
        ddns_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/service/ddns",
            warnings,
            label="DDNS",
        )

    ddns_entries: list[dict[str, Any]] = []
    for row in _rows_from_result(ddns_raw):
        cleaned = deep_redact(row)
        svc_code = cleaned.get("service")
        svc_label = _DDNS_SERVICE_NAMES.get(as_int(svc_code, -1), str(svc_code))
        ddns_entries.append({
            "id": str(cleaned.get("id") or ""),
            "service": svc_code,
            "serviceName": svc_label,
            "domainName": str(cleaned.get("domainName") or ""),
            "interfacePortId": str(cleaned.get("interfacePortId") or ""),
            "username": str(cleaned.get("username") or ""),
            "updateInterval": cleaned.get("updateInterval"),
            "status": bool(cleaned.get("status", True)),
            "hasPassword": bool(row.get("password") or row.get("ddnsPwd")),
        })

    ports_out: list[dict[str, Any]] = []
    for port in wan_data.get("ports") or []:
        if not isinstance(port, dict):
            continue
        p = dict(port)
        ip = str(p.get("ip") or "")
        if maskWanIp and ip:
            p["ip"] = mask_ipv4_middle(ip)
        ports_out.append(p)

    return {
        "site": site.name,
        "siteId": site.site_id,
        "gatewayConnected": wan_data.get("gatewayConnected"),
        "wanMode": wan_data.get("wanMode"),
        "wanPortCount": len(ports_out),
        "wanPorts": ports_out,
        "wanPortSettings": deep_redact(wan_ports_raw) if isinstance(wan_ports_raw, dict) else None,
        "ddnsCount": len(ddns_entries),
        "ddnsEntries": ddns_entries,
        "warnings": warnings,
    }


def _get_ipv6_status(client: OmadaClient, maskWanIp: bool = False) -> dict[str, Any]:
    """Summarize IPv6 configuration across WAN ports and LAN/VLAN interfaces."""
    site = _site(client)
    warnings: list[str] = []
    with client.scoped_cache():
        wan_data = collect_wan_status_data(
            client, site, mask_wan_ip=bool(maskWanIp)
        )
        warnings.extend(wan_data.get("warnings") or [])
        try:
            interfaces = _fetch_lan_interfaces(client, site)
        except OmadaError as exc:
            warnings.append(f"LAN interfaces: {exc.message}")
            interfaces = []

    wan_ports: list[dict[str, Any]] = []
    wan_v6_enabled = False
    for port in wan_data.get("ports") or []:
        if not isinstance(port, dict):
            continue
        v6_addr = port.get("ipv6Address")
        v6_en = bool(port.get("ipv6Enabled"))
        if v6_en:
            wan_v6_enabled = True
        wan_ports.append({
            "portName": str(port.get("portName") or ""),
            "portUuid": str(port.get("portUuid") or ""),
            "ipv6Enabled": v6_en,
            "ipv6Proto": port.get("ipv6Proto"),
            "ipv6Address": mask_ipv4_middle(str(v6_addr)) if (maskWanIp and v6_addr) else v6_addr,
            "primaryIpv6Dns": port.get("primaryIpv6Dns"),
            "secondaryIpv6Dns": port.get("secondaryIpv6Dns"),
        })

    lan_out: list[dict[str, Any]] = []
    dual_stack_count = 0
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        v6 = _extract_lan_ipv6(iface)
        enabled = bool(v6 and v6.get("enabled"))
        if enabled:
            dual_stack_count += 1
        lan_out.append({
            "id": str(iface.get("id") or ""),
            "name": str(iface.get("name") or ""),
            "vlan": iface.get("vlan"),
            "ipv6Enabled": enabled,
            "ipv6": v6,
        })

    return {
        "site": site.name,
        "siteId": site.site_id,
        "wanIpv6Enabled": wan_v6_enabled,
        "lanCount": len(lan_out),
        "dualStackLanCount": dual_stack_count,
        "wanPorts": wan_ports,
        "lanNetworks": lan_out,
        "warnings": warnings,
    }


def _list_traffic_rules(client: OmadaClient) -> dict[str, Any]:
    """List URL filtering, bandwidth control, and session-limit rules."""
    site = _site(client)
    warnings: list[str] = []
    with client.scoped_cache():
        url_gw_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/firewall/urlfilterings?type=gateway",
            warnings,
            label="gateway URL filtering",
        )
        url_ap_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/firewall/urlfilterings?type=ap",
            warnings,
            label="AP URL filtering",
        )
        bw_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/transmission/bandwidthControls",
            warnings,
            label="bandwidth controls",
        )
        sess_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/transmission/sessionLimits",
            warnings,
            label="session limits",
        )
        acl_gw_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/firewall/acls?type=0&currentPage=1&currentPageSize=100",
            warnings,
            label="gateway ACLs",
        )

    url_gw_rows = _rows_from_result(url_gw_raw)
    url_ap_rows = _rows_from_result(url_ap_raw)
    bw_rows = _rows_from_result(bw_raw)
    sess_rows = _rows_from_result(sess_raw)
    gw_acl_rows = _rows_from_result(acl_gw_raw)

    bw_enabled = bool(bw_raw.get("bandwidthControl")) if isinstance(bw_raw, dict) and "bandwidthControl" in bw_raw else None
    sess_enabled = bool(sess_raw.get("sessionLimitEnable")) if isinstance(sess_raw, dict) and "sessionLimitEnable" in sess_raw else None

    return deep_redact({
        "site": site.name,
        "gatewayUrlFilteringCount": len(url_gw_rows),
        "gatewayUrlFilteringRules": url_gw_rows,
        "apUrlFilteringCount": len(url_ap_rows),
        "apUrlFilteringRules": url_ap_rows,
        "bandwidthControlEnabled": bw_enabled,
        "bandwidthControlCount": len(bw_rows),
        "bandwidthControlRules": bw_rows,
        "sessionLimitEnabled": sess_enabled,
        "sessionLimitCount": len(sess_rows),
        "sessionLimitRules": sess_rows,
        "gatewayAclCount": len(gw_acl_rows),
        "warnings": warnings,
    })


def _list_qos_rules(client: OmadaClient) -> dict[str, Any]:
    """List gateway QoS bandwidth-class rules, VoIP QoS, and switch queue profiles."""
    site = _site(client)
    warnings: list[str] = []
    with client.scoped_cache():
        bwc_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/qos/gateway/bwc",
            warnings,
            label="gateway QoS BWC",
        )
        class_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/qos/gateway/class-rule",
            warnings,
            label="gateway QoS class rules",
        )
        voip_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/qos/gateway/voip",
            warnings,
            label="gateway VoIP QoS",
        )
        wans_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/qos/gateway/wans",
            warnings,
            label="gateway QoS WAN limits",
        )
        sw_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/setting/qos/switch/queue-profiles",
            warnings,
            label="switch QoS queue profiles",
        )
        insight_raw, _ = try_api_result(
            client,
            f"sites/{site.site_id}/insight/qos",
            warnings,
            label="QoS insight",
        )

    bwc_rows = _rows_from_result(bwc_raw)
    class_rows = _rows_from_result(class_raw)
    wan_rows = _rows_from_result(wans_raw)
    sw_rows = _rows_from_result(sw_raw)
    insight_rows = _rows_from_result(insight_raw)

    return deep_redact({
        "site": site.name,
        "gatewayBwcRules": bwc_rows,
        "gatewayClassRules": class_rows,
        "gatewayVoipQos": voip_raw if isinstance(voip_raw, dict) else None,
        "gatewayWanLimits": wan_rows,
        "switchQueueProfiles": sw_rows,
        "insightEntries": insight_rows,
        "warnings": warnings,
    })


def _list_backups(client: OmadaClient) -> dict[str, Any]:
    """List controller auto-backup schedule, stored backup files, and current export status."""
    warnings: list[str] = []
    with client.scoped_cache():
        task_raw, _ = try_api_result(
            client,
            "autoBackup/autoBackupTask",
            warnings,
            label="auto-backup schedule",
        )
        files_raw, _ = try_api_result(
            client,
            "autoBackup/gridAutoBackupFiles?currentPage=1&currentPageSize=50",
            warnings,
            label="auto-backup files",
        )
        status_raw, _ = try_api_result(
            client,
            "maintenance/backup/result",
            warnings,
            label="manual backup status",
        )

    files = _rows_from_result(files_raw)
    return deep_redact({
        "autoBackupSchedule": task_raw if isinstance(task_raw, dict) else None,
        "backupFileCount": len(files),
        "backupFiles": files,
        "manualBackupStatus": status_raw if isinstance(status_raw, dict) else None,
        "warnings": warnings,
    })


_VOUCHER_GROUP_FIELDS: dict[str, set[type]] = {
    "id": {str, int},
    "name": {str},
    "amount": {int},
    "codeLength": {int},
    "type": {int},
    "duration": {int},
    "durationNum": {int},
    "durationUnit": {int},
    "maxUsers": {int},
    "createTime": {int},
}
_VOUCHER_FIELDS: dict[str, set[type]] = {
    "id": {str, int},
    "groupId": {str, int},
    "status": {bool, int},
    "createTime": {int},
    "expireTime": {int},
}
_VOUCHER_CREDENTIAL_KEYS = ("code", "voucherCode", "activationCode")


def _project_hotspot_row(row: dict[str, Any], *, group: bool) -> dict[str, Any]:
    """Keep only scalar metadata and drop fields that duplicate a credential."""
    fields = _VOUCHER_GROUP_FIELDS if group else _VOUCHER_FIELDS
    credentials = [row[key] for key in _VOUCHER_CREDENTIAL_KEYS if row.get(key) is not None]
    return {
        key: row[key] for key, types in fields.items()
        if key in row and type(row[key]) in types
        and all(str(row[key]) != str(credential) for credential in credentials)
    }


def _hotspot_row_schema(fields: dict[str, set[type]]) -> dict[str, Any]:
    json_types = {str: "string", int: "integer", bool: "boolean"}
    return {
        "type": "object",
        "properties": {
            name: {"type": sorted(json_types[field_type] for field_type in types)}
            for name, types in fields.items()
        },
        "additionalProperties": False,
    }


def _list_hotspot_vouchers(
    client: OmadaClient,
    groupId: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List hotspot voucher group and voucher metadata for the active site."""
    site = _site(client)
    max_rows = max(1, min(as_int(limit, 100), 1000))
    max_pages = max(1, (max_rows + 99) // 100)
    with client.scoped_cache():
        vouchers_ep = (
            f"hotspot/sites/{site.site_id}/voucherGroups/{quote(groupId, safe='')}"
            if groupId
            else f"hotspot/sites/{site.site_id}/vouchers"
        )
        try:
            groups, meta = client.paginate(
                f"hotspot/sites/{site.site_id}/voucherGroups",
                page_size=min(100, max_rows),
                max_pages=max_pages,
            )
            v_raw, available = try_api_result(
                client, f"{vouchers_ep}?currentPage=1&currentPageSize={min(100, max_rows)}",
                [], label="hotspot vouchers",
            )
        except OmadaError as exc:
            raise OmadaError("could not read hotspot voucher metadata", code=exc.code) from None
        vouchers = _rows_from_result(v_raw)

    return {
        "site": site.name,
        "siteId": site.site_id,
        "groupCount": len(groups[:max_rows]),
        "totalGroups": (meta or {}).get("totalRows", len(groups)),
        "groups": [_project_hotspot_row(row, group=True) for row in groups[:max_rows]],
        "voucherCount": len(vouchers[:max_rows]),
        "vouchers": [_project_hotspot_row(row, group=False) for row in vouchers[:max_rows]],
        "warnings": [] if available else ["Hotspot vouchers are unavailable."],
    }


def _audit_all_sites(client: OmadaClient, maxSites: int = 20) -> dict[str, Any]:
    """Audit all sites visible to the controller account (requires OMADA_ALLOW_CROSS_SITE=true)."""
    if not client.config.allow_cross_site:
        raise OmadaError(
            "cross-site fleet audit refused while OMADA_ALLOW_CROSS_SITE=false",
            hint="set OMADA_ALLOW_CROSS_SITE=true to allow multi-site fleet operations",
        )
    limit = max(1, min(as_int(maxSites, 20), 100))
    coverage: dict[str, str] = {}
    warnings: list[str] = []
    site_summaries: list[dict[str, Any]] = []
    with client.request_budget(_FLEET_AUDIT_REQUEST_LIMIT) as budget:
        collected = read_audit_source(
            lambda: client.paginate("sites", max_pages=5, page_size=50),
            "siteDirectory", "Site directory", coverage, warnings,
        )
        all_sites, meta = collected if collected is not None else ([], None)
        if collected is not None and pagination_status(meta) != "complete":
            coverage["siteDirectory"] = "partial"
            warnings.append("Site directory: partial (bounded collection).")

        for row in all_sites[:limit]:
            sid = str(row.get("id") or "")
            if not sid:
                coverage["siteDirectory"] = "partial"
                continue
            if budget.used >= budget.limit:
                warnings.append("The fleet request budget limited the number of sites checked.")
                break
            site = SiteInfo(sid, str(row.get("name") or sid))
            site_summaries.append(_audit_fleet_site(client, site))

    audited = sum(s["status"] == "complete" for s in site_summaries)
    truncated = coverage["siteDirectory"] != "complete" or len(all_sites) > len(site_summaries)
    return {
        "totalSites": len(all_sites),
        "auditedSites": len(site_summaries),
        "completeSites": audited,
        "partialSites": len(site_summaries) - audited,
        "truncated": truncated,
        "complete": not truncated and audited == len(site_summaries),
        "controllerRequests": budget.used,
        "requestLimit": budget.limit,
        "siteDirectoryStatus": coverage["siteDirectory"],
        "unhealthySites": sum(s["healthy"] is False for s in site_summaries),
        "totalDevices": sum(s["deviceCount"] or 0 for s in site_summaries),
        "totalOfflineDevices": sum(s["offlineDevices"] or 0 for s in site_summaries),
        "totalUpgradePending": sum(s["upgradePendingDevices"] or 0 for s in site_summaries),
        "warnings": warnings,
        "sites": site_summaries,
    }


def _audit_fleet_site(client: OmadaClient, site: SiteInfo) -> dict[str, Any]:
    coverage: dict[str, str] = {}
    warnings: list[str] = []
    with client.request_budget(_FLEET_SITE_REQUEST_LIMIT) as budget:
        raw_detail = read_audit_source(
            lambda: client.api_result(f"sites/{site.site_id}"),
            "site", "Site connectivity", coverage, warnings,
        )
        raw_wan = as_mapping(raw_detail).get("wan")
        wan_up = bool(raw_wan) if raw_wan in (True, False) else None
        if coverage["site"] == "complete" and wan_up is None:
            coverage["site"] = "partial"
            warnings.append("Site connectivity: WAN state was not reported.")
        devices = read_audit_source(
            lambda: _fetch_devices(client, site), "devices", "Devices", coverage, warnings,
        )
    offline = sum(not is_device_online(d) for d in devices) if devices is not None else None
    upgrades = sum(bool(d.get("needUpgrade")) for d in devices) if devices is not None else None
    complete = all(state == "complete" for state in coverage.values())
    known_unhealthy = bool(offline or upgrades or wan_up is False)
    return {
        "id": site.site_id,
        "name": site.name,
        "deviceCount": len(devices) if devices is not None else None,
        "offlineDevices": offline,
        "upgradePendingDevices": upgrades,
        "wanConnected": wan_up,
        "healthy": not known_unhealthy if complete or known_unhealthy else None,
        "status": "complete" if complete else "partial",
        "controllerRequests": budget.used,
        "coverage": coverage,
        "warnings": warnings,
    }


_WAN_IP_DETAILS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "site": {"type": "string"},
        "siteId": {"type": "string"},
        "gatewayConnected": {"type": ["boolean", "null"]},
        "wanMode": {},
        "wanPortCount": {"type": "integer", "minimum": 0},
        "wanPorts": {"type": "array", "items": {"type": "object"}},
        "wanPortSettings": {"type": ["object", "null"]},
        "ddnsCount": {"type": "integer", "minimum": 0},
        "ddnsEntries": {"type": "array", "items": {"type": "object"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["site", "siteId", "wanPortCount", "wanPorts", "ddnsCount", "ddnsEntries", "warnings"],
}

_IPV6_STATUS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "site": {"type": "string"},
        "siteId": {"type": "string"},
        "wanIpv6Enabled": {"type": "boolean"},
        "lanCount": {"type": "integer", "minimum": 0},
        "dualStackLanCount": {"type": "integer", "minimum": 0},
        "wanPorts": {"type": "array", "items": {"type": "object"}},
        "lanNetworks": {"type": "array", "items": {"type": "object"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["site", "siteId", "wanIpv6Enabled", "lanCount", "dualStackLanCount", "wanPorts", "lanNetworks", "warnings"],
}

_TRAFFIC_RULES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "site": {"type": "string"},
        "gatewayUrlFilteringCount": {"type": "integer", "minimum": 0},
        "gatewayUrlFilteringRules": {"type": "array", "items": {"type": "object"}},
        "apUrlFilteringCount": {"type": "integer", "minimum": 0},
        "apUrlFilteringRules": {"type": "array", "items": {"type": "object"}},
        "bandwidthControlEnabled": {"type": ["boolean", "null"]},
        "bandwidthControlCount": {"type": "integer", "minimum": 0},
        "bandwidthControlRules": {"type": "array", "items": {"type": "object"}},
        "sessionLimitEnabled": {"type": ["boolean", "null"]},
        "sessionLimitCount": {"type": "integer", "minimum": 0},
        "sessionLimitRules": {"type": "array", "items": {"type": "object"}},
        "gatewayAclCount": {"type": "integer", "minimum": 0},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["site", "gatewayUrlFilteringRules", "bandwidthControlRules", "sessionLimitRules", "warnings"],
}

_QOS_RULES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "site": {"type": "string"},
        "gatewayBwcRules": {"type": "array", "items": {"type": "object"}},
        "gatewayClassRules": {"type": "array", "items": {"type": "object"}},
        "gatewayVoipQos": {"type": ["object", "null"]},
        "gatewayWanLimits": {"type": "array", "items": {"type": "object"}},
        "switchQueueProfiles": {"type": "array", "items": {"type": "object"}},
        "insightEntries": {"type": "array", "items": {"type": "object"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["site", "gatewayBwcRules", "gatewayClassRules", "switchQueueProfiles", "warnings"],
}

_BACKUPS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "autoBackupSchedule": {"type": ["object", "null"]},
        "backupFileCount": {"type": "integer", "minimum": 0},
        "backupFiles": {"type": "array", "items": {"type": "object"}},
        "manualBackupStatus": {"type": ["object", "null"]},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["backupFileCount", "backupFiles", "warnings"],
}

_HOTSPOT_VOUCHERS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "site": {"type": "string"},
        "siteId": {"type": "string"},
        "groupCount": {"type": "integer", "minimum": 0},
        "totalGroups": {"type": "integer", "minimum": 0},
        "groups": {"type": "array", "items": _hotspot_row_schema(_VOUCHER_GROUP_FIELDS)},
        "voucherCount": {"type": "integer", "minimum": 0},
        "vouchers": {"type": "array", "items": _hotspot_row_schema(_VOUCHER_FIELDS)},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["site", "siteId", "groupCount", "groups", "voucherCount", "vouchers", "warnings"],
}

_FLEET_AUDIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "totalSites": {"type": "integer", "minimum": 0},
        "auditedSites": {"type": "integer", "minimum": 0},
        "completeSites": {"type": "integer", "minimum": 0},
        "partialSites": {"type": "integer", "minimum": 0},
        "truncated": {"type": "boolean"},
        "complete": {"type": "boolean"},
        "controllerRequests": {"type": "integer", "minimum": 0},
        "requestLimit": {"type": "integer", "minimum": 1},
        "siteDirectoryStatus": {"enum": ["complete", "partial", "unavailable"]},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "unhealthySites": {"type": "integer", "minimum": 0},
        "totalDevices": {"type": "integer", "minimum": 0},
        "totalOfflineDevices": {"type": "integer", "minimum": 0},
        "totalUpgradePending": {"type": "integer", "minimum": 0},
        "sites": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "deviceCount": {"type": ["integer", "null"]},
                    "offlineDevices": {"type": ["integer", "null"]},
                    "upgradePendingDevices": {"type": ["integer", "null"]},
                    "wanConnected": {"type": ["boolean", "null"]},
                    "healthy": {"type": ["boolean", "null"]},
                    "status": {"enum": ["complete", "partial"]},
                    "controllerRequests": {"type": "integer", "minimum": 0},
                    "coverage": {"type": "object"},
                    "warnings": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["id", "name", "status", "coverage", "warnings"],
            },
        },
    },
    "required": [
        "totalSites", "auditedSites", "completeSites", "partialSites", "truncated", "complete", "unhealthySites",
        "controllerRequests", "requestLimit", "siteDirectoryStatus", "warnings",
        "totalDevices", "totalOfflineDevices", "totalUpgradePending", "sites",
    ],
}
