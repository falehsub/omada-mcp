"""Read domain module: switch_wifi_read (Phase B Switch L2 & Wi-Fi/RF coverage)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import (
    as_int,
    as_mapping,
    deep_redact,
    resolve_device_detail,
    try_api_result,
    try_paginate,
    unwrap_rows,
)
from ._device_helpers import collect_switch_ports_data
from ._tool_model import _site, as_int_or_none, normalize_mac
from ._write_fetchers import (
    _fetch_devices,
    _fetch_poe_schedules,
    _fetch_schedules,
    _fetch_switch_lags,
    _omada_mac,
)

STP_MODE_LABELS: dict[int, str] = {
    0: "off",
    1: "stp",
    2: "rstp",
    3: "mstp",
}

RF_SCAN_STATUS_LABELS: dict[int, str] = {
    0: "completed",
    1: "idle",
    2: "running",
}

LAG_TYPE_LABELS: dict[int, str] = {
    1: "static",
    2: "lacp",
    3: "lacp_active",
    4: "lacp_passive",
}


def _strip_override_secrets(entry: Mapping[str, Any]) -> dict[str, Any]:
    raw_psk = entry.get("psk") or entry.get("securityKey")
    has_psk = bool(raw_psk)
    cleaned = deep_redact(
        {k: v for k, v in entry.items() if k not in ("psk", "securityKey", "passphrase", "password")}
    )
    cleaned["hasPresharedKey"] = has_psk
    return cleaned


def _try_mapping(
    client: OmadaClient,
    endpoint: str,
    warnings: list[str],
    *,
    label: str,
) -> dict[str, Any]:
    raw, ok = try_api_result(client, endpoint, warnings, label=label)
    return dict(raw) if ok and isinstance(raw, Mapping) else {}


def _get_wifi_radio_features(client: OmadaClient) -> dict[str, Any]:
    """Return site-wide Wi-Fi radio & roaming features (802.11r/k, band steering, ATF, mesh, beacon, mcast limit)."""
    site = _site(client)
    warnings: list[str] = []
    source = "setting/wireless/feature"
    raw = _try_mapping(client, f"sites/{site.site_id}/setting/wireless/feature", warnings, label="wireless/feature")
    if not raw:
        raw = _try_mapping(client, f"sites/{site.site_id}/setting", warnings, label="setting")
        source = "setting"
    if not raw:
        raise OmadaError(
            "wireless radio features endpoint is unavailable on this controller",
            hint="; ".join(warnings) or "Verify site settings access on the controller.",
        )

    roaming = dict(raw.get("roaming") or {}) if isinstance(raw.get("roaming"), Mapping) else {}
    band_steering = dict(raw.get("bandSteering") or {}) if isinstance(raw.get("bandSteering"), Mapping) else {}
    multi_band_bs = (
        dict(raw.get("bandSteeringForMultiBand") or {})
        if isinstance(raw.get("bandSteeringForMultiBand"), Mapping)
        else {}
    )
    atf = dict(raw.get("airtimeFairness") or {}) if isinstance(raw.get("airtimeFairness"), Mapping) else {}
    mesh = dict(raw.get("mesh") or {}) if isinstance(raw.get("mesh"), Mapping) else {}
    beacon = dict(raw.get("beaconControl") or {}) if isinstance(raw.get("beaconControl"), Mapping) else {}
    lldp = dict(raw.get("lldp") or {}) if isinstance(raw.get("lldp"), Mapping) else {}
    adv = dict(raw.get("advancedFeature") or {}) if isinstance(raw.get("advancedFeature"), Mapping) else {}
    mcast = dict(raw.get("mcastRateLimit") or {}) if isinstance(raw.get("mcastRateLimit"), Mapping) else {}

    return deep_redact({
        "source": source,
        "roaming": {
            "fastRoaming80211r": bool(roaming.get("fastRoamingEnable", False)),
            "aiRoamingEnable": bool(roaming.get("aiRoamingEnable", False)),
            "dualBand11kReportEnable": bool(roaming.get("dualBand11kReportEnable", False)),
            "forceDisassociationEnable": bool(roaming.get("forceDisassociationEnable", False)),
            "nonStickRoamingEnable": bool(roaming.get("nonStickRoamingEnable", False)),
            "nonPingPongRoamingEnable": bool(roaming.get("nonPingPongRoamingEnable", False)),
        },
        "bandSteering": {
            "enable": bool(band_steering.get("enable", False)),
            "connectionThreshold": band_steering.get("connectionThreshold"),
            "differenceThreshold": band_steering.get("differenceThreshold"),
            "maxFailures": band_steering.get("maxFailures"),
            "multiBandMode": multi_band_bs.get("mode"),
        },
        "airtimeFairness": {
            "enable2g": bool(atf.get("enable2g", False)),
            "enable5g": bool(atf.get("enable5g", False)),
            "enable6g": bool(atf.get("enable6g", False)),
        },
        "mesh": {
            "meshEnable": bool(mesh.get("meshEnable", False)),
            "autoFailoverEnable": bool(mesh.get("autoFailoverEnable", False)),
            "defGatewayEnable": bool(mesh.get("defGatewayEnable", False)),
            "fullSector": bool(mesh.get("fullSector", False)),
        },
        "advancedFeatureEnable": bool(adv.get("enable", False)) if adv else None,
        "lldpEnable": bool(lldp.get("enable", False)) if lldp else None,
        "beaconControl": beacon,
        "mcastRateLimit": mcast,
        "warnings": warnings,
    })


def _get_ap_ssid_overrides(client: OmadaClient, mac: str) -> dict[str, Any]:
    """Inspect per-AP WLAN group binding and SSID overrides (name, enable, VLAN, PSK indicator)."""
    site = _site(client)
    ap = resolve_device_detail(client, site, mac, expected_type="ap")
    norm_mac = normalize_mac(str(ap.get("mac") or ""))
    wlan_id = str(ap.get("wlanId") or "")

    warnings: list[str] = []
    wlan_group_name = ""
    groups, _, ok_groups = try_paginate(client, f"sites/{site.site_id}/setting/wlans", warnings, label="setting/wlans")
    if ok_groups and wlan_id:
        for grp in groups:
            if str(grp.get("id") or "") == wlan_id:
                wlan_group_name = str(grp.get("name") or "")
                break

    raw_overrides = ap.get("ssidOverrides")
    overrides: list[dict[str, Any]] = []
    if isinstance(raw_overrides, list):
        for entry in raw_overrides:
            if not isinstance(entry, Mapping):
                continue
            item = _strip_override_secrets(entry)
            item.setdefault("index", entry.get("index"))
            item.setdefault("globalSsid", str(entry.get("globalSsid") or ""))
            item.setdefault("ssid", str(entry.get("ssid") or ""))
            item.setdefault("enable", bool(entry.get("enable", False)))
            item.setdefault("ssidEnable", bool(entry.get("ssidEnable", True)))
            item.setdefault("vlanEnable", bool(entry.get("vlanEnable", False)))
            item.setdefault("vlanId", entry.get("vlanId"))
            overrides.append(item)

    return {
        "mac": norm_mac,
        "name": str(ap.get("name") or norm_mac),
        "wlanId": wlan_id,
        "wlanGroupName": wlan_group_name,
        "overrideCount": sum(1 for item in overrides if item.get("enable")),
        "totalSsids": len(overrides),
        "overrides": overrides,
        "warnings": warnings,
    }


def _get_mesh_status(client: OmadaClient, mac: str | None = None) -> dict[str, Any]:
    """Return site mesh policy plus per-AP wireless mesh/uplink/downlink roles and candidate parents."""
    site = _site(client)
    warnings: list[str] = []
    wf = _try_mapping(client, f"sites/{site.site_id}/setting/wireless/feature", warnings, label="wireless/feature")
    if not wf:
        wf = _try_mapping(client, f"sites/{site.site_id}/setting", warnings, label="setting")
    mesh_cfg = dict(wf.get("mesh") or {}) if isinstance(wf.get("mesh"), Mapping) else {}

    if mac is not None and str(mac).strip():
        aps = [resolve_device_detail(client, site, mac, expected_type="ap")]
    else:
        devices = _fetch_devices(client, site)
        aps = [
            resolve_device_detail(client, site, str(d["mac"]), expected_type="ap")
            for d in devices
            if str(d.get("type") or "").lower() == "ap" and d.get("mac")
        ]

    ap_entries: list[dict[str, Any]] = []
    for ap in aps:
        dev_mac = _omada_mac(str(ap.get("mac") or ""))
        dev_cap = as_mapping(ap.get("devCap"))
        dev_misc = as_mapping(ap.get("deviceMisc"))
        support_mesh = bool(dev_misc.get("supportMesh") or dev_cap.get("meshChainNum"))

        downlinks: list[dict[str, Any]] = []
        for dl in ap.get("downlinkList") or []:
            if isinstance(dl, Mapping):
                downlinks.append({
                    "mac": normalize_mac(str(dl.get("mac") or "")),
                    "name": str(dl.get("name") or ""),
                    "rssi": dl.get("rssi"),
                })

        candidates: list[dict[str, Any]] = []
        if support_mesh and (mac is not None or bool(ap.get("wirelessLinked"))):
            raw_cand = _try_mapping(
                client,
                f"sites/{site.site_id}/eaps/{dev_mac}/grid/mesh/candiParents",
                warnings,
                label=f"candiParents:{dev_mac}",
            )
            c_rows_raw = raw_cand.get("data")
            c_rows = c_rows_raw if isinstance(c_rows_raw, list) else []
            for row in c_rows:
                if isinstance(row, Mapping):
                    candidates.append({
                        "mac": normalize_mac(str(row.get("mac") or "")),
                        "name": str(row.get("name") or ""),
                        "rssi": row.get("rssi"),
                        "channel": row.get("channel"),
                        "hop": row.get("hop"),
                        "linkStatus": row.get("linkStatus"),
                        "recommend": bool(row.get("recommend", False)),
                    })

        wired_uplink = ap.get("wiredUplink")
        if isinstance(wired_uplink, Mapping):
            wired_uplink = deep_redact(dict(wired_uplink))

        ap_entries.append({
            "mac": normalize_mac(dev_mac),
            "name": str(ap.get("name") or dev_mac),
            "model": str(ap.get("showModel") or ap.get("model") or ""),
            "online": (ap.get("statusCategory") == 1) or (ap.get("status") in (1, 14)),
            "supportMesh": support_mesh,
            "meshChainMaxHops": as_int_or_none(dev_cap.get("meshChainNum")),
            "wirelessLinked": bool(ap.get("wirelessLinked", False)),
            "isMeshStatus": ap.get("isMeshStatus"),
            "wiredUplink": wired_uplink,
            "downlinkCount": len(downlinks),
            "downlinks": downlinks,
            "candidateParents": candidates,
        })

    return {
        "siteMesh": {
            "meshEnable": bool(mesh_cfg.get("meshEnable", False)),
            "autoFailoverEnable": bool(mesh_cfg.get("autoFailoverEnable", False)),
            "defGatewayEnable": bool(mesh_cfg.get("defGatewayEnable", False)),
            "fullSector": bool(mesh_cfg.get("fullSector", False)),
        },
        "apCount": len(ap_entries),
        "wirelessMeshApCount": sum(1 for a in ap_entries if a["wirelessLinked"]),
        "aps": ap_entries,
        "warnings": warnings,
    }


def _get_wlan_optimization_status(client: OmadaClient) -> dict[str, Any]:
    """Read AI RF Planning configuration, live optimization scan status, and experience history."""
    site = _site(client)
    warnings: list[str] = []
    cfg = _try_mapping(client, f"sites/{site.site_id}/rfPlanning", warnings, label="rfPlanning")
    res = _try_mapping(client, f"sites/{site.site_id}/rfPlanning/result", warnings, label="rfPlanning/result")
    exp = _try_mapping(client, f"sites/{site.site_id}/experienceIndex", warnings, label="experienceIndex")
    hist = _try_mapping(client, f"sites/{site.site_id}/rfplanning/history", warnings, label="rfplanning/history")

    status_code = as_int_or_none(res.get("status"))
    status_label = RF_SCAN_STATUS_LABELS.get(status_code, str(status_code)) if status_code is not None else "unknown"
    last_scan = exp.get("lastScan") if isinstance(exp.get("lastScan"), list) else []

    return deep_redact({
        "config": cfg,
        "scanStatus": {
            "status": status_code,
            "statusLabel": status_label,
            "planningHistoryId": res.get("planningHistroyId") or res.get("planningHistoryId"),
        },
        "experienceHistory": last_scan,
        "firstDeploy": hist.get("firstDeploy") if isinstance(hist, Mapping) else None,
        "warnings": warnings,
    })


def _list_switch_lags(client: OmadaClient, mac: str) -> dict[str, Any]:
    """List LAG/LACP port-channel groups and capabilities on a managed switch."""
    site = _site(client)
    sw = resolve_device_detail(client, site, mac, expected_type="switch")
    dev_mac = _omada_mac(str(sw.get("mac") or ""))
    dev_cap = as_mapping(sw.get("devCap"))
    lag_cap = as_mapping(dev_cap.get("lagCap"))

    warnings: list[str] = []
    rows = _fetch_switch_lags(client, site, dev_mac, sw_detail=sw, warnings=warnings)
    items: list[dict[str, Any]] = []
    for row in rows:
        ltype = as_int_or_none(row.get("lagType"))
        if ltype is None and isinstance(row.get("lagSetting"), Mapping):
            ltype = as_int_or_none(as_mapping(row.get("lagSetting")).get("lagType"))
        ports = row.get("ports")
        if not isinstance(ports, list):
            ports = []
        items.append(deep_redact({
            "lagId": as_int(row.get("lagId"), 0),
            "name": str(row.get("name") or f"LAG {row.get('lagId', '')}"),
            "lagType": ltype,
            "lagTypeLabel": LAG_TYPE_LABELS.get(ltype, str(ltype)) if ltype is not None else "unknown",
            "ports": [as_int(p, 0) for p in ports if isinstance(p, (int, str))],
            "disable": bool(row.get("disable", False)),
            "profileId": str(row.get("profileId") or ""),
            "profileName": str(row.get("profileName") or ""),
            "portStatus": row.get("portStatus"),
        }))
    items.sort(key=lambda item: item["lagId"])

    return {
        "mac": normalize_mac(dev_mac),
        "name": str(sw.get("name") or dev_mac),
        "lagCount": len(items),
        "maxLagNum": as_int_or_none(dev_cap.get("maxLagNum")),
        "maxLagMember": as_int_or_none(dev_cap.get("maxLagMember")),
        "maxLacpMember": as_int_or_none(dev_cap.get("maxLacpMember")),
        "lacpModeSupport": bool(lag_cap.get("lacpModSupport", False)),
        "lags": items,
        "warnings": warnings,
    }


def _get_switch_global_features(client: OmadaClient, mac: str) -> dict[str, Any]:
    """Read switch-level L2 features (STP/RSTP/MSTP, Loopback Detection, Jumbo Frame, Multicast, Port Mirrors)."""
    site = _site(client)
    sw = resolve_device_detail(client, site, mac, expected_type="switch")
    norm_mac = normalize_mac(str(sw.get("mac") or ""))
    dev_cap = as_mapping(sw.get("devCap"))

    stp_code = as_int_or_none(sw.get("stp"))
    jumbo_mtu = as_int_or_none(sw.get("jumbo"))
    jumbo_enable = sw.get("jumboEnable")
    if jumbo_enable is None and jumbo_mtu is not None:
        jumbo_enable = jumbo_mtu > 1518

    ports_data = collect_switch_ports_data(
        client, site, sw, include_counters=False, include_cable_test=False, include_down_ports=True, compact=True
    )
    warnings = list(ports_data.get("warnings") or [])
    raw_ports_ep, ok_ports = try_api_result(
        client, f"sites/{site.site_id}/switches/{_omada_mac(norm_mac)}/ports", warnings, label="switch/ports"
    )
    port_rows = unwrap_rows(raw_ports_ep) if ok_ports else (sw.get("ports") or [])
    mirrors: list[dict[str, Any]] = []
    for raw_p in port_rows:
        if not isinstance(raw_p, Mapping):
            continue
        if str(raw_p.get("operation") or "").lower() == "mirroring":
            mirrors.append({
                "mirroringPort": as_int(raw_p.get("port"), 0),
                "name": str(raw_p.get("name") or ""),
                "mirroredPorts": list(raw_p.get("mirroredPorts") or []),
                "mirroredLags": [
                    m.get("lagId") for m in (raw_p.get("mirroredLags") or []) if isinstance(m, Mapping)
                ],
            })

    site_setting = _try_mapping(client, f"sites/{site.site_id}/setting", warnings, label="setting")
    lldp = as_mapping(site_setting.get("lldp"))

    return deep_redact({
        "mac": norm_mac,
        "name": str(sw.get("name") or norm_mac),
        "model": str(sw.get("showModel") or sw.get("model") or ""),
        "easySmart": bool(sw.get("es", False)),
        "stp": {
            "mode": stp_code,
            "modeLabel": STP_MODE_LABELS.get(stp_code, str(stp_code)) if stp_code is not None else "unknown",
            "priority": sw.get("priority"),
            "helloTime": sw.get("helloTime"),
            "maxAge": sw.get("maxAge"),
            "forwardDelay": sw.get("forwardDelay"),
            "txHoldCount": sw.get("txHoldCount"),
            "maxHops": sw.get("maxHops"),
            "stpExtendSupport": bool(dev_cap.get("stpExtendSupport", False)),
        },
        "loopbackDetectEnable": bool(sw.get("loopbackDetectEnable", False)),
        "loopbackCount": as_int(sw.get("loopbackNum"), 0),
        "jumbo": {
            "enable": bool(jumbo_enable),
            "mtu": jumbo_mtu,
            "supported": bool(dev_cap.get("jumboSupport", False)),
        },
        "multicastEnable": sw.get("multicast"),
        "lldpSiteEnable": lldp.get("enable") if lldp else None,
        "capabilities": {
            "flowControlSupport": bool(dev_cap.get("flowControlSupport", False)),
            "eeeSupport": bool(dev_cap.get("eeeSupport", False)),
            "mirrorSupport": bool(dev_cap.get("mirrorSupport", False)),
            "maxMirrorGroup": as_int_or_none(dev_cap.get("maxMirrorGroup")),
            "maxMirroredPort": as_int_or_none(dev_cap.get("maxMirroredPort")),
            "igmpFastLeaveSupport": bool(dev_cap.get("igmpFastLeaveSupport", False)),
            "dhcpSnoopSupport": bool(dev_cap.get("supportDhcpSnoop", False)),
            "arpDetectSupport": bool(dev_cap.get("supportArpDetect", False)),
        },
        "portMirrors": mirrors,
        "uplinkPorts": ports_data.get("uplinkPorts") or [],
        "warnings": warnings,
    })


def _list_poe_schedules(client: OmadaClient, *, strict: bool = False) -> list[dict[str, Any]]:
    """List site PoE schedules with resolved time-range names and switch port bindings."""
    site = _site(client)
    warnings: list[str] = []
    if strict:
        rows = _fetch_poe_schedules(client, site)
    else:
        rows, _, ok = try_paginate(
            client, f"sites/{site.site_id}/setting/service/poeSchedules", warnings, label="poeSchedules"
        )
        if not ok:
            raise OmadaError(
                "PoE schedules endpoint (setting/service/poeSchedules) is unavailable on this controller",
                hint="; ".join(warnings) or "Ensure a PoE-capable switch/controller supports PoE scheduling.",
            )
    if not rows:
        return []

    sched_names: dict[str, str] = {}
    try:
        for s in _fetch_schedules(client, site):
            sid_s = str(s.get("id") or "")
            if sid_s:
                sched_names[sid_s] = str(s.get("name") or "")
    except OmadaError:
        if strict:
            raise

    dev_names: dict[str, str] = {}
    try:
        for d in _fetch_devices(client, site):
            dmac = normalize_mac(str(d.get("mac") or ""))
            if dmac:
                dev_names[dmac] = str(d.get("name") or dmac)
    except OmadaError:
        if strict:
            raise

    out: list[dict[str, Any]] = []
    for row in rows:
        turn_on_id = str(row.get("turnOnTime") or "")
        raw_map = as_mapping(row.get("poePortsMap"))
        bindings: list[dict[str, Any]] = []
        for raw_mac, raw_ports in raw_map.items():
            nmac = normalize_mac(str(raw_mac))
            port_nums = [as_int(p, 0) for p in (raw_ports or []) if isinstance(p, (int, str))]
            bindings.append({
                "mac": nmac,
                "deviceName": dev_names.get(nmac, nmac),
                "ports": sorted(port_nums),
            })
        bindings.sort(key=lambda b: b["mac"])
        out.append(deep_redact({
            "id": str(row.get("id") or ""),
            "name": str(row.get("name") or ""),
            "enabled": bool(row.get("status", True)),
            "scheduleId": turn_on_id,
            "scheduleName": sched_names.get(turn_on_id, ""),
            "poeScheduleType": row.get("poeScheduleType"),
            "poePortsMap": {normalize_mac(str(k)): list(v or []) for k, v in raw_map.items()},
            "portBindings": bindings,
            "nextExecute": row.get("nextExecute"),
        }))
    out.sort(key=lambda item: (item["name"].lower(), item["id"]))
    return out


_WIFI_RADIO_FEATURES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "source": {"type": "string"},
        "roaming": {"type": "object"},
        "bandSteering": {"type": "object"},
        "airtimeFairness": {"type": "object"},
        "mesh": {"type": "object"},
        "beaconControl": {"type": "object"},
        "mcastRateLimit": {"type": "object"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["source", "roaming", "bandSteering", "airtimeFairness", "mesh", "warnings"],
}

_AP_SSID_OVERRIDES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "wlanId": {"type": "string"},
        "wlanGroupName": {"type": "string"},
        "overrideCount": {"type": "integer", "minimum": 0},
        "totalSsids": {"type": "integer", "minimum": 0},
        "overrides": {"type": "array", "items": {"type": "object"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["mac", "name", "wlanId", "overrideCount", "totalSsids", "overrides", "warnings"],
}

_MESH_STATUS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "siteMesh": {"type": "object"},
        "apCount": {"type": "integer", "minimum": 0},
        "wirelessMeshApCount": {"type": "integer", "minimum": 0},
        "aps": {"type": "array", "items": {"type": "object"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["siteMesh", "apCount", "wirelessMeshApCount", "aps", "warnings"],
}

_WLAN_OPTIMIZATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "config": {"type": "object"},
        "scanStatus": {"type": "object"},
        "experienceHistory": {"type": "array", "items": {"type": "object"}},
        "firstDeploy": {"type": ["boolean", "null"]},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["config", "scanStatus", "experienceHistory", "warnings"],
}

_SWITCH_LAGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "lagCount": {"type": "integer", "minimum": 0},
        "maxLagNum": {"type": ["integer", "null"]},
        "maxLagMember": {"type": ["integer", "null"]},
        "maxLacpMember": {"type": ["integer", "null"]},
        "lacpModeSupport": {"type": "boolean"},
        "lags": {"type": "array", "items": {"type": "object"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["mac", "name", "lagCount", "lags", "warnings"],
}

_SWITCH_GLOBAL_FEATURES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "model": {"type": "string"},
        "easySmart": {"type": "boolean"},
        "stp": {"type": "object"},
        "loopbackDetectEnable": {"type": "boolean"},
        "loopbackCount": {"type": "integer"},
        "jumbo": {"type": "object"},
        "multicastEnable": {},
        "capabilities": {"type": "object"},
        "portMirrors": {"type": "array", "items": {"type": "object"}},
        "uplinkPorts": {"type": "array", "items": {"type": "integer"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["mac", "name", "stp", "loopbackDetectEnable", "jumbo", "capabilities", "portMirrors", "warnings"],
}

_POE_SCHEDULE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "enabled": {"type": "boolean"},
        "scheduleId": {"type": "string"},
        "scheduleName": {"type": "string"},
        "poePortsMap": {"type": "object"},
        "portBindings": {"type": "array", "items": {"type": "object"}},
    },
    "required": ["id", "name", "enabled", "scheduleId", "poePortsMap", "portBindings"],
}
