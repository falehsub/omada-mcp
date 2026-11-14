"""Read domain module: devices_read."""

from __future__ import annotations

from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import PROFILE_TYPE_LABELS, resolve_raw_device, try_paginate
from ._device_helpers import collect_ap_radios_data, collect_rf_scan_data, collect_switch_ports_data
from ._tool_model import _pick, _site, as_int_or_none, normalize_mac
from ._write_fetchers import _fetch_devices, _fetch_ssids
from .clients_read import _fetch_client_rows

_DEVICE_FIELDS: tuple[tuple[str, tuple[str, ...], Any], ...] = (
    ("mac", ("mac",), ""),
    ("name", ("name",), ""),
    ("type", ("type",), ""),
    ("model", ("showModel", "compoundModel", "model"), ""),
    ("ip", ("ip",), ""),
    ("firmware", ("firmwareVersion",), ""),
    ("uptime", ("uptime", "uptimeLong"), ""),
    ("clientCount", ("clientNum",), 0),
    ("status", ("statusCategory",), -1),
    ("needUpgrade", ("needUpgrade",), False),
)


def project_device(device: dict[str, Any]) -> dict[str, Any]:
    return {out: _pick(device, *src, default=default) for out, src, default in _DEVICE_FIELDS}


_WLAN_FIELDS: tuple[str, ...] = (
    "id", "name", "ssid", "band", "enabled", "guest", "security", "vlanId",
    "networkName", "hideSsid", "macFilterEnable", "rateLimitEnable",
)


def project_wlan(wlan: dict[str, Any], group_name: str | None = None) -> dict[str, Any]:
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


def _list_devices(client: OmadaClient) -> list[dict[str, Any]]:
    site = _site(client)
    rows = _fetch_devices(client, site)
    return [project_device(row) for row in rows]


def _get_device(client: OmadaClient, mac: str) -> dict[str, Any]:
    wanted = normalize_mac(mac)
    for device in _list_devices(client):
        if normalize_mac(device.get("mac", "")) == wanted or \
                str(device.get("name", "")).lower() == str(mac).strip().lower():
            return device
    raise OmadaError(
        f"no device matches {mac!r}",
        hint="list devices first; the argument accepts a MAC or the device name",
    )


def _list_wlans(client: OmadaClient) -> list[dict[str, Any]]:
    site = _site(client)
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/wlans")
    projected: list[dict[str, Any]] = []
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


def _get_switch_ports(
    client: OmadaClient,
    mac: str,
    includeCounters: bool = True,
    includeCableTest: bool = True,
    includeDownPorts: bool = True,
    compact: bool = False,
) -> dict[str, Any]:
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
) -> dict[str, Any]:
    with client.scoped_cache():
        site = _site(client)
        ap = resolve_raw_device(client, site, mac, expected_type="ap")
        client_rows: list[dict[str, Any]] | None = None
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


def _get_rf_scan(client: OmadaClient, mac: str) -> dict[str, Any]:
    site = _site(client)
    ap = resolve_raw_device(client, site, mac, expected_type="ap")
    return collect_rf_scan_data(client, site, ap)


def _list_port_profiles(client: OmadaClient) -> list[dict[str, Any]]:
    site = _site(client)
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/lan/profiles")
    projected: list[dict[str, Any]] = []
    for row in rows:
        ptype = row.get("type")
        ptype_int = as_int_or_none(ptype) if ptype is not None else None
        projected.append({
            "id": str(row.get("id") or ""),
            "name": str(row.get("name") or ""),
            "type": ptype,
            "typeLabel": PROFILE_TYPE_LABELS.get(ptype_int, str(ptype)) if ptype_int is not None else str(ptype),
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


def _list_wlan_groups(client: OmadaClient) -> list[dict[str, Any]]:
    site = _site(client)
    groups, _ = client.paginate(f"sites/{site.site_id}/setting/wlans")
    warnings: list[str] = []
    ssid_groups, _, ok_ws = try_paginate(
        client, f"sites/{site.site_id}/wlanSsid", warnings, label="wlanSsid",
    )
    ssids_by_gid: dict[str, list[dict[str, Any]]] = {}
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
    out: list[dict[str, Any]] = []
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


_DEVICE_SCHEMA: dict[str, Any] = {
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


_WLAN_SCHEMA: dict[str, Any] = {
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


_SWITCH_PORTS_SCHEMA: dict[str, Any] = {
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


_AP_RADIOS_SCHEMA: dict[str, Any] = {
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


_RF_SCAN_SCHEMA: dict[str, Any] = {
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


_PORT_PROFILE_SCHEMA: dict[str, Any] = {
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


_WLAN_GROUP_SCHEMA: dict[str, Any] = {
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

