"""Shared read-only normalization, safety-inspection, and diagnostic helpers.

Python 3.10+ standard library only (zero runtime dependencies). Both
``tools.py`` (read-only diagnostics) and ``write_tools.py`` (pre-mutation
guards and validators) import these helpers so uplink/LAG detection, AP radio
channel/width validation, WAN status, and secret redaction live in one place.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from .client import OmadaClient, OmadaError, OmadaSessionExpiredError, SiteInfo, redact_secrets

_OPTIONAL_UNAVAILABLE_CODES = frozenset({
    -1, -1001, -1005, -1007, -1600, -30129, -30130, -33004, -33005, -40001, -41011,
})

_PEM_SECRET_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)

LINK_SPEED_LABELS: Dict[int, str] = {
    0: "auto",
    1: "10M",
    2: "100M",
    3: "1000M",
    4: "10000M",
    5: "2500M",
    6: "5000M",
    7: "25000M",
}

LINK_SPEED_MBPS: Dict[int, int] = {
    0: 0,
    1: 10,
    2: 100,
    3: 1000,
    4: 10000,
    5: 2500,
    6: 5000,
    7: 25000,
}

DUPLEX_LABELS: Dict[int, str] = {
    0: "auto",
    1: "half",
    2: "full",
}

CHANNEL_WIDTH_LABELS: Dict[str, str] = {
    "2": "20MHz",
    "3": "40MHz",
    "4": "AUTO",
    "5": "80MHz",
    "6": "AUTO",
    "7": "160MHz",
    "8": "AUTO",
    "9": "240MHz",
    "10": "320MHz",
}

CHANNEL_WIDTH_AUTO_BY_BAND: Dict[str, str] = {
    "2g": "4",
    "5g": "6",
    "5g2": "6",
    "6g": "8",
}

CHANNEL_WIDTH_TO_CODE: Dict[str, Dict[str, str]] = {
    "2g": {"20": "2", "20mhz": "2", "40": "3", "40mhz": "3", "auto": "4"},
    "5g": {"20": "2", "20mhz": "2", "40": "3", "40mhz": "3", "80": "5", "80mhz": "5",
           "160": "7", "160mhz": "7", "auto": "6"},
    "5g2": {"20": "2", "20mhz": "2", "40": "3", "40mhz": "3", "80": "5", "80mhz": "5",
            "160": "7", "160mhz": "7", "auto": "6"},
    "6g": {"20": "2", "20mhz": "2", "40": "3", "40mhz": "3", "80": "5", "80mhz": "5",
           "160": "7", "160mhz": "7", "240": "9", "240mhz": "9", "320": "10", "320mhz": "10",
           "auto": "8"},
}

TX_POWER_LEVEL_LABELS: Dict[int, str] = {
    0: "low",
    1: "medium",
    2: "high",
    3: "custom",
    4: "auto",
}

TX_POWER_LEVEL_TO_CODE: Dict[str, int] = {
    "low": 0,
    "medium": 1,
    "med": 1,
    "high": 2,
    "custom": 3,
    "auto": 4,
}

PROFILE_TYPE_LABELS: Dict[int, str] = {
    0: "all",
    1: "disable",
    2: "custom",
    3: "lag",
}

ACL_TYPE_MAP: Dict[str, int] = {
    "gateway": 0,
    "switch": 1,
    "eap": 2,
}

ACL_TYPE_LABELS: Dict[int, str] = {
    0: "gateway",
    1: "switch",
    2: "eap",
}


def normalize_mac(value: str) -> str:
    """Normalise ``AABBCCDDEEFF`` / ``AA-BB-CC-DD-EE-FF`` / ``aa:bb:..`` to colons."""
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).lower()
    if len(cleaned) == 12 and all(ch in "0123456789abcdef" for ch in cleaned):
        return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    return str(value or "").strip().lower()


def omada_mac(value: str) -> str:
    """Format a 12-hex MAC address as uppercase hyphen-delimited ``AA-BB-CC-DD-EE-FF``."""
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).upper()
    if len(cleaned) == 12 and all(ch in "0123456789ABCDEF" for ch in cleaned):
        return "-".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    return str(value or "").strip()


def as_int(value: Any, default: int = 0) -> int:
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def deep_redact(value: Any) -> Any:
    """Recursively mask secret fields and embedded private-key PEM blocks."""
    cleaned = redact_secrets(value)
    if isinstance(cleaned, str):
        if _PEM_SECRET_RE.search(cleaned):
            return _PEM_SECRET_RE.sub("***REDACTED***", cleaned)
        return cleaned
    if isinstance(cleaned, list):
        return [deep_redact(item) for item in cleaned]
    if isinstance(cleaned, dict):
        out: Dict[str, Any] = {}
        for k, v in cleaned.items():
            kl = str(k).lower()
            if any(tok in kl for tok in ("privatekey", "preshared", "passphrase", "secret", "password", "community")):
                if v not in (None, "", False, True):
                    out[k] = "***REDACTED***"
                    continue
            out[k] = deep_redact(v)
        return out
    return cleaned


_NON_PUBLIC_V4_NETS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def mask_ipv4_middle(ip: str) -> str:
    """Mask host octets of a non-RFC1918 WAN IP address while preserving network hint."""
    raw = str(ip or "").strip()
    if not raw or raw in ("0.0.0.0", "-"):
        return raw
    try:
        addr = ipaddress.IPv4Address(raw)
    except ipaddress.AddressValueError:
        if ":" in raw:
            parts = raw.split(":")
            return ":".join(parts[:2] + ["***"]) if len(parts) > 2 else raw
        return raw
    if any(addr in net for net in _NON_PUBLIC_V4_NETS):
        return raw
    octets = raw.split(".")
    return f"{octets[0]}.{octets[1]}.***.***"


def width_flag_to_widths(width_flag: Optional[int]) -> List[str]:
    """Decode Omada channelInfo ``widthFlag`` bitmask into supported channel widths."""
    if width_flag is None or isinstance(width_flag, bool):
        return []
    try:
        wf = int(width_flag)
    except (TypeError, ValueError):
        return []
    widths: List[str] = []
    if (wf & 65536) != 0:
        widths.append("20MHz")
    if (wf & 393216) != 0:
        widths.append("40MHz")
    if (wf & 8388864) == 8388864:
        widths.append("80MHz")
    if (wf & 16777472) == 16777472:
        widths.append("160MHz")
    if (wf & 67109120) == 67109120:
        widths.append("240MHz")
    if (wf & 33554688) == 33554688:
        widths.append("320MHz")
    return widths


def try_api_result(
    client: OmadaClient,
    endpoint: str,
    warnings: List[str],
    *,
    label: str = "",
) -> Tuple[Optional[Any], bool]:
    """Fetch an optional GET endpoint, converting feature/hardware absences to warnings."""
    tag = label or endpoint
    try:
        return client.api_result(endpoint), True
    except OmadaSessionExpiredError:
        raise
    except OmadaError as exc:
        if exc.code is None or exc.code in _OPTIONAL_UNAVAILABLE_CODES:
            warnings.append(f"{tag}: unavailable ({exc.code}: {exc})")
            return None, False
        raise


def try_paginate(
    client: OmadaClient,
    endpoint: str,
    warnings: List[str],
    *,
    label: str = "",
    page_size: int = 100,
    max_pages: int = 20,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]], bool]:
    """Paginate an optional GET endpoint gracefully on missing hardware/features."""
    tag = label or endpoint
    try:
        rows, meta = client.paginate(endpoint, page_size=page_size, max_pages=max_pages)
        return rows, meta, True
    except OmadaSessionExpiredError:
        raise
    except OmadaError as exc:
        if exc.code is None or exc.code in _OPTIONAL_UNAVAILABLE_CODES:
            warnings.append(f"{tag}: unavailable ({exc.code}: {exc})")
            return [], None, False
        raise


def is_device_online(dev: Mapping[str, Any]) -> bool:
    status_cat = dev.get("statusCategory")
    status_val = dev.get("status")
    return (status_cat == 1) or (status_cat is None and status_val in (1, 14))


def unwrap_rows(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [dict(r) for r in payload if isinstance(r, Mapping)]
    if isinstance(payload, Mapping):
        data = payload.get("data")
        if isinstance(data, list):
            return [dict(r) for r in data if isinstance(r, Mapping)]
    return []


def resolve_raw_device(
    client: OmadaClient,
    site: SiteInfo,
    mac_or_query: str,
    *,
    expected_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve a raw device dict from ``sites/{site}/devices`` by MAC or exact name."""
    raw = client.api_result(f"sites/{site.site_id}/devices")
    devices = unwrap_rows(raw)
    wanted_mac = normalize_mac(mac_or_query)
    wanted_name = str(mac_or_query or "").strip().lower()
    matched: Optional[Dict[str, Any]] = None
    for dev in devices:
        if normalize_mac(str(dev.get("mac") or "")) == wanted_mac or (
            wanted_name and str(dev.get("name") or "").strip().lower() == wanted_name
        ):
            matched = dev
            break
    if matched is None:
        raise OmadaError(
            f"no device matches {mac_or_query!r}",
            hint="list_devices first; accepts a device MAC address or exact device name",
        )
    if expected_type and str(matched.get("type") or "").lower() != expected_type.lower():
        raise OmadaError(
            f"device {matched.get('name') or matched.get('mac')} is type "
            f"{matched.get('type')!r}, expected {expected_type!r}",
            hint=f"pass the MAC or name of an adopted {expected_type}",
        )
    return matched


def _speed_label(code: Any) -> str:
    if isinstance(code, str) and not code.isdigit():
        return code
    return LINK_SPEED_LABELS.get(as_int(code, -1), f"unknown({code})")


def _speed_mbps(code: Any) -> int:
    return LINK_SPEED_MBPS.get(as_int(code, -1), 0)


def _duplex_label(code: Any) -> str:
    if isinstance(code, str) and not code.isdigit():
        return code
    return DUPLEX_LABELS.get(as_int(code, -1), f"unknown({code})")


def _controller_host_from_config(client: OmadaClient) -> Optional[str]:
    parsed = urlparse(client.config.base_url or "")
    return parsed.hostname.lower() if parsed.hostname else None


def _topology_downlinks_for_switch(
    topo_raw: Optional[Mapping[str, Any]],
    switch_mac_norm: str,
) -> Tuple[Optional[int], Set[int]]:
    """Extract (uplink_port, controller_hosting_ports) for a switch from topology-v2."""
    uplink_port: Optional[int] = None
    controller_ports: Set[int] = set()
    if not isinstance(topo_raw, Mapping):
        return uplink_port, controller_ports

    roots = topo_raw.get("topologyArray")
    if not isinstance(roots, list):
        return uplink_port, controller_ports

    def walk(node: Any) -> None:
        nonlocal uplink_port
        if not isinstance(node, Mapping):
            return
        node_mac = normalize_mac(str(node.get("mac") or ""))
        if node_mac == switch_mac_norm:
            for key in ("wireUpLink", "wiredUpInfo", "switchUpLink", "upperPort"):
                blk = node.get(key)
                if isinstance(blk, Mapping):
                    # On the switch's own uplink block, ``port`` is this switch's local port
                    # while ``upLinkPort`` is the upstream neighbor's port (e.g. gateway LAN3).
                    up = blk.get("port") or blk.get("upLinkPort")
                    pnum = up.get("port") if isinstance(up, Mapping) else up
                    if pnum is not None and str(pnum).isdigit():
                        uplink_port = int(pnum)
                        break
            for succ in node.get("successors") or []:
                if not isinstance(succ, Mapping):
                    continue
                stype = str(succ.get("type") or succ.get("clientType") or "").lower()
                sname = str(succ.get("name") or "").lower()
                if "controller" in stype or "omada controller" in sname:
                    for key in ("switchUpLink", "wiredUpInfo", "wireUpLink", "upperPort"):
                        blk = succ.get(key)
                        if isinstance(blk, Mapping):
                            up = blk.get("upLinkPort") or blk.get("port")
                            pnum = up.get("port") if isinstance(up, Mapping) else up
                            if pnum is not None and str(pnum).isdigit():
                                controller_ports.add(int(pnum))
                                break
        for succ in node.get("successors") or []:
            walk(succ)

    for root in roots:
        walk(root)
    return uplink_port, controller_ports


def _compact_switch_port(entry: Mapping[str, Any]) -> Dict[str, Any]:
    """Strip zero counters, empty strings/lists, and null cableTest stubs from a port dict."""
    out: Dict[str, Any] = {
        "port": entry["port"],
        "name": entry["name"],
        "linkUp": entry["linkUp"],
        "isUplink": entry["isUplink"],
        "isLagMember": entry["isLagMember"],
        "speed": entry["speed"],
        "speedMbps": entry["speedMbps"],
    }
    if entry.get("standardPort"):
        out["standardPort"] = entry["standardPort"]
    if entry.get("disabled"):
        out["disabled"] = True
    if entry.get("operation") and entry["operation"] != "switching":
        out["operation"] = entry["operation"]
    if entry.get("profileName"):
        out["profileName"] = entry["profileName"]
    if entry.get("profileOverrideEnable"):
        out["profileOverrideEnable"] = True
    if entry.get("nativeNetworkId"):
        out["nativeNetworkId"] = entry["nativeNetworkId"]
    if entry.get("tagNetworkIds"):
        out["tagNetworkIds"] = entry["tagNetworkIds"]
    if entry.get("untagNetworkIds"):
        out["untagNetworkIds"] = entry["untagNetworkIds"]
    if entry.get("linkUp") and entry.get("duplex") and entry["duplex"] != "unknown":
        out["duplex"] = entry["duplex"]
    if entry.get("maxSpeed") and entry.get("maxSpeed") != entry.get("speed"):
        out["maxSpeed"] = entry["maxSpeed"]
        out["maxSpeedMbps"] = entry["maxSpeedMbps"]
    if entry.get("stpDiscarding"):
        out["stpDiscarding"] = True
    if entry.get("lagId") is not None:
        out["lagId"] = entry["lagId"]
    if entry.get("carriesController"):
        out["carriesController"] = True
    if entry.get("poeDelivering") or entry.get("poePowerW"):
        out["poeDelivering"] = bool(entry.get("poeDelivering"))
        out["poePowerW"] = entry["poePowerW"]
        if entry.get("pdClass"):
            out["pdClass"] = entry["pdClass"]
    counters = entry.get("counters")
    if isinstance(counters, Mapping):
        nz = {ck: cv for ck, cv in counters.items() if cv}
        if nz:
            out["counters"] = nz
    if entry.get("cableTest") is not None:
        out["cableTest"] = entry["cableTest"]
    if entry.get("downlinkDevices"):
        out["downlinkDevices"] = entry["downlinkDevices"]
    return out


def collect_switch_ports_data(
    client: OmadaClient,
    site: SiteInfo,
    switch_dev: Mapping[str, Any],
    *,
    include_counters: bool = True,
    include_cable_test: bool = True,
    include_topology: bool = True,
    include_down_ports: bool = True,
    compact: bool = False,
) -> Dict[str, Any]:
    """Fetch and correlate live switch detail, ports, PoE, counters, cable test, LAGs, and uplinks."""
    warnings: List[str] = []
    mac_norm = normalize_mac(str(switch_dev.get("mac") or ""))
    mac_wire = omada_mac(mac_norm)

    detail_raw, ok_detail = try_api_result(
        client, f"sites/{site.site_id}/switches/{mac_wire}", warnings, label="switch detail",
    )
    sw = dict(detail_raw) if ok_detail and isinstance(detail_raw, Mapping) else dict(switch_dev)

    ports_raw, _, ok_ports = try_paginate(
        client, f"sites/{site.site_id}/switches/{mac_wire}/ports", warnings, label="switch ports",
    )
    if not ok_ports and isinstance(sw.get("ports"), list):
        ports_raw = [dict(p) for p in sw["ports"] if isinstance(p, Mapping)]

    counters_by_port: Dict[int, Dict[str, Any]] = {}
    if include_counters:
        c_rows, _, ok_cnt = try_paginate(
            client, f"sites/{site.site_id}/insight/switch/port/counters", warnings, label="port counters",
        )
        if ok_cnt:
            for row in c_rows:
                if normalize_mac(str(row.get("switchMac") or "")) == mac_norm or not row.get("switchMac"):
                    pno = as_int(row.get("port"), -1)
                    if pno >= 0:
                        counters_by_port[pno] = dict(row)

    poe_by_port: Dict[int, Dict[str, Any]] = {}
    dev_cap = sw.get("devCap") if isinstance(sw.get("devCap"), Mapping) else {}
    poe_supported = bool(sw.get("poeSupport") or dev_cap.get("poeSupport") or sw.get("poeTotalPower"))
    p_rows, _, ok_poe = try_paginate(
        client, f"sites/{site.site_id}/insight/switch/port/poe", warnings, label="port PoE",
    )
    if ok_poe:
        for row in p_rows:
            if normalize_mac(str(row.get("switchMac") or "")) == mac_norm or not row.get("switchMac"):
                pno = as_int(row.get("port"), -1)
                if pno >= 0:
                    poe_by_port[pno] = dict(row)
                    poe_supported = True

    cable_ports_by_port: Dict[int, Dict[str, Any]] = {}
    ct_ports_raw, ok_ct_ports = try_api_result(
        client, f"sites/{site.site_id}/cable-test/switches/{mac_wire}/ports",
        warnings, label="switch port downlinks",
    )
    if ok_ct_ports:
        for row in unwrap_rows(ct_ports_raw):
            pno = as_int(row.get("port"), -1)
            if pno >= 0:
                cable_ports_by_port[pno] = dict(row)

    cable_results_by_port: Dict[int, Dict[str, Any]] = {}
    cable_test_status: Optional[int] = None
    cable_test_supported = dev_cap.get("cableTestSupport")
    if include_cable_test and cable_test_supported is not False:
        ct_full, ok_ct_full = try_api_result(
            client, f"sites/{site.site_id}/cable-test/switches/{mac_wire}/full-results",
            warnings, label="cable test results",
        )
        if ok_ct_full and isinstance(ct_full, Mapping):
            cable_test_status = ct_full.get("status")
            for row in unwrap_rows(ct_full.get("data") or []):
                pno = as_int(row.get("port"), -1)
                if pno >= 0:
                    cable_results_by_port[pno] = redact_secrets(dict(row))

    lags_raw, ok_lags = try_api_result(
        client, f"sites/{site.site_id}/switches/{mac_wire}/lags", warnings, label="switch LAGs",
    )
    lag_groups = unwrap_rows(lags_raw) if ok_lags else []
    lag_port_map: Dict[int, Any] = {}
    for lg in lag_groups:
        lid = lg.get("lagId") or lg.get("id") or lg.get("name")
        for member in lg.get("ports") or lg.get("portList") or lg.get("memberPorts") or []:
            mp = member.get("port") if isinstance(member, Mapping) else member
            if mp is not None and str(mp).isdigit():
                lag_port_map[int(mp)] = lid

    insight_detail_raw, ok_id = try_api_result(
        client, f"sites/{site.site_id}/insight/switch/detail", warnings, label="switch insight detail",
    )
    insight_uplink_port: Optional[int] = None
    if ok_id:
        for item in unwrap_rows(insight_detail_raw):
            if normalize_mac(str(item.get("mac") or "")) == mac_norm:
                up_blk = item.get("uplink")
                if isinstance(up_blk, Mapping) and up_blk.get("port") is not None:
                    insight_uplink_port = as_int(up_blk.get("port"), -1)
                if not lag_groups and isinstance(item.get("lags"), list):
                    lag_groups = [dict(x) for x in item["lags"] if isinstance(x, Mapping)]

    topo_uplink_port: Optional[int] = None
    topo_controller_ports: Set[int] = set()
    if include_topology:
        topo_raw, ok_topo = try_api_result(
            client, f"sites/{site.site_id}/topology-v2", warnings, label="topology-v2",
        )
        if ok_topo and isinstance(topo_raw, Mapping):
            topo_uplink_port, topo_controller_ports = _topology_downlinks_for_switch(topo_raw, mac_norm)

    controller_host = _controller_host_from_config(client)
    stat_downlinks_by_port: Dict[int, Dict[str, Any]] = {}
    stat_raw, ok_stat = try_api_result(
        client, f"sites/{site.site_id}/stat/switches/{mac_wire}", warnings, label="switch port stats",
    )
    if ok_stat and isinstance(stat_raw, Mapping):
        for sp in stat_raw.get("ports") or []:
            if isinstance(sp, Mapping):
                pno = as_int(sp.get("port"), -1)
                if pno >= 0:
                    stat_downlinks_by_port[pno] = dict(sp)

    profiles_by_id: Dict[str, str] = {}
    prof_rows, _, ok_prof = try_paginate(
        client, f"sites/{site.site_id}/setting/lan/profiles", warnings, label="port profiles",
    )
    if ok_prof:
        for pr in prof_rows:
            pid = str(pr.get("id") or "")
            if pid:
                profiles_by_id[pid] = str(pr.get("name") or "")

    sw_uplink_port = sw.get("uplinkPort")
    if sw_uplink_port is None and isinstance(sw.get("uplink"), Mapping):
        sw_uplink_port = sw["uplink"].get("port")
    uplink_ports: Set[int] = set()
    for cand in (sw_uplink_port, insight_uplink_port, topo_uplink_port):
        if cand is not None and as_int(cand, -1) > 0:
            uplink_ports.add(int(cand))

    normalized_ports: List[Dict[str, Any]] = []
    sum_port_poe_w = 0.0
    for raw_p in sorted(ports_raw, key=lambda r: as_int(r.get("port"), 0)):
        pno = as_int(raw_p.get("port"), 0)
        pstatus = raw_p.get("portStatus") if isinstance(raw_p.get("portStatus"), Mapping) else {}
        stat_row = stat_downlinks_by_port.get(pno, {})
        stat_ps = stat_row.get("portStatus") if isinstance(stat_row.get("portStatus"), Mapping) else {}
        ps = pstatus or stat_ps
        ct_row = cable_ports_by_port.get(pno, {})
        poe_row = poe_by_port.get(pno, {})
        cnt_row = counters_by_port.get(pno, {})

        is_uplink = bool(ct_row.get("isUpperPort")) or (pno in uplink_ports)
        if is_uplink:
            uplink_ports.add(pno)

        agg_list = raw_p.get("allAggregatingPorts") or []
        op_str = str(raw_p.get("operation") or stat_row.get("operation") or "switching")
        lag_id = lag_port_map.get(pno) or raw_p.get("lagId")
        is_lag = (op_str.lower() == "aggregating") or bool(agg_list) or (lag_id is not None)

        downlinks: List[Dict[str, Any]] = []
        raw_dl = ct_row.get("downlinkDevices")
        if isinstance(raw_dl, list):
            for dl in raw_dl:
                if isinstance(dl, Mapping):
                    downlinks.append({
                        "name": str(dl.get("name") or ""),
                        "mac": normalize_mac(str(dl.get("mac") or "")),
                        "type": str(dl.get("type") or dl.get("deviceType") or ("client" if dl.get("isClient") else "")),
                        "model": str(dl.get("model") or ""),
                        "ip": str(dl.get("ip") or ""),
                    })
        elif isinstance(stat_row.get("downlink"), Mapping):
            dl = stat_row["downlink"]
            downlinks.append({
                "name": str(dl.get("name") or ""),
                "mac": normalize_mac(str(dl.get("mac") or "")),
                "type": str(dl.get("type") or dl.get("clientType") or ""),
                "model": str(dl.get("model") or ""),
                "ip": str(dl.get("ip") or ""),
            })

        carries_controller = pno in topo_controller_ports
        for dl in downlinks:
            dl_type = dl["type"].lower()
            dl_name = dl["name"].lower()
            if "controller" in dl_type or "omada controller" in dl_name:
                carries_controller = True
            if controller_host and dl["ip"].lower() == controller_host:
                carries_controller = True

        link_up = bool(ps.get("linkStatus") == 1)
        act_speed_code = ps.get("linkSpeed") if ps.get("linkSpeed") is not None else raw_p.get("speed")
        max_speed_code = raw_p.get("maxSpeed") if raw_p.get("maxSpeed") is not None else stat_row.get("maxSpeed")
        act_duplex_code = ps.get("duplex") if ps.get("duplex") is not None else raw_p.get("duplex")

        poe_power_w = as_float(
            poe_row.get("power") if poe_row.get("power") is not None else ps.get("poePower"),
            0.0,
        ) or 0.0
        sum_port_poe_w += poe_power_w
        poe_delivering = bool(ps.get("poe")) or bool(poe_row.get("poe")) or (poe_power_w > 0.0)
        port_poe_supported = bool(raw_p.get("supportPoe")) or ("poe" in raw_p and raw_p.get("poe") is not None)
        if port_poe_supported:
            poe_supported = True

        std_port_raw = raw_p.get("standardPort") or stat_row.get("oswStandPort")
        if isinstance(std_port_raw, Mapping):
            std_port_str = (
                f"{std_port_raw.get('unit', 1)}/{std_port_raw.get('slot', 0)}/{std_port_raw.get('port', pno)}"
            )
        else:
            std_port_str = str(std_port_raw or pno)

        profile_id = str(raw_p.get("profileId") or "")
        profile_name = str(raw_p.get("profileName") or profiles_by_id.get(profile_id, ""))

        counters_obj: Optional[Dict[str, Any]] = None
        if cnt_row or ps:
            counters_obj = {
                "txBytes": as_int(cnt_row.get("txBytes") if cnt_row else ps.get("tx"), 0),
                "rxBytes": as_int(cnt_row.get("rxBytes") if cnt_row else ps.get("rx"), 0),
                "txFrames": as_int(cnt_row.get("txFrames"), 0),
                "rxFrames": as_int(cnt_row.get("rxFrames"), 0),
                "txErrors": as_int(cnt_row.get("txErrors"), 0),
                "rxErrors": as_int(cnt_row.get("rxErrors"), 0),
                "txDrops": as_int(cnt_row.get("txDropPkts", cnt_row.get("txDrops")), 0),
                "rxDrops": as_int(cnt_row.get("rxDropPkts", cnt_row.get("rxDrops")), 0),
                "txMulticast": as_int(cnt_row.get("txMulticast"), 0),
                "rxMulticast": as_int(cnt_row.get("rxMulticast"), 0),
                "txBroadcast": as_int(cnt_row.get("txBroadcast"), 0),
                "rxBroadcast": as_int(cnt_row.get("rxBroadcast"), 0),
            }

        normalized_ports.append({
            "port": pno,
            "standardPort": std_port_str,
            "name": str(raw_p.get("name") or f"Port{pno}"),
            "disabled": bool(raw_p.get("disable", False)) or profile_name.lower() == "disable",
            "operation": op_str,
            "profileId": profile_id,
            "profileName": profile_name,
            "profileOverrideEnable": bool(raw_p.get("profileOverrideEnable", False)),
            "nativeNetworkId": str(raw_p.get("nativeNetworkId") or ""),
            "tagNetworkIds": [str(x) for x in (raw_p.get("tagNetworkIds") or [])],
            "untagNetworkIds": [str(x) for x in (raw_p.get("untagNetworkIds") or [])],
            "linkUp": link_up,
            "speed": _speed_label(act_speed_code) if link_up else "down",
            "speedMbps": _speed_mbps(act_speed_code) if link_up else 0,
            "maxSpeed": _speed_label(max_speed_code),
            "maxSpeedMbps": _speed_mbps(max_speed_code),
            "duplex": _duplex_label(act_duplex_code),
            "stpDiscarding": bool(ps.get("stpDiscarding", False)),
            "isUplink": is_uplink,
            "isLagMember": is_lag,
            "lagId": lag_id,
            "carriesController": carries_controller,
            "poeSupported": port_poe_supported,
            "poeMode": raw_p.get("poe"),
            "poeDelivering": poe_delivering,
            "poePowerW": round(poe_power_w, 2),
            "poeVoltageV": as_float(poe_row.get("voltage")),
            "poeCurrentMa": as_float(poe_row.get("current")),
            "pdClass": str(poe_row.get("pdClass") or ""),
            "counters": counters_obj,
            "cableTest": cable_results_by_port.get(pno),
            "downlinkDevices": downlinks,
        })

    total_budget = as_float(sw.get("poeTotalPower"))
    remain_w = as_float(sw.get("poeRemain"))
    remain_pct = as_float(sw.get("poeRemainPercent"))
    used_w: Optional[float] = None
    used_pct: Optional[float] = None
    if total_budget is not None and total_budget > 0:
        if remain_w is not None:
            used_w = round(max(0.0, total_budget - remain_w), 2)
            used_pct = round(
                max(0.0, 100.0 - remain_pct) if remain_pct is not None else (used_w / total_budget) * 100.0,
                2,
            )
        else:
            used_w = round(sum_port_poe_w, 2)
            remain_w = round(max(0.0, total_budget - used_w), 2)
            used_pct = round((used_w / total_budget) * 100.0, 2)
    elif poe_supported:
        used_w = round(sum_port_poe_w, 2)

    out_ports = normalized_ports
    if not include_down_ports:
        out_ports = [p for p in out_ports if p.get("linkUp")]
    if compact:
        out_ports = [_compact_switch_port(p) for p in out_ports]

    return {
        "mac": mac_norm,
        "name": str(sw.get("name") or mac_norm),
        "model": str(sw.get("showModel") or sw.get("model") or ""),
        "online": is_device_online(sw),
        "poe": {
            "supported": poe_supported,
            "totalBudgetW": total_budget,
            "remainingW": remain_w,
            "usedW": used_w,
            "usedPercent": used_pct,
        },
        "uplinkPorts": sorted(uplink_ports),
        "lagGroups": lag_groups,
        "cableTestSupported": None if cable_test_supported is None else bool(cable_test_supported),
        "cableTestStatus": cable_test_status,
        "ports": out_ports,
        "warnings": warnings,
    }


def _retry_rate_pct(retries: int, pkts: int) -> Optional[float]:
    if pkts <= 0:
        return 0.0 if retries == 0 else None
    return round((retries / float(pkts)) * 100.0, 2)


def _extract_ap_band_map(ap: Mapping[str, Any]) -> Dict[str, Tuple[str, str, str]]:
    """Map canonical band names to (radioSettingKey, wpKey, radioTrafficKey)."""
    misc = ap.get("deviceMisc") if isinstance(ap.get("deviceMisc"), Mapping) else {}
    has_5g1 = bool(misc.get("support5g") and misc.get("support5g2")) or ("radioSetting5g1" in ap)
    candidates: Dict[str, Tuple[str, str, str]] = {}
    if misc.get("support2g", True) or "radioSetting2g" in ap or "wp2g" in ap:
        candidates["2g"] = ("radioSetting2g", "wp2g", "radioTraffic2g")
    if misc.get("support5g", True) or "radioSetting5g" in ap or "radioSetting5g1" in ap or "wp5g" in ap:
        rs_key = "radioSetting5g1" if (has_5g1 and "radioSetting5g1" in ap) else "radioSetting5g"
        wp_key = "wp5g1" if (has_5g1 and "wp5g1" in ap) else "wp5g"
        candidates["5g"] = (rs_key, wp_key, "radioTraffic5g1" if rs_key.endswith("5g1") else "radioTraffic5g")
    if misc.get("support5g2") or "radioSetting5g2" in ap or "wp5g2" in ap:
        candidates["5g2"] = ("radioSetting5g2", "wp5g2", "radioTraffic5g2")
    if misc.get("support6g") or "radioSetting6g" in ap or "wp6g" in ap:
        candidates["6g"] = ("radioSetting6g", "wp6g", "radioTraffic6g")
    return candidates


def _channel_info_by_band(channel_info_raw: Any) -> Dict[str, List[Dict[str, Any]]]:
    rows = unwrap_rows(channel_info_raw)
    out: Dict[str, List[Dict[str, Any]]] = {}
    for entry in rows:
        band_raw = str(entry.get("band") or "").strip().lower()
        rid = entry.get("radioId")
        if "2.4" in band_raw or band_raw == "2g" or (not band_raw and rid == 0):
            band = "2g"
        elif "5g2" in band_raw or "5g-2" in band_raw or (not band_raw and rid == 2):
            band = "5g2"
        elif "5g" in band_raw or (not band_raw and rid == 1):
            band = "5g"
        elif "6g" in band_raw or (not band_raw and rid == 3):
            band = "6g"
        else:
            band = band_raw or f"radio{rid}"
        clist = entry.get("channelList")
        if isinstance(clist, list):
            out[band] = [dict(c) for c in clist if isinstance(c, Mapping)]
    return out


def collect_ap_radios_data(
    client: OmadaClient,
    site: SiteInfo,
    ap_dev: Mapping[str, Any],
    *,
    include_rf_scan: bool = True,
    include_available_channels: bool = True,
) -> Dict[str, Any]:
    """Fetch and normalize AP radio settings, RF utilization/retries, available channels, and RF scan."""
    warnings: List[str] = []
    mac_norm = normalize_mac(str(ap_dev.get("mac") or ""))
    mac_wire = omada_mac(mac_norm)

    detail_raw, ok_detail = try_api_result(
        client, f"sites/{site.site_id}/eaps/{mac_wire}", warnings, label="AP detail",
    )
    ap = dict(detail_raw) if ok_detail and isinstance(detail_raw, Mapping) else dict(ap_dev)

    chan_by_band: Dict[str, List[Dict[str, Any]]] = {}
    if include_available_channels:
        cinfo_raw, ok_ci = try_api_result(
            client, f"sites/{site.site_id}/eaps/{mac_wire}/channelInfo", warnings, label="AP channelInfo",
        )
        if ok_ci:
            chan_by_band = _channel_info_by_band(cinfo_raw)

    rf_scan_obj: Optional[Dict[str, Any]] = None
    if include_rf_scan:
        rf_raw, ok_rf = try_api_result(
            client, f"sites/{site.site_id}/eaps/{mac_wire}/tools/rfScan", warnings, label="AP RF scan",
        )
        if ok_rf and isinstance(rf_raw, Mapping):
            rf_scan_obj = deep_redact(dict(rf_raw))

    band_map = _extract_ap_band_map(ap)
    radios: List[Dict[str, Any]] = []
    for band, (rs_key, wp_key, rt_key) in band_map.items():
        rs = ap.get(rs_key) if isinstance(ap.get(rs_key), Mapping) else {}
        wp = ap.get(wp_key) if isinstance(ap.get(wp_key), Mapping) else {}
        rt = ap.get(rt_key) if isinstance(ap.get(rt_key), Mapping) else {}
        if not rs and not wp and not rt and band not in chan_by_band:
            continue

        avail_entries: List[Dict[str, Any]] = []
        raw_chan_val = str(rs.get("channel") if rs.get("channel") is not None else "")
        resolved_chan: Any = raw_chan_val
        for ch_item in chan_by_band.get(band, []):
            item_val = str(ch_item.get("value") if ch_item.get("value") is not None else "")
            chan_num = ch_item.get("channelValue") if ch_item.get("channelValue") is not None else ch_item.get("value")
            if raw_chan_val and item_val == raw_chan_val and chan_num is not None:
                resolved_chan = chan_num
            avail_entries.append({
                "value": item_val,
                "channel": chan_num,
                "freq": ch_item.get("freq"),
                "maxPower": ch_item.get("maxPow"),
                "dfs": bool(ch_item.get("dfs")),
                "widths": width_flag_to_widths(ch_item.get("widthFlag")),
            })

        actual_str = str(wp.get("actualChannel") or "")
        if (not resolved_chan or str(resolved_chan) == raw_chan_val) and "/" in actual_str:
            head = actual_str.split("/", 1)[0].strip()
            if head.isdigit():
                resolved_chan = int(head)
        if raw_chan_val in ("0", "auto"):
            resolved_chan = resolved_chan if isinstance(resolved_chan, int) and resolved_chan > 0 else "auto"

        w_code = str(rs.get("channelWidth") or "")
        tx_pkts = as_int(rt.get("txPkts"), 0)
        rx_pkts = as_int(rt.get("rxPkts"), 0)
        tx_retries = as_int(rt.get("txRetryPkts"), 0)
        rx_retries = as_int(rt.get("rxRetryPkts"), 0)
        pow_level = rs.get("txPowerLevel")

        radios.append({
            "band": band,
            "settingKey": rs_key,
            "enabled": bool(rs.get("radioEnable", True)),
            "channel": resolved_chan,
            "channelWireValue": raw_chan_val,
            "actualChannel": actual_str or None,
            "freq": rs.get("freq"),
            "channelWidth": str(wp.get("bandWidth") or CHANNEL_WIDTH_LABELS.get(w_code, w_code)),
            "channelWidthCode": w_code,
            "txPower": rs.get("txPower") if rs.get("txPower") is not None else wp.get("txPower"),
            "txPowerLevel": pow_level,
            "txPowerMode": TX_POWER_LEVEL_LABELS.get(as_int(pow_level, -1), ""),
            "txUtilPct": as_float(wp.get("txUtil")),
            "rxUtilPct": as_float(wp.get("rxUtil")),
            "interferencePct": as_float(wp.get("interUtil")),
            "noiseFloorDbm": as_float(wp.get("noiseFloor")),
            "maxTxRateMbps": as_float(wp.get("maxTxRate")),
            "radioMode": str(wp.get("rdMode") or ""),
            "txPkts": tx_pkts,
            "rxPkts": rx_pkts,
            "txRetryPkts": tx_retries,
            "rxRetryPkts": rx_retries,
            "txRetryRatePct": _retry_rate_pct(tx_retries, tx_pkts),
            "rxRetryRatePct": _retry_rate_pct(rx_retries, rx_pkts),
            "txDropPkts": as_int(rt.get("txDropPkts"), 0),
            "rxDropPkts": as_int(rt.get("rxDropPkts"), 0),
            "txErrPkts": as_int(rt.get("txErrPkts"), 0),
            "rxErrPkts": as_int(rt.get("rxErrPkts"), 0),
            "availableChannels": avail_entries,
        })

    return {
        "mac": mac_norm,
        "name": str(ap.get("name") or mac_norm),
        "model": str(ap.get("showModel") or ap.get("model") or ""),
        "online": is_device_online(ap),
        "wlanGroupId": str(ap.get("wlanId") or ""),
        "supportRfScan": bool(ap.get("supportRFScan", True)),
        "radios": radios,
        "rfScan": rf_scan_obj,
        "warnings": warnings,
    }


def collect_rf_scan_data(
    client: OmadaClient,
    site: SiteInfo,
    ap_dev: Mapping[str, Any],
) -> Dict[str, Any]:
    """Collect latest RF scan status/results paired with current AP interference telemetry."""
    radio_data = collect_ap_radios_data(
        client, site, ap_dev, include_rf_scan=True, include_available_channels=True,
    )
    rf = radio_data.get("rfScan") or {}
    channels: List[Dict[str, Any]] = []
    for key in ("channels", "channelList", "data", "scanResult", "list"):
        rows = rf.get(key)
        if isinstance(rows, list):
            channels = [deep_redact(dict(r)) for r in rows if isinstance(r, Mapping)]
            break
    band_statuses = {
        k: rf.get(f"status{k}")
        for k in ("2g", "5g", "5g2", "6g")
        if f"status{k}" in rf
    }
    return {
        "mac": radio_data["mac"],
        "name": radio_data["name"],
        "model": radio_data["model"],
        "supportRfScan": radio_data["supportRfScan"],
        "scanTime": rf.get("time"),
        "status": rf.get("status"),
        "bandStatuses": band_statuses,
        "radioUtilization": [
            {
                "band": r["band"],
                "channel": r["channel"],
                "channelWidth": r["channelWidth"],
                "txUtilPct": r["txUtilPct"],
                "rxUtilPct": r["rxUtilPct"],
                "interferencePct": r["interferencePct"],
                "noiseFloorDbm": r["noiseFloorDbm"],
            }
            for r in radio_data["radios"]
        ],
        "channels": channels,
        "warnings": radio_data["warnings"],
    }


def collect_wan_status_data(
    client: OmadaClient,
    site: SiteInfo,
    *,
    devices: Optional[Sequence[Mapping[str, Any]]] = None,
    include_speedtest: bool = True,
    mask_wan_ip: bool = False,
) -> Dict[str, Any]:
    """Gather gateway WAN link status, DNS/gateway IPs, latency/loss, failover, and speedtest."""
    warnings: List[str] = []
    devs = list(devices) if devices is not None else unwrap_rows(
        try_api_result(client, f"sites/{site.site_id}/devices", warnings, label="devices")[0]
    )
    gateways = [d for d in devs if str(d.get("type") or "").lower() == "gateway"]

    wan_cfg_raw, ok_wcfg = try_api_result(
        client, f"sites/{site.site_id}/setting/wan/networks", warnings, label="WAN settings",
    )
    wan_ls_raw, ok_wls = try_api_result(
        client, f"sites/{site.site_id}/setting/wanlanstatus", warnings, label="WAN/LAN status",
    )
    port_state_raw, ok_ps = try_api_result(
        client, f"sites/{site.site_id}/dashboard/portstatedetails", warnings, label="WAN port state details",
    )

    gw_detail: Dict[str, Any] = {}
    gw_mac_norm = ""
    gw_name = ""
    gw_model = ""
    if gateways:
        gw = gateways[0]
        gw_mac_norm = normalize_mac(str(gw.get("mac") or ""))
        gw_name = str(gw.get("name") or gw_mac_norm)
        gw_model = str(gw.get("showModel") or gw.get("model") or "")
        gd, ok_gd = try_api_result(
            client, f"sites/{site.site_id}/gateways/{omada_mac(gw_mac_norm)}", warnings, label="gateway detail",
        )
        if ok_gd and isinstance(gd, Mapping):
            gw_detail = dict(gd)
    else:
        warnings.append("No adopted gateway present on site; live WAN telemetry unavailable.")

    speedtest_obj: Optional[Dict[str, Any]] = None
    if include_speedtest and gateways:
        st_raw, ok_st = try_api_result(
            client, f"sites/{site.site_id}/cmd/getSpeedTestResult", warnings, label="speedtest result",
        )
        if ok_st and isinstance(st_raw, Mapping):
            speedtest_obj = deep_redact(dict(st_raw))

    port_infos_by_name: Dict[str, Dict[str, Any]] = {}
    port_infos_by_port: Dict[int, Dict[str, Any]] = {}
    if ok_ps and isinstance(port_state_raw, Mapping):
        for pi in port_state_raw.get("portInfos") or []:
            if isinstance(pi, Mapping):
                if pi.get("port") is not None:
                    port_infos_by_port[as_int(pi.get("port"), -1)] = dict(pi)
                if pi.get("portName"):
                    port_infos_by_name[str(pi["portName"])] = dict(pi)

    wan_list_by_name: Dict[str, Dict[str, Any]] = {}
    if ok_wls and isinstance(wan_ls_raw, Mapping):
        for wl in wan_ls_raw.get("wanList") or []:
            if isinstance(wl, Mapping) and wl.get("portName"):
                wan_list_by_name[str(wl["portName"])] = dict(wl)

    osg_settings_by_name: Dict[str, Dict[str, Any]] = {}
    wan_cfg = deep_redact(dict(wan_cfg_raw)) if ok_wcfg and isinstance(wan_cfg_raw, Mapping) else {}
    osg_info = wan_cfg.get("osgPortInfo") if isinstance(wan_cfg.get("osgPortInfo"), Mapping) else {}
    for wp in osg_info.get("wanLanPortSettings") or []:
        if isinstance(wp, Mapping) and wp.get("portName") and wp.get("mode") in (0, -1):
            osg_settings_by_name[str(wp["portName"])] = dict(wp)

    wan_ports: List[Dict[str, Any]] = []
    seen_ports: Set[int] = set()
    for pc in gw_detail.get("portConfigs") or []:
        if not isinstance(pc, Mapping):
            continue
        ps = pc.get("portStat") if isinstance(pc.get("portStat"), Mapping) else {}
        pno = as_int(ps.get("port") if ps.get("port") is not None else pc.get("port"), 0)
        pname = str(ps.get("name") or "")
        is_wan = (ps.get("mode") == 0) or (pname in wan_list_by_name) or (pno in port_infos_by_port)
        if not is_wan:
            continue
        seen_ports.add(pno)
        pi = port_infos_by_port.get(pno) or port_infos_by_name.get(pname) or {}
        ipv4_cfg = ps.get("wanPortIpv4Config") if isinstance(ps.get("wanPortIpv4Config"), Mapping) else {}
        ipv6_cfg = ps.get("wanPortIpv6Config") if isinstance(ps.get("wanPortIpv6Config"), Mapping) else {}

        raw_ip = str(ipv4_cfg.get("ip") or ps.get("ip") or pi.get("ip") or "")
        raw_gw = str(ipv4_cfg.get("gateway") or "")
        pri_dns = str(ipv4_cfg.get("priDns") or "")
        snd_dns = str(ipv4_cfg.get("sndDns") or "")
        if mask_wan_ip:
            raw_ip = mask_ipv4_middle(raw_ip)
            raw_gw = mask_ipv4_middle(raw_gw)

        link_up = bool(ps.get("status") == 1)
        inet_up = bool(ps.get("internetState") == 1)
        wan_ports.append({
            "port": pno,
            "name": pname or f"WAN{pno}",
            "enabled": bool(pc.get("status", 1)),
            "linkUp": link_up,
            "internetUp": inet_up,
            "onlineDetection": bool(ps.get("onlineDetection") == 1),
            "proto": str(ps.get("proto") or ""),
            "ip": raw_ip,
            "netmask": str(ipv4_cfg.get("netmask") or ""),
            "gateway": raw_gw,
            "primaryDns": pri_dns if pri_dns not in ("0.0.0.0", "") else "",
            "secondaryDns": snd_dns if snd_dns not in ("0.0.0.0", "") else "",
            "ipv6Enabled": bool(ipv6_cfg.get("enable")),
            "ipv6Address": mask_ipv4_middle(str(ipv6_cfg.get("addr") or "")) if mask_wan_ip else str(ipv6_cfg.get("addr") or ""),
            "speed": _speed_label(ps.get("speed")) if link_up else "down",
            "duplex": _duplex_label(ps.get("duplex")),
            "maxBandwidthMbps": as_int(pi.get("maxBandwidth"), 0) or None,
            "rxRateBps": as_int(ps.get("rxRate") if ps.get("rxRate") is not None else pi.get("rxRate"), 0),
            "txRateBps": as_int(ps.get("txRate") if ps.get("txRate") is not None else pi.get("txRate"), 0),
            "rxBytes": as_int(ps.get("rx"), 0),
            "txBytes": as_int(ps.get("tx"), 0),
            "latencyMs": as_float(ps.get("latency")),
            "lossPct": as_float(ps.get("loss")),
            "healthLevel": ps.get("healthLevel"),
            "rxErrorPkts": as_int(ps.get("rxErrorPkts"), 0),
            "txErrorPkts": as_int(ps.get("txErrorPkts"), 0),
        })

    if not wan_ports and port_infos_by_port:
        for pno, pi in sorted(port_infos_by_port.items()):
            ip_val = str(pi.get("ip") or "")
            wan_ports.append({
                "port": pno,
                "name": str(pi.get("portName") or f"WAN{pno}"),
                "enabled": True,
                "linkUp": ip_val not in ("", "0.0.0.0"),
                "internetUp": ip_val not in ("", "0.0.0.0"),
                "onlineDetection": False,
                "proto": "",
                "ip": mask_ipv4_middle(ip_val) if mask_wan_ip else ip_val,
                "netmask": "",
                "gateway": "",
                "primaryDns": "",
                "secondaryDns": "",
                "ipv6Enabled": False,
                "ipv6Address": "",
                "speed": "unknown",
                "duplex": "unknown",
                "maxBandwidthMbps": as_int(pi.get("maxBandwidth"), 0) or None,
                "rxRateBps": as_int(pi.get("rxRate"), 0),
                "txRateBps": as_int(pi.get("txRate"), 0),
                "rxBytes": 0,
                "txBytes": 0,
                "latencyMs": None,
                "lossPct": None,
                "healthLevel": None,
                "rxErrorPkts": 0,
                "txErrorPkts": 0,
            })

    up_count = sum(1 for p in wan_ports if p["linkUp"])
    inet_count = sum(1 for p in wan_ports if p["internetUp"])
    lb_cfg = wan_cfg.get("loadBalance") if isinstance(wan_cfg.get("loadBalance"), Mapping) else {}
    lb_enabled = bool(lb_cfg.get("enable")) if lb_cfg else (inet_count > 1)
    failover_cfg = bool(
        wan_cfg.get("linkBackup")
        or wan_cfg.get("failover")
        or (len(wan_ports) > 1 and not lb_enabled)
    )
    wan_mode = (
        "load_balance" if lb_enabled
        else ("failover" if len(wan_ports) > 1 else ("single_wan" if len(wan_ports) == 1 else "none"))
    )

    return {
        "hasGateway": bool(gateways) or bool(wan_ls_raw and wan_ls_raw.get("hasGateway")),
        "gatewayMac": gw_mac_norm,
        "gatewayName": gw_name,
        "gatewayModel": gw_model,
        "wanMode": wan_mode,
        "loadBalanceEnabled": lb_enabled,
        "failoverConfigured": failover_cfg,
        "totalWanPorts": len(wan_ports),
        "linkUpCount": up_count,
        "internetUpCount": inet_count,
        "ports": wan_ports,
        "speedTest": speedtest_obj,
        "warnings": warnings,
    }


def collect_vpn_tunnels_data(client: OmadaClient, site: SiteInfo) -> Dict[str, Any]:
    """Collect VPN tunnel/peer state and secret-redacted VPN definitions."""
    warnings: List[str] = []
    tunnels: List[Dict[str, Any]] = []
    configured: List[Dict[str, Any]] = []

    stat_endpoints = (
        ("tunnel", f"sites/{site.site_id}/setting/vpn/stats/tunnel?filters.vpnType=0"),
        ("ipsec", f"sites/{site.site_id}/setting/vpn/stats/ipsec"),
        ("sslvpn", f"sites/{site.site_id}/setting/vpn/stats/sslvpn"),
    )
    for vtype, ep in stat_endpoints:
        rows, _, ok = try_paginate(client, ep, warnings, label=f"VPN {vtype} stats")
        if ok:
            for row in rows:
                cleaned = deep_redact(row)
                cleaned.setdefault("vpnCategory", vtype)
                tunnels.append(cleaned)

    dash_endpoints = (
        ("wireguard", f"sites/{site.site_id}/dashboard/wireguardtunnels"),
        ("ipsec", f"sites/{site.site_id}/dashboard/ipsectunnels"),
        ("sslvpn", f"sites/{site.site_id}/dashboard/sslvpntunnels"),
        ("openvpn_server", f"sites/{site.site_id}/dashboard/openvpntunnels?type=0"),
        ("openvpn_client", f"sites/{site.site_id}/dashboard/openvpntunnels?type=1"),
    )
    for vtype, ep in dash_endpoints:
        res, ok = try_api_result(client, ep, warnings, label=f"VPN dashboard {vtype}")
        if ok:
            for row in unwrap_rows(res):
                cleaned = deep_redact(row)
                cleaned.setdefault("vpnCategory", vtype)
                tunnels.append(cleaned)

    for vtype, ep in (
        ("vpn", f"sites/{site.site_id}/setting/vpns"),
        ("wireguard", f"sites/{site.site_id}/setting/wireguard"),
        ("wireguard_peer", f"sites/{site.site_id}/setting/wireguard/peer"),
    ):
        rows, _, ok = try_paginate(client, ep, warnings, label=f"VPN settings {vtype}")
        if ok:
            for row in rows:
                cleaned = deep_redact(row)
                cleaned.setdefault("vpnCategory", vtype)
                configured.append(cleaned)

    up_count = sum(
        1 for t in tunnels
        if t.get("status") in (1, True, "up", "connected", "UP")
        or str(t.get("state") or "").lower() in ("up", "connected", "active")
    )
    return {
        "tunnels": tunnels,
        "configuredVpns": configured,
        "counts": {
            "activeOrStatTunnels": len(tunnels),
            "upTunnels": up_count,
            "configuredEntries": len(configured),
        },
        "warnings": warnings,
    }


def _extract_node_uplink(node: Mapping[str, Any]) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    for key in ("wireUpLink", "wiredUpInfo", "switchUpLink", "upperPort"):
        blk = node.get(key)
        if isinstance(blk, Mapping):
            up = blk.get("upLinkPort") or blk.get("port")
            pnum = up.get("port") if isinstance(up, Mapping) else up
            port_val = int(pnum) if pnum is not None and str(pnum).isdigit() else None
            spd = _speed_label(blk.get("linkSpeed")) if blk.get("linkSpeed") is not None else None
            dpx = _duplex_label(blk.get("duplex")) if blk.get("duplex") is not None else None
            return port_val, spd, dpx
    return None, None, None


def collect_topology_data(
    client: OmadaClient,
    site: SiteInfo,
    *,
    devices: Optional[Sequence[Mapping[str, Any]]] = None,
    include_clients: bool = False,
) -> Dict[str, Any]:
    """Build a compact uplink topology tree with fallback from topology-v2 to topology."""
    warnings: List[str] = []
    topo_raw, ok = try_api_result(client, f"sites/{site.site_id}/topology-v2", warnings, label="topology-v2")
    if not ok or not isinstance(topo_raw, Mapping):
        topo_raw, ok = try_api_result(client, f"sites/{site.site_id}/topology", warnings, label="topology")
    topo = topo_raw if isinstance(topo_raw, Mapping) else {}
    roots_raw = topo.get("topologyArray")
    if not isinstance(roots_raw, list):
        roots_raw = unwrap_rows(topo)

    devs = list(devices) if devices is not None else unwrap_rows(
        try_api_result(client, f"sites/{site.site_id}/devices", warnings, label="devices")[0]
    )
    dev_by_mac = {normalize_mac(str(d.get("mac") or "")): d for d in devs if d.get("mac")}
    seen_macs: Set[str] = set()
    counts: Dict[str, int] = {"gateway": 0, "switch": 0, "ap": 0, "other": 0}
    max_depth = 0

    def build_node(node: Mapping[str, Any], depth: int) -> Optional[Dict[str, Any]]:
        nonlocal max_depth
        ntype = str(node.get("type") or node.get("clientType") or "unknown").lower()
        is_client = bool(node.get("isClient")) or ntype == "client"
        if is_client and not include_clients:
            return None
        max_depth = max(max_depth, depth)
        mac_norm = normalize_mac(str(node.get("mac") or ""))
        if mac_norm:
            seen_macs.add(mac_norm)
        if ntype in ("gateway", "switch", "ap"):
            counts[ntype] += 1
        elif not is_client:
            counts["other"] += 1

        up_port, up_speed, up_duplex = _extract_node_uplink(node)
        children: List[Dict[str, Any]] = []
        for succ in node.get("successors") or []:
            if isinstance(succ, Mapping):
                child = build_node(succ, depth + 1)
                if child is not None:
                    children.append(child)

        return {
            "type": ntype,
            "mac": mac_norm,
            "name": str(node.get("name") or mac_norm),
            "model": str(node.get("showModel") or node.get("model") or ""),
            "ip": str(node.get("ip") or ""),
            "online": not bool(node.get("disconnected")) and (
                is_device_online(node) if "status" in node or "statusCategory" in node else True
            ),
            "uplinkPort": up_port,
            "uplinkSpeed": up_speed,
            "uplinkDuplex": up_duplex,
            "clientCount": as_int(node.get("clientCount"), 0),
            "children": children,
        }

    tree: List[Dict[str, Any]] = []
    for r in roots_raw:
        if isinstance(r, Mapping):
            built = build_node(r, 1)
            if built is not None:
                tree.append(built)

    unattached = [
        {
            "type": str(d.get("type") or "").lower(),
            "mac": mac_norm,
            "name": str(d.get("name") or mac_norm),
            "model": str(d.get("showModel") or d.get("model") or ""),
            "ip": str(d.get("ip") or ""),
            "online": is_device_online(d),
        }
        for mac_norm, d in dev_by_mac.items()
        if mac_norm not in seen_macs
    ]

    return {
        "roots": tree,
        "unattachedDevices": unattached,
        "counts": {
            "gateways": counts["gateway"],
            "switches": counts["switch"],
            "aps": counts["ap"],
            "otherNodes": counts["other"],
            "totalManagedDevices": len(devs),
            "maxDepth": max_depth,
        },
        "warnings": warnings,
    }


def collect_security_status_data(
    client: OmadaClient,
    site: SiteInfo,
    *,
    limit: int = 20,
) -> Dict[str, Any]:
    """Gather IPS/IDS, attack defense, WIDS/WIPS, threat events, and rogue AP state."""
    warnings: List[str] = []
    cap = max(1, min(200, int(limit or 20)))

    ips_raw, ok_ips = try_api_result(client, f"sites/{site.site_id}/setting/ips", warnings, label="IPS settings")
    ips_obj: Optional[Dict[str, Any]] = None
    if ok_ips and isinstance(ips_raw, Mapping):
        ips_obj = {
            "enabled": bool(ips_raw.get("enable", False)),
            "lowCategories": ips_raw.get("lowCategories"),
            "mediumCategories": ips_raw.get("mediumCategories"),
            "highCategories": ips_raw.get("highCategories"),
            "allCategories": ips_raw.get("allCategories"),
        }

    threats_raw, _, ok_threats = try_paginate(
        client, f"sites/{site.site_id}/ips/threat-management?archived=false",
        warnings, label="IPS threat events", page_size=min(100, cap), max_pages=1,
    )
    threat_alerts = [deep_redact(t) for t in threats_raw[:cap]] if ok_threats else []

    ad_raw, ok_ad = try_api_result(
        client, f"sites/{site.site_id}/setting/firewall/attackdefense",
        warnings, label="attack defense",
    )
    attack_defense = deep_redact(dict(ad_raw)) if ok_ad and isinstance(ad_raw, Mapping) else None

    wids_events, _, ok_wids = try_paginate(
        client, f"sites/{site.site_id}/insight/wids",
        warnings, label="WIDS events", page_size=min(100, cap), max_pages=1,
    )
    wids_bl, _, ok_bl = try_paginate(
        client, f"sites/{site.site_id}/insight/wids/blacklist",
        warnings, label="WIDS blacklist", page_size=min(100, cap), max_pages=1,
    )
    wids_obj: Optional[Dict[str, Any]] = None
    if ok_wids or ok_bl:
        wids_obj = {
            "events": [deep_redact(e) for e in wids_events[:cap]],
            "blacklist": [deep_redact(b) for b in wids_bl[:cap]],
        }

    rogues_raw, _, ok_rogue = try_paginate(
        client, f"sites/{site.site_id}/insight/rogueaps",
        warnings, label="rogue APs", page_size=min(100, cap), max_pages=1,
    )
    rogue_aps = [deep_redact(r) for r in rogues_raw[:cap]] if ok_rogue else []

    return {
        "ips": ips_obj,
        "attackDefense": attack_defense,
        "wids": wids_obj,
        "threatAlerts": threat_alerts,
        "rogueAps": rogue_aps,
        "counts": {
            "threatAlerts": len(threat_alerts),
            "rogueAps": len(rogue_aps),
            "widsEvents": len(wids_obj["events"]) if wids_obj else 0,
            "widsBlacklist": len(wids_obj["blacklist"]) if wids_obj else 0,
        },
        "warnings": warnings,
    }


def validate_ap_radio_change(
    client: OmadaClient,
    site: SiteInfo,
    ap_detail: Mapping[str, Any],
    band: str,
    *,
    channel: Optional[Any] = None,
    channel_width: Optional[Any] = None,
    tx_power_level: Optional[Any] = None,
    tx_power: Optional[int] = None,
) -> Tuple[str, str, Dict[str, Any], List[str]]:
    """Validate AP band, channel, channel width, and TX power against channelInfo & widthFlag.

    Returns ``(setting_key, target_wire_channel, validated_fields_summary, warnings)``.
    """
    band_norm = str(band or "").strip().lower()
    if band_norm in ("2.4g", "2.4", "2g"):
        band_norm = "2g"
    elif band_norm in ("5g", "5g1"):
        band_norm = "5g"
    elif band_norm in ("5g2", "5g-2"):
        band_norm = "5g2"
    elif band_norm in ("6g",):
        band_norm = "6g"

    band_map = _extract_ap_band_map(ap_detail)
    if band_norm not in band_map:
        raise OmadaError(
            f"AP does not support band {band!r}",
            hint=f"supported bands for this AP: {', '.join(sorted(band_map.keys())) or 'none'}",
        )
    rs_key, _, _ = band_map[band_norm]
    warnings: List[str] = []
    mac_wire = omada_mac(str(ap_detail.get("mac") or ""))
    cinfo_raw, ok_ci = try_api_result(
        client, f"sites/{site.site_id}/eaps/{mac_wire}/channelInfo", warnings, label="AP channelInfo",
    )
    chan_list = _channel_info_by_band(cinfo_raw).get(band_norm, []) if ok_ci else []

    current_rs = ap_detail.get(rs_key) if isinstance(ap_detail.get(rs_key), Mapping) else {}
    target_wire_channel = str(current_rs.get("channel") or "0")
    matched_chan_entry: Optional[Dict[str, Any]] = None

    def _find_chan_entry(
        ch_input: Any,
        *,
        prefer_wire: bool = False,
    ) -> Optional[Dict[str, Any]]:
        s = str(ch_input).strip()
        keys = ("value", "channelValue", "freq") if prefer_wire else ("channelValue", "value", "freq")
        for key in keys:
            for entry in chan_list:
                val = entry.get(key)
                if val is not None and str(val) == s:
                    return entry
        return None

    if channel is not None:
        ch_str = str(channel).strip().lower()
        if ch_str in ("0", "auto"):
            target_wire_channel = "0"
        elif chan_list:
            entry = _find_chan_entry(channel, prefer_wire=False)
            if entry is None:
                avail = sorted({
                    str(c.get("channelValue") or c.get("value"))
                    for c in chan_list if (c.get("channelValue") or c.get("value")) is not None
                }, key=lambda x: as_int(x, 0))
                raise OmadaError(
                    f"channel {channel!r} is not allowed on band {band_norm} for this AP/region",
                    hint=f"available {band_norm} channels: {', '.join(avail)} (or 'auto')",
                )
            matched_chan_entry = entry
            target_wire_channel = str(entry.get("value"))
        else:
            target_wire_channel = str(channel).strip()
    elif target_wire_channel not in ("", "0", "auto") and chan_list:
        matched_chan_entry = _find_chan_entry(target_wire_channel, prefer_wire=True)

    target_width_code = str(current_rs.get("channelWidth") or "")
    if channel_width is not None:
        cw_raw = str(channel_width).strip().lower()
        band_table = CHANNEL_WIDTH_TO_CODE.get(band_norm, CHANNEL_WIDTH_TO_CODE["5g"])
        if cw_raw in band_table:
            target_width_code = band_table[cw_raw]
        elif str(channel_width) in CHANNEL_WIDTH_LABELS:
            target_width_code = str(channel_width)
        else:
            raise OmadaError(
                f"invalid channelWidth {channel_width!r} for band {band_norm}",
                hint=f"valid widths for {band_norm}: {', '.join(sorted(k for k in band_table if k.endswith('mhz') or k == 'auto'))}",
            )

        requested_label = CHANNEL_WIDTH_LABELS.get(target_width_code, target_width_code)
        if requested_label != "AUTO" and matched_chan_entry is not None and "widthFlag" in matched_chan_entry:
            allowed_widths = width_flag_to_widths(matched_chan_entry.get("widthFlag"))
            if allowed_widths and requested_label not in allowed_widths:
                raise OmadaError(
                    f"channelWidth {requested_label} is not supported on channel "
                    f"{matched_chan_entry.get('channelValue') or matched_chan_entry.get('value')} ({band_norm})",
                    hint=f"supported widths on this channel: {', '.join(allowed_widths)}, or AUTO",
                )

    resolved_pow_level: Optional[int] = None
    if tx_power_level is not None:
        if isinstance(tx_power_level, int) and tx_power_level in TX_POWER_LEVEL_LABELS:
            resolved_pow_level = tx_power_level
        else:
            key = str(tx_power_level).strip().lower()
            if key not in TX_POWER_LEVEL_TO_CODE:
                raise OmadaError(
                    f"invalid txPowerLevel {tx_power_level!r}",
                    hint="valid levels: low (0), medium (1), high (2), custom (3), auto (4)",
                )
            resolved_pow_level = TX_POWER_LEVEL_TO_CODE[key]

    if tx_power is not None:
        misc = ap_detail.get("deviceMisc") if isinstance(ap_detail.get("deviceMisc"), Mapping) else {}
        min_p = misc.get("minPower2G" if band_norm == "2g" else "minPower5G")
        max_p = misc.get("maxPower2G" if band_norm == "2g" else "maxPower5G")
        if min_p is not None and tx_power < int(min_p):
            raise OmadaError(f"txPower {tx_power} is below hardware minimum {min_p} dBm")
        if max_p is not None and tx_power > int(max_p):
            raise OmadaError(f"txPower {tx_power} exceeds hardware maximum {max_p} dBm")

    return rs_key, target_wire_channel, {
        "band": band_norm,
        "wireChannel": target_wire_channel,
        "channelWidthCode": target_width_code,
        "channelWidthLabel": CHANNEL_WIDTH_LABELS.get(target_width_code, target_width_code),
        "txPowerLevel": resolved_pow_level,
        "matchedChannel": matched_chan_entry.get("channelValue") if matched_chan_entry else None,
    }, warnings


def extra_network_audit_findings(
    client: OmadaClient,
    site: SiteInfo,
    raw_devices: Sequence[Mapping[str, Any]],
) -> List[Dict[str, str]]:
    """Collect optional PoE, uplink speed, AP retry/interference, and WAN audit findings."""
    findings: List[Dict[str, str]] = []
    for dev in raw_devices:
        if not is_device_online(dev):
            continue
        dtype = str(dev.get("type") or "").lower()
        target = str(dev.get("name") or dev.get("mac") or "unknown")
        if dtype == "switch":
            try:
                sw_data = collect_switch_ports_data(
                    client, site, dev,
                    include_counters=False, include_cable_test=False, include_topology=False,
                )
            except OmadaError:
                continue
            poe = sw_data.get("poe") or {}
            used_pct = poe.get("usedPercent")
            if poe.get("supported") and used_pct is not None and used_pct >= 85.0:
                findings.append({
                    "code": "SWITCH_POE_BUDGET_HIGH",
                    "severity": "critical" if used_pct >= 95.0 else "warning",
                    "target": target,
                    "detail": (
                        f"Switch PoE utilization is {used_pct}% "
                        f"({poe.get('usedW')}W / {poe.get('totalBudgetW')}W)."
                    ),
                })
            for p in sw_data.get("ports") or []:
                if not p.get("linkUp"):
                    continue
                spd = p.get("speedMbps") or 0
                max_spd = p.get("maxSpeedMbps") or 0
                if max_spd >= 1000 and 0 < spd <= 100 and (p.get("isUplink") or p.get("downlinkDevices")):
                    findings.append({
                        "code": "SWITCH_LINK_SPEED_DOWNGRADED",
                        "severity": "warning",
                        "target": f"{target} port {p['port']}",
                        "detail": (
                            f"Port {p['port']} ({p['name']}) is linked at {p['speed']} "
                            f"on a {p['maxSpeed']} interface (possible cabling/auto-neg fault)."
                        ),
                    })
        elif dtype == "ap":
            try:
                ap_data = collect_ap_radios_data(
                    client, site, dev,
                    include_rf_scan=False, include_available_channels=False,
                )
            except OmadaError:
                continue
            for radio in ap_data.get("radios") or []:
                band = radio["band"]
                tx_pkts = radio.get("txPkts") or 0
                rx_pkts = radio.get("rxPkts") or 0
                tx_r = radio.get("txRetryRatePct")
                rx_r = radio.get("rxRetryRatePct")
                if (tx_pkts >= 100 and tx_r is not None and tx_r >= 20.0) or (
                    rx_pkts >= 100 and rx_r is not None and rx_r >= 25.0
                ):
                    findings.append({
                        "code": "AP_HIGH_RETRY_RATE",
                        "severity": "warning",
                        "target": f"{target} ({band})",
                        "detail": (
                            f"Radio {band} retry rate is elevated "
                            f"(txRetry={tx_r}%, rxRetry={rx_r}%)."
                        ),
                    })
                inter = radio.get("interferencePct")
                if inter is not None and inter >= 40.0:
                    findings.append({
                        "code": "AP_HIGH_INTERFERENCE",
                        "severity": "warning",
                        "target": f"{target} ({band})",
                        "detail": f"Radio {band} channel interference is {inter}%.",
                    })

    if any(str(d.get("type") or "").lower() == "gateway" for d in raw_devices):
        try:
            wan = collect_wan_status_data(
                client, site, devices=raw_devices, include_speedtest=False,
            )
            ports = wan.get("ports") or []
            if wan.get("hasGateway") and ports:
                up_inet = wan.get("internetUpCount", 0)
                if up_inet == 0:
                    findings.append({
                        "code": "WAN_ALL_PORTS_DOWN",
                        "severity": "critical",
                        "target": wan.get("gatewayName") or site.name,
                        "detail": "All configured WAN ports report internet offline.",
                    })
                elif wan.get("failoverConfigured") and up_inet < len(ports):
                    down_names = [p["name"] for p in ports if not p["internetUp"] and p.get("enabled", True)]
                    if down_names:
                        findings.append({
                            "code": "WAN_LINK_DEGRADED",
                            "severity": "warning",
                            "target": wan.get("gatewayName") or site.name,
                            "detail": f"WAN link down / failover condition on: {', '.join(down_names)}.",
                        })
                for p in ports:
                    loss = p.get("lossPct")
                    if p.get("internetUp") and loss is not None and loss > 1.0:
                        findings.append({
                            "code": "WAN_PACKET_LOSS",
                            "severity": "warning",
                            "target": f"{wan.get('gatewayName') or 'gateway'} {p['name']}",
                            "detail": f"{p['name']} reports {loss}% packet loss (latency={p.get('latencyMs')}ms).",
                        })
        except OmadaError:
            pass
    return findings


def dhcp_pool_capacity(dhcp: Mapping[str, Any]) -> int:
    """Total IPv4 addresses across ``dhcpSettings.ipRangePool`` (or start/end fallback)."""
    pools = list(dhcp.get("ipRangePool") or [])
    if not pools and dhcp.get("ipaddrStart") and dhcp.get("ipaddrEnd"):
        pools = [{"ipaddrStart": dhcp.get("ipaddrStart"), "ipaddrEnd": dhcp.get("ipaddrEnd")}]
    total = 0
    for pool in pools:
        if not isinstance(pool, Mapping):
            continue
        start_raw = pool.get("ipaddrStart")
        end_raw = pool.get("ipaddrEnd")
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
