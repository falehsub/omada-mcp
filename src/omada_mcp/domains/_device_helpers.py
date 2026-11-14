"""Switch port, AP radio, and RF scan collection and validation helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlparse

from ..client import OmadaClient, OmadaError, SiteInfo, redact_secrets
from ._common import (
    CHANNEL_WIDTH_LABELS,
    CHANNEL_WIDTH_TO_CODE,
    DUPLEX_LABELS,
    LINK_SPEED_LABELS,
    LINK_SPEED_MBPS,
    TX_POWER_LEVEL_LABELS,
    TX_POWER_LEVEL_TO_CODE,
    as_float,
    as_int,
    as_mapping,
    deep_redact,
    is_device_online,
    normalize_mac,
    omada_mac,
    try_api_result,
    try_paginate,
    unwrap_rows,
    width_flag_to_widths,
)


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


def _controller_host_from_config(client: OmadaClient) -> str | None:
    parsed = urlparse(client.config.base_url or "")
    return parsed.hostname.lower() if parsed.hostname else None


def _topology_downlinks_for_switch(
    topo_raw: Mapping[str, Any] | None,
    switch_mac_norm: str,
) -> tuple[int | None, set[int]]:
    """Extract (uplink_port, controller_hosting_ports) for a switch from topology-v2."""
    uplink_port: int | None = None
    controller_ports: set[int] = set()
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


def _compact_switch_port(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Strip zero counters, empty strings/lists, and null cableTest stubs from a port dict."""
    out: dict[str, Any] = {
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
) -> dict[str, Any]:
    """Fetch and correlate live switch detail, ports, PoE, counters, cable test, LAGs, and uplinks."""
    warnings: list[str] = []
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

    counters_by_port: dict[int, dict[str, Any]] = {}
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

    poe_by_port: dict[int, dict[str, Any]] = {}
    dev_cap = as_mapping(sw.get("devCap"))
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

    cable_ports_by_port: dict[int, dict[str, Any]] = {}
    ct_ports_raw, ok_ct_ports = try_api_result(
        client, f"sites/{site.site_id}/cable-test/switches/{mac_wire}/ports",
        warnings, label="switch port downlinks",
    )
    if ok_ct_ports:
        for row in unwrap_rows(ct_ports_raw):
            pno = as_int(row.get("port"), -1)
            if pno >= 0:
                cable_ports_by_port[pno] = dict(row)

    cable_results_by_port: dict[int, dict[str, Any]] = {}
    cable_test_status: int | None = None
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
    lag_port_map: dict[int, Any] = {}
    for lg in lag_groups:
        lid = lg.get("lagId") or lg.get("id") or lg.get("name")
        for member in lg.get("ports") or lg.get("portList") or lg.get("memberPorts") or []:
            mp = member.get("port") if isinstance(member, Mapping) else member
            if mp is not None and str(mp).isdigit():
                lag_port_map[int(mp)] = lid

    insight_detail_raw, ok_id = try_api_result(
        client, f"sites/{site.site_id}/insight/switch/detail", warnings, label="switch insight detail",
    )
    insight_uplink_port: int | None = None
    if ok_id:
        for item in unwrap_rows(insight_detail_raw):
            if normalize_mac(str(item.get("mac") or "")) == mac_norm:
                up_blk = item.get("uplink")
                if isinstance(up_blk, Mapping) and up_blk.get("port") is not None:
                    insight_uplink_port = as_int(up_blk.get("port"), -1)
                if not lag_groups and isinstance(item.get("lags"), list):
                    lag_groups = [dict(x) for x in item["lags"] if isinstance(x, Mapping)]

    topo_uplink_port: int | None = None
    topo_controller_ports: set[int] = set()
    if include_topology:
        topo_raw, ok_topo = try_api_result(
            client, f"sites/{site.site_id}/topology-v2", warnings, label="topology-v2",
        )
        if ok_topo and isinstance(topo_raw, Mapping):
            topo_uplink_port, topo_controller_ports = _topology_downlinks_for_switch(topo_raw, mac_norm)

    controller_host = _controller_host_from_config(client)
    stat_downlinks_by_port: dict[int, dict[str, Any]] = {}
    stat_raw, ok_stat = try_api_result(
        client, f"sites/{site.site_id}/stat/switches/{mac_wire}", warnings, label="switch port stats",
    )
    if ok_stat and isinstance(stat_raw, Mapping):
        for sp in stat_raw.get("ports") or []:
            if isinstance(sp, Mapping):
                pno = as_int(sp.get("port"), -1)
                if pno >= 0:
                    stat_downlinks_by_port[pno] = dict(sp)

    profiles_by_id: dict[str, str] = {}
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
    uplink_ports: set[int] = set()
    for cand in (sw_uplink_port, insight_uplink_port, topo_uplink_port):
        if cand is not None and as_int(cand, -1) > 0:
            uplink_ports.add(int(cand))

    normalized_ports: list[dict[str, Any]] = []
    sum_port_poe_w = 0.0
    for raw_p in sorted(ports_raw, key=lambda r: as_int(r.get("port"), 0)):
        pno = as_int(raw_p.get("port"), 0)
        pstatus = as_mapping(raw_p.get("portStatus"))
        stat_row = stat_downlinks_by_port.get(pno, {})
        stat_ps = as_mapping(stat_row.get("portStatus"))
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

        downlinks: list[dict[str, Any]] = []
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

        counters_obj: dict[str, Any] | None = None
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
    used_w: float | None = None
    used_pct: float | None = None
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


def _retry_rate_pct(retries: int, pkts: int) -> float | None:
    if pkts <= 0:
        return 0.0 if retries == 0 else None
    return round((retries / float(pkts)) * 100.0, 2)


def _extract_ap_band_map(ap: Mapping[str, Any]) -> dict[str, tuple[str, str, str]]:
    """Map canonical band names to (radioSettingKey, wpKey, radioTrafficKey)."""
    misc = as_mapping(ap.get("deviceMisc"))
    has_5g1 = bool(misc.get("support5g") and misc.get("support5g2")) or ("radioSetting5g1" in ap)
    candidates: dict[str, tuple[str, str, str]] = {}
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


def _channel_info_by_band(channel_info_raw: Any) -> dict[str, list[dict[str, Any]]]:
    rows = unwrap_rows(channel_info_raw)
    out: dict[str, list[dict[str, Any]]] = {}
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


_RADIO_ID_TO_BAND: dict[int, str] = {0: "2g", 1: "5g", 2: "5g2", 3: "6g"}


def count_ap_clients_by_band(
    ap_mac: str,
    ap_name: str,
    clients: Sequence[Mapping[str, Any]],
) -> dict[str, int]:
    """Count active wireless clients connected to an AP, grouped by ``radioId`` band."""
    counts: dict[str, int] = {}
    target_mac = normalize_mac(ap_mac)
    target_name = ap_name.strip().lower()
    for row in clients:
        if not row.get("wireless"):
            continue
        row_ap_mac = normalize_mac(str(row.get("apMac") or ""))
        row_ap_name = str(row.get("apName") or "").strip().lower()
        if target_mac and row_ap_mac:
            if row_ap_mac != target_mac:
                continue
        elif target_name and row_ap_name:
            if row_ap_name != target_name:
                continue
        else:
            continue
        rid = as_int(row.get("radioId"), -1)
        band = _RADIO_ID_TO_BAND.get(rid)
        if band:
            counts[band] = counts.get(band, 0) + 1
    return counts


def collect_ap_radios_data(
    client: OmadaClient,
    site: SiteInfo,
    ap_dev: Mapping[str, Any],
    *,
    include_rf_scan: bool = True,
    include_available_channels: bool = True,
    client_rows: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Fetch and normalize AP radio settings, RF utilization/retries, available channels, and RF scan."""
    warnings: list[str] = []
    mac_norm = normalize_mac(str(ap_dev.get("mac") or ""))
    mac_wire = omada_mac(mac_norm)

    detail_raw, ok_detail = try_api_result(
        client, f"sites/{site.site_id}/eaps/{mac_wire}", warnings, label="AP detail",
    )
    ap = dict(detail_raw) if ok_detail and isinstance(detail_raw, Mapping) else dict(ap_dev)

    chan_by_band: dict[str, list[dict[str, Any]]] = {}
    if include_available_channels:
        cinfo_raw, ok_ci = try_api_result(
            client, f"sites/{site.site_id}/eaps/{mac_wire}/channelInfo", warnings, label="AP channelInfo",
        )
        if ok_ci:
            chan_by_band = _channel_info_by_band(cinfo_raw)

    rf_scan_obj: dict[str, Any] | None = None
    if include_rf_scan:
        rf_raw, ok_rf = try_api_result(
            client, f"sites/{site.site_id}/eaps/{mac_wire}/tools/rfScan", warnings, label="AP RF scan",
        )
        if ok_rf and isinstance(rf_raw, Mapping):
            rf_scan_obj = deep_redact(dict(rf_raw))

    ap_name = str(ap.get("name") or mac_norm)
    band_counts = (
        count_ap_clients_by_band(mac_norm, ap_name, client_rows)
        if client_rows is not None
        else None
    )

    band_map = _extract_ap_band_map(ap)
    radios: list[dict[str, Any]] = []
    for band, (rs_key, wp_key, rt_key) in band_map.items():
        rs = as_mapping(ap.get(rs_key))
        wp = as_mapping(ap.get(wp_key))
        rt = as_mapping(ap.get(rt_key))
        if not rs and not wp and not rt and band not in chan_by_band:
            continue

        avail_entries: list[dict[str, Any]] = []
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
            "clientCount": band_counts.get(band, 0) if band_counts is not None else None,
            "availableChannels": avail_entries,
        })

    return {
        "mac": mac_norm,
        "name": ap_name,
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
) -> dict[str, Any]:
    """Collect latest RF scan status/results paired with current AP interference telemetry."""
    radio_data = collect_ap_radios_data(
        client, site, ap_dev, include_rf_scan=True, include_available_channels=True,
    )
    rf = radio_data.get("rfScan") or {}
    channels: list[dict[str, Any]] = []
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


def validate_ap_radio_change(
    client: OmadaClient,
    site: SiteInfo,
    ap_detail: Mapping[str, Any],
    band: str,
    *,
    channel: Any | None = None,
    channel_width: Any | None = None,
    tx_power_level: Any | None = None,
    tx_power: int | None = None,
) -> tuple[str, str, dict[str, Any], list[str]]:
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
    warnings: list[str] = []
    mac_wire = omada_mac(str(ap_detail.get("mac") or ""))
    cinfo_raw, ok_ci = try_api_result(
        client, f"sites/{site.site_id}/eaps/{mac_wire}/channelInfo", warnings, label="AP channelInfo",
    )
    chan_list = _channel_info_by_band(cinfo_raw).get(band_norm, []) if ok_ci else []

    current_rs = as_mapping(ap_detail.get(rs_key))
    target_wire_channel = str(current_rs.get("channel") or "0")
    matched_chan_entry: dict[str, Any] | None = None

    def _find_chan_entry(
        ch_input: Any,
        *,
        prefer_wire: bool = False,
    ) -> dict[str, Any] | None:
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

    resolved_pow_level: int | None = None
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
        misc = as_mapping(ap_detail.get("deviceMisc"))
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
