"""WAN status, VPN tunnel, topology, security, and audit collection helpers."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError, SiteInfo
from ._common import (
    as_float,
    as_int,
    as_mapping,
    deep_redact,
    is_device_online,
    mask_ipv4_middle,
    normalize_mac,
    omada_mac,
    try_api_result,
    try_paginate,
    unwrap_rows,
)
from ._device_helpers import (
    _duplex_label,
    _speed_label,
    collect_ap_radios_data,
    collect_switch_ports_data,
)


def collect_wan_status_data(
    client: OmadaClient,
    site: SiteInfo,
    *,
    devices: Sequence[Mapping[str, Any]] | None = None,
    include_speedtest: bool = True,
    mask_wan_ip: bool = False,
) -> dict[str, Any]:
    """Gather gateway WAN link status, DNS/gateway IPs, latency/loss, failover, and speedtest."""
    warnings: list[str] = []
    devs = list(devices) if devices is not None else unwrap_rows(
        try_api_result(client, f"sites/{site.site_id}/devices", warnings, label="devices")[0]
    )
    gateways = [d for d in devs if str(d.get("type") or "").lower() == "gateway"]

    wan_ls_raw, ok_wls = try_api_result(
        client, f"sites/{site.site_id}/setting/wanlanstatus", warnings, label="WAN/LAN status",
    )
    has_gw_flag = bool(gateways) or bool(ok_wls and isinstance(wan_ls_raw, Mapping) and wan_ls_raw.get("hasGateway"))
    if has_gw_flag:
        wan_cfg_raw, ok_wcfg = try_api_result(
            client, f"sites/{site.site_id}/setting/wan/networks", warnings, label="WAN settings",
        )
        port_state_raw, ok_ps = try_api_result(
            client, f"sites/{site.site_id}/dashboard/portstatedetails", warnings, label="WAN port state details",
        )
    else:
        wan_cfg_raw, ok_wcfg = None, False
        port_state_raw, ok_ps = None, False

    gw_detail: dict[str, Any] = {}
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

    speedtest_obj: dict[str, Any] | None = None
    if include_speedtest and gateways:
        st_raw, ok_st = try_api_result(
            client, f"sites/{site.site_id}/cmd/getSpeedTestResult", warnings, label="speedtest result",
        )
        if ok_st and isinstance(st_raw, Mapping):
            speedtest_obj = deep_redact(dict(st_raw))

    port_infos_by_name: dict[str, dict[str, Any]] = {}
    port_infos_by_port: dict[int, dict[str, Any]] = {}
    if ok_ps and isinstance(port_state_raw, Mapping):
        for pi in port_state_raw.get("portInfos") or []:
            if isinstance(pi, Mapping):
                if pi.get("port") is not None:
                    port_infos_by_port[as_int(pi.get("port"), -1)] = dict(pi)
                if pi.get("portName"):
                    port_infos_by_name[str(pi["portName"])] = dict(pi)

    wan_list_by_name: dict[str, dict[str, Any]] = {}
    if ok_wls and isinstance(wan_ls_raw, Mapping):
        for wl in wan_ls_raw.get("wanList") or []:
            if isinstance(wl, Mapping) and wl.get("portName"):
                wan_list_by_name[str(wl["portName"])] = dict(wl)

    osg_settings_by_name: dict[str, dict[str, Any]] = {}
    wan_cfg = deep_redact(dict(wan_cfg_raw)) if ok_wcfg and isinstance(wan_cfg_raw, Mapping) else {}
    osg_info = as_mapping(wan_cfg.get("osgPortInfo"))
    for wp in osg_info.get("wanLanPortSettings") or []:
        if isinstance(wp, Mapping) and wp.get("portName") and wp.get("mode") in (0, -1):
            osg_settings_by_name[str(wp["portName"])] = dict(wp)

    wan_ports: list[dict[str, Any]] = []
    seen_ports: set[int] = set()
    for pc in gw_detail.get("portConfigs") or []:
        if not isinstance(pc, Mapping):
            continue
        ps = as_mapping(pc.get("portStat"))
        pno = as_int(ps.get("port") if ps.get("port") is not None else pc.get("port"), 0)
        pname = str(ps.get("name") or "")
        is_wan = (ps.get("mode") == 0) or (pname in wan_list_by_name) or (pno in port_infos_by_port)
        if not is_wan:
            continue
        seen_ports.add(pno)
        pi = port_infos_by_port.get(pno) or port_infos_by_name.get(pname) or {}
        ipv4_cfg = as_mapping(ps.get("wanPortIpv4Config"))
        ipv6_cfg = as_mapping(ps.get("wanPortIpv6Config"))

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


def collect_vpn_tunnels_data(
    client: OmadaClient,
    site: SiteInfo,
    *,
    has_gateway: bool | None = None,
) -> dict[str, Any]:
    """Collect VPN tunnel/peer state and secret-redacted VPN definitions."""
    warnings: list[str] = []
    tunnels: list[dict[str, Any]] = []
    configured: list[dict[str, Any]] = []

    if has_gateway is None:
        devs = unwrap_rows(
            try_api_result(client, f"sites/{site.site_id}/devices", warnings, label="devices")[0]
        )
        has_gateway = any(str(d.get("type") or "").lower() == "gateway" for d in devs)

    if has_gateway:
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
    else:
        warnings.append("No adopted gateway present on site; live VPN tunnel telemetry skipped.")

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


def _extract_node_uplink(node: Mapping[str, Any]) -> tuple[int | None, str | None, str | None]:
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
    devices: Sequence[Mapping[str, Any]] | None = None,
    include_clients: bool = False,
) -> dict[str, Any]:
    """Build a compact uplink topology tree with fallback from topology-v2 to topology."""
    warnings: list[str] = []
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
    seen_macs: set[str] = set()
    counts: dict[str, int] = {"gateway": 0, "switch": 0, "ap": 0, "other": 0}
    max_depth = 0

    def build_node(node: Mapping[str, Any], depth: int) -> dict[str, Any] | None:
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
        children: list[dict[str, Any]] = []
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

    tree: list[dict[str, Any]] = []
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
) -> dict[str, Any]:
    """Gather IPS/IDS, attack defense, WIDS/WIPS, threat events, and rogue AP state."""
    warnings: list[str] = []
    cap = max(1, min(200, int(limit or 20)))

    ips_raw, ok_ips = try_api_result(client, f"sites/{site.site_id}/setting/ips", warnings, label="IPS settings")
    ips_obj: dict[str, Any] | None = None
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
    wids_obj: dict[str, Any] | None = None
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


def extra_network_audit_findings(
    client: OmadaClient,
    site: SiteInfo,
    raw_devices: Sequence[Mapping[str, Any]],
) -> list[dict[str, str]]:
    """Collect optional PoE, uplink speed, AP retry/interference, and WAN audit findings."""
    findings: list[dict[str, str]] = []
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
