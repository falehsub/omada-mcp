"""Read domain module: diagnostics_read."""

from __future__ import annotations

import datetime
from typing import Any

from ..client import OmadaClient, OmadaError, explain_error_code, redact_secrets
from ._common import as_float as _as_float
from ._common import as_mapping, deep_redact, omada_mac, try_api_result, try_paginate
from ._device_helpers import collect_ap_radios_data, collect_switch_ports_data
from ._network_helpers import collect_vpn_tunnels_data, collect_wan_status_data
from ._tool_model import (
    _DIAGNOSTIC_FINDING_SCHEMA,
    _as_int,
    _iso,
    _pick,
    _site,
    as_int_or_none,
    normalize_mac,
)
from ._write_fetchers import _fetch_devices
from .clients_read import _fetch_clients
from .networks_read import _WAN_STATUS_SCHEMA


def _explain_error(
    _client: OmadaClient,
    code: int,
    endpoint: str | None = None,
) -> dict[str, Any]:
    return explain_error_code(int(code), endpoint=endpoint)


def _list_logs(
    client: OmadaClient,
    category: str = "alerts",
    hours: int = 24,
    level: Any | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
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
    out: list[dict[str, Any]] = []
    for row in rows:
        raw_time = row.get("time") or row.get("timestamp") or row.get("createTime")
        if cat == "audit" and hours > 0 and isinstance(raw_time, (int, float)) and raw_time < start_ms:
            continue
        row_level = row.get("level") if row.get("level") is not None else row.get("severity")
        if level_needle is not None and str(row_level if row_level is not None else "").strip().lower() != level_needle:
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


def _safe_recent_logs(
    client: OmadaClient,
    hours: int,
    warnings: list[str],
    limit: int = 50,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
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
) -> dict[str, Any]:
    with client.scoped_cache():
        return _diagnose_client_impl(client, mac, hours=hours)


def _diagnose_client_impl(
    client: OmadaClient,
    mac: str,
    hours: int = 24,
) -> dict[str, Any]:
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 0:
        raise OmadaError("hours must be a non-negative integer")
    site = _site(client)
    warnings: list[str] = []
    wanted_mac = normalize_mac(mac)
    needle = str(mac or "").strip().lower()

    matched_live: dict[str, Any] | None = None
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
    detail_raw: dict[str, Any] = {}
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
    rate_limit = as_mapping(detail_raw.get("rateLimit"))

    client_summary: dict[str, Any] = {
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

    parent_radio: dict[str, Any] | None = None
    parent_switch_port: dict[str, Any] | None = None

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
            rid = as_int_or_none(radio_id)
            band_hint = {0: "2g", 1: "5g", 2: "5g2", 3: "6g"}.get(rid) if rid is not None else None
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

    findings: list[dict[str, str]] = []
    next_steps: list[str] = []

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


def _diagnose_wan(
    client: OmadaClient,
    includeSpeedtest: bool = True,
    hours: int = 24,
) -> dict[str, Any]:
    with client.scoped_cache():
        return _diagnose_wan_impl(client, includeSpeedtest=includeSpeedtest, hours=hours)


def _diagnose_wan_impl(
    client: OmadaClient,
    includeSpeedtest: bool = True,
    hours: int = 24,
) -> dict[str, Any]:
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 0:
        raise OmadaError("hours must be a non-negative integer")
    site = _site(client)
    warnings: list[str] = []
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

    findings: list[dict[str, str]] = []
    next_steps: list[str] = []
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


_EXPLAIN_ERROR_SCHEMA: dict[str, Any] = {
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


_LOG_SCHEMA: dict[str, Any] = {
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


_DIAGNOSE_CLIENT_SCHEMA: dict[str, Any] = {
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


_DIAGNOSE_WAN_SCHEMA: dict[str, Any] = {
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

