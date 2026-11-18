"""Read domain module: diagnostics_read."""

from __future__ import annotations

import datetime
import math
import re
from typing import Any
from urllib.parse import quote

from ..client import OmadaClient, OmadaError, explain_error_code, redact_secrets
from ._common import (
    PaginatedList,
    as_mapping,
    deep_redact,
    omada_mac,
    pagination_status,
    try_api_result,
    try_paginate,
)
from ._common import as_float as _as_float
from ._device_helpers import collect_ap_radios_data, collect_switch_ports_data
from ._network_helpers import collect_vpn_tunnels_data, collect_wan_status_data, read_audit_source
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

_CLIENT_DIAGNOSTIC_REQUEST_LIMIT = 64
_WAN_DIAGNOSTIC_REQUEST_LIMIT = 32
_HISTORY_FIELDS = (
    "mac", "name", "hostName", "ip", "ssid", "apMac", "apName", "switchMac", "switchName",
    "firstSeen", "lastSeen", "associationTime", "connectTime", "time", "duration", "uptime",
)
_RATE_LIMIT_FIELDS = ("enable", "rateLimitId", "upLimit", "downLimit", "upEnable", "downEnable")


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

    rows, meta = client.paginate(
        endpoint,
        page_size=min(100, cap),
        max_pages=max(1, (cap + 99) // 100),
    )

    level_needle = str(level).strip().lower() if level is not None and str(level).strip() != "" else None
    matched_rows: list[dict[str, Any]] = []
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
        matched_rows.append({
            "id": str(cleaned.get("id") or cleaned.get("logId") or ""),
            "category": cat,
            "time": _iso(_diagnostic_time_ms(raw_time)),
            "level": row_level,
            "type": cleaned.get("type") if cleaned.get("type") is not None else cleaned.get("auditType"),
            "module": cleaned.get("module"),
            "content": str(content or ""),
            "target": str(target or ""),
            "resolved": bool(cleaned.get("resolved", False)),
        })

    upstream_meta = (meta or {}).get("_pagination") or {}
    out = matched_rows[:cap]
    hit_cap = len(matched_rows) > cap
    upstream_truncated = bool(upstream_meta.get("truncated", False))
    truncated = hit_cap or upstream_truncated
    reason = (
        f"logs capped at limit={cap}"
        if hit_cap
        else upstream_meta.get("truncationReason")
    )
    return PaginatedList(
        out,
        truncated=truncated,
        total_rows=upstream_meta.get("totalRows") if upstream_truncated else len(matched_rows),
        pages_fetched=upstream_meta.get("pagesFetched"),
        max_pages=upstream_meta.get("maxPages"),
        limit=cap,
        truncation_reason=reason,
    )


def _safe_recent_logs(
    client: OmadaClient,
    hours: int,
    warnings: list[str],
    limit: int = 50,
) -> tuple[list[dict[str, Any]], str]:
    events: list[dict[str, Any]] = []
    statuses: list[str] = []
    for cat in ("alerts", "events"):
        try:
            rows = _list_logs(client, category=cat, hours=hours, limit=limit)
            events.extend(rows)
            if isinstance(rows, PaginatedList) and rows.truncated:
                statuses.append("partial")
                warnings.append(f"logs/{cat}: partial (bounded collection).")
            else:
                statuses.append("available")
        except OmadaError as exc:
            statuses.append("unavailable")
            warnings.append(f"logs/{cat}: unavailable (controller code {exc.code}).")
    if statuses == ["unavailable", "unavailable"]:
        return events, "unavailable"
    if any(status != "available" for status in statuses):
        return events, "partial"
    return events, "available" if events else "empty"


def _diagnostic_time_ms(value: Any) -> int | None:
    """Read controller epoch stamps and ISO timestamps without guessing missing time."""
    if isinstance(value, bool):
        return None
    try:
        stamp = float(value)
    except (TypeError, ValueError):
        if not isinstance(value, str):
            return None
        try:
            parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return int(parsed.timestamp() * 1000) if parsed.tzinfo is not None else None
        except (OSError, OverflowError, ValueError):
            return None
    if math.isfinite(stamp) and stamp > 0:
        return int(stamp * 1000) if stamp < 100_000_000_000 else int(stamp)
    return None


def _window_start(now_ms: int, hours: int) -> int | None:
    return max(1, now_ms - hours * 3600 * 1000) if hours else None


def _matches_identity(text: str, identities: set[str]) -> bool:
    # A complete identifier is evidence; an identifier embedded in another name or address is not.
    return any(
        re.search(rf"(?<![\w:.@-]){re.escape(value)}(?![\w:@-]|\.(?=\w))", text)
        for value in identities
    )


def _mac_forms(value: str) -> set[str]:
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
        return set()
    return {value, omada_mac(value).lower(), value.replace(":", "")}


def _prioritize_recent(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda row: _diagnostic_time_ms(row.get("time")) or 0, reverse=True)


def _diagnose_client(
    client: OmadaClient,
    mac: str,
    hours: int = 24,
) -> dict[str, Any]:
    with client.request_budget(_CLIENT_DIAGNOSTIC_REQUEST_LIMIT) as budget, client.scoped_cache():
        result = _diagnose_client_impl(client, mac, hours=hours)
    result["controllerRequests"] = budget.used
    result["requestLimit"] = budget.limit
    if budget.used >= budget.limit:
        result["warnings"].append("The request budget limited client diagnostic checks.")
    return result


def _diagnose_client_impl(
    client: OmadaClient,
    mac: str,
    hours: int = 24,
) -> dict[str, Any]:
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 0:
        raise OmadaError("hours must be a non-negative integer")
    site = _site(client)
    warnings: list[str] = []
    coverage: dict[str, str] = {}
    now_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
    start_ms = _window_start(now_ms, hours)
    wanted_mac = normalize_mac(mac)
    needle = str(mac or "").strip().lower()

    matched_live: dict[str, Any] | None = None
    live_rows = read_audit_source(
        lambda: _fetch_clients(client, limit=0), "activeClients", "Active clients", coverage, warnings,
    )
    for entry in live_rows or []:
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
    if _mac_forms(target_mac):
        raw_d, ok_d = try_api_result(
            client, f"sites/{site.site_id}/clients/{omada_mac(target_mac)}",
            warnings, label="client detail",
        )
        if ok_d and isinstance(raw_d, dict):
            detail_raw = raw_d

    search_key = omada_mac(target_mac) if _mac_forms(target_mac) else str(mac).strip()
    past_rows, past_meta, ok_past = try_paginate(
        client, f"sites/{site.site_id}/insight/pastConnection?searchKey={quote(search_key, safe='')}",
        warnings, label="client connection history", page_size=20, max_pages=1,
    )
    history_rows = [
        {key: row[key] for key in _HISTORY_FIELDS if isinstance(row.get(key), (str, int, float))}
        for row in past_rows
        if (normalize_mac(str(row.get("mac") or "")) == target_mac if _mac_forms(target_mac)
            else needle and needle in {str(row.get(key, "")).lower() for key in ("name", "hostName", "ip")})
    ]
    sessions_chrono: list[tuple[int, dict[str, Any]]] = []
    past_undated = 0
    past_outside_window = 0
    for row in history_rows:
        when = _diagnostic_time_ms(_pick(row, "firstSeen", "associationTime", "connectTime", "time", "lastSeen"))
        if when is None:
            past_undated += 1
        elif when > now_ms or (start_ms is not None and when < start_ms):
            past_outside_window += 1
        else:
            sessions_chrono.append((when, row))
    sessions_chrono.sort(key=lambda pair: pair[0])
    past_connections = [row for _, row in reversed(sessions_chrono)]

    if matched_live is None and not detail_raw and not history_rows:
        complete_search = coverage["activeClients"] == "complete" and pagination_status(past_meta, available=ok_past) == "complete"
        raise OmadaError(
            f"no client matches {mac!r}" if complete_search else f"could not resolve client {mac!r} with the available telemetry",
            hint="check list_clients; accepts MAC, hostname, or IP",
        )

    base = matched_live or {}
    c_mac = normalize_mac(str(detail_raw.get("mac") or base.get("mac") or target_mac))
    c_name = str(detail_raw.get("name") or base.get("name") or detail_raw.get("hostName") or c_mac)
    c_host = str(detail_raw.get("hostName") or base.get("hostName") or "")
    c_ip = str(detail_raw.get("ip") or base.get("ip") or "")
    is_wireless = bool(detail_raw.get("wireless") if "wireless" in detail_raw else base.get("wireless", False))
    if not matched_live and not detail_raw and history_rows:
        latest = past_connections[0] if past_connections else history_rows[0]
        c_mac = normalize_mac(str(latest.get("mac") or c_mac))
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
        "active": (bool(detail_raw["active"]) if detail_raw.get("active") in (True, False)
                   else True if matched_live else False if coverage["activeClients"] == "complete" else None),
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
        "rateLimit": ({key: rate_limit[key] for key in _RATE_LIMIT_FIELDS
                       if isinstance(rate_limit.get(key), (str, int, bool))} if rate_limit else None),
        "lockToApMac": normalize_mac(str(detail_raw.get("lockToApMac") or "")) if detail_raw.get("lockToApMac") else "",
    }

    raw_devices = read_audit_source(
        lambda: _fetch_devices(client, site), "devices", "Devices", coverage, warnings,
    ) or []

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
            ap_data = read_audit_source(
                lambda: collect_ap_radios_data(
                    client, site, ap_dev, include_rf_scan=False, include_available_channels=False,
                ), "parentDevice", "Parent AP", coverage, warnings,
            ) or {}
            warnings.extend(ap_data.get("warnings") or [])
            rid = as_int_or_none(radio_id)
            band_hint = {0: "2g", 1: "5g", 2: "5g2", 3: "6g"}.get(rid) if rid is not None else None
            for r in ap_data.get("radios") or []:
                if (band_hint and r["band"] == band_hint) or (channel is not None and r.get("channel") == channel):
                    parent_radio = r
                    break
            if parent_radio is None and len(ap_data.get("radios") or []) == 1:
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
            sw_data = read_audit_source(
                lambda: collect_switch_ports_data(
                    client, site, sw_dev, include_counters=True, include_cable_test=True, include_topology=False,
                ), "parentDevice", "Parent switch", coverage, warnings,
            ) or {}
            warnings.extend(sw_data.get("warnings") or [])
            if switch_port is not None:
                pnum = _as_int(switch_port, -1)
                parent_switch_port = next(
                    (p for p in (sw_data.get("ports") or []) if p.get("port") == pnum), None,
                )

    parent_tokens = {value.lower() for value in (ap_name, switch_name) if value}
    parent_tokens.update(_mac_forms(ap_mac) | _mac_forms(switch_mac))
    client_tokens = {value.lower() for value in (c_name, c_host, c_ip) if value and value != "0.0.0.0"}
    client_tokens.difference_update(parent_tokens)
    client_tokens.update(_mac_forms(c_mac))
    all_logs, logs_state = _safe_recent_logs(client, hours, warnings)
    direct_logs: list[dict[str, Any]] = []
    infrastructure_logs: list[dict[str, Any]] = []
    logs_undated = 0
    logs_outside_window = 0
    for entry in all_logs:
        time_ms = _diagnostic_time_ms(entry.get("time"))
        if time_ms is None:
            logs_undated += 1
            continue
        if time_ms > now_ms or (start_ms is not None and time_ms < start_ms):
            logs_outside_window += 1
            continue
        message = f"{entry.get('target', '')} {entry.get('content', '')}".lower()
        if _matches_identity(message, client_tokens):
            direct_logs.append(entry)
        elif _matches_identity(message, parent_tokens):
            infrastructure_logs.append(entry)
    if logs_state == "available" and logs_undated:
        logs_state = "partial"

    findings: list[dict[str, str]] = []
    next_steps: list[str] = []

    if client_summary["active"] is False:
        findings.append({
            "code": "CLIENT_OFFLINE",
            "severity": "warning",
            "detail": f"Client {c_name} ({c_mac}) is not currently active on the live client table.",
        })
        next_steps.append("Check physical link/Wi-Fi radio availability or review recent pastConnection entries.")

    if client_summary["lockToApMac"] and ap_mac and client_summary["lockToApMac"] != ap_mac:
        findings.append({
            "code": "LOCK_TO_AP_MISMATCH",
            "severity": "warning",
            "detail": f"Client is locked to AP {client_summary['lockToApMac']} but currently associated with {ap_mac}.",
        })
        next_steps.append("Verify lock-to-AP binding or clear/update it via set_client_lock_to_ap.")

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

    ap_transitions: list[dict[str, Any]] = []
    unique_aps: set[str] = set()
    short_sessions = 0
    prev_ap_id = ""
    prev_ap_label = ""
    for ts, row in sessions_chrono:
        row_ap_mac = normalize_mac(str(_pick(row, "apMac", default="") or ""))
        row_ap_name = str(_pick(row, "apName", default="") or "")
        ap_id = row_ap_mac or row_ap_name.lower()
        ap_label = row_ap_name or row_ap_mac
        if ap_id:
            unique_aps.add(ap_id)
            if prev_ap_id and ap_id != prev_ap_id:
                ap_transitions.append({
                    "fromAp": prev_ap_label,
                    "toAp": ap_label,
                    "time": _iso(ts),
                    "ssid": str(_pick(row, "ssid", default="") or ""),
                })
            prev_ap_id = ap_id
            prev_ap_label = ap_label
        dur = as_int_or_none(_pick(row, "duration", "uptime"))
        if dur is not None and 0 < dur < 120:
            short_sessions += 1

    roam_log_events: list[dict[str, Any]] = []
    disconnect_log_events: list[dict[str, Any]] = []
    connect_log_count = 0
    for entry in _prioritize_recent(direct_logs):
        text = f"{entry.get('target', '')} {entry.get('content', '')}".lower()
        if any(tok in text for tok in ("roam", "handoff", "steer")):
            roam_log_events.append({
                "time": entry.get("time", ""),
                "category": entry.get("category", ""),
                "content": entry.get("content", ""),
            })
        elif any(tok in text for tok in ("disconnect", "deauth", "offline", "dropped", "disassociat")):
            disconnect_log_events.append({
                "time": entry.get("time", ""),
                "category": entry.get("category", ""),
                "content": entry.get("content", ""),
            })
        elif any(tok in text for tok in ("connect", "joined", "associat")):
            connect_log_count += 1

    past_status = pagination_status(past_meta, available=ok_past)
    if past_status == "unavailable":
        past_state = "unavailable"
    elif past_status == "partial" or past_undated:
        past_state = "partial"
    elif past_connections:
        past_state = "available"
    else:
        past_state = "empty"

    if parent_radio is not None or parent_switch_port is not None:
        parent_state = "available"
    elif (is_wireless and (ap_mac or ap_name)) or (not is_wireless and (switch_mac or switch_name)):
        parent_state = "unavailable"
    else:
        parent_state = "not_applicable"

    telemetry_availability = {
        "activeClients": coverage["activeClients"],
        "clientDetail": "available" if detail_raw else "unavailable",
        "pastConnections": past_state,
        "logs": logs_state,
        "parentTelemetry": parent_state,
    }

    roaming_summary = {
        "sessionCount": len(past_connections),
        "uniqueApCount": len(unique_aps),
        "apTransitionCount": len(ap_transitions),
        "shortSessionCount": short_sessions,
        "apTransitions": ap_transitions[:20],
        "roamLogEvents": roam_log_events[:20],
        "disconnectLogCount": len(disconnect_log_events),
        "connectLogCount": connect_log_count,
        "historyAvailable": bool(past_connections or roam_log_events or disconnect_log_events),
    }

    if len(disconnect_log_events) >= 3 or (short_sessions >= 3 and len(past_connections) >= 3):
        findings.append({
            "code": "FREQUENT_DISCONNECTS",
            "severity": "warning",
            "detail": (
                f"Observed {len(disconnect_log_events)} disconnect log event(s) and "
                f"{short_sessions} short session(s) (<120s) for {c_name}."
            ),
        })
        next_steps.append("Check RSSI/SNR stability, AP channel interference, and client power-saving / band-steering behavior.")

    if len(ap_transitions) >= 3 or len(roam_log_events) >= 3:
        findings.append({
            "code": "FREQUENT_AP_ROAMING",
            "severity": "warning" if short_sessions >= 2 else "info",
            "detail": (
                f"Observed {len(ap_transitions)} AP transition(s) across {len(unique_aps)} AP(s) and "
                f"{len(roam_log_events)} roam log event(s)."
            ),
        })
        next_steps.append("Review AP TX power overlap / RSSI threshold to avoid sticky or ping-pong roaming.")

    missing_sources = [k for k, v in telemetry_availability.items() if v in ("unavailable", "partial")]
    if missing_sources:
        findings.append({
            "code": "TELEMETRY_PARTIAL",
            "severity": "info",
            "detail": "Some diagnostic telemetry sources were unavailable or partial: " + ", ".join(missing_sources) + ".",
        })

    if is_wireless and not past_connections and not roam_log_events:
        findings.append({
            "code": "ROAM_HISTORY_UNAVAILABLE",
            "severity": "info",
            "detail": (
                "No dated connection sessions or direct roam events were observed in the selected window; "
                "roaming stability cannot be confirmed from current history."
            ),
        })

    if not next_steps:
        if any(f["severity"] != "info" for f in findings):
            next_steps.append("Inspect the evidence in the reported findings and recheck the affected client link.")
        elif roaming_summary["historyAvailable"] and not missing_sources and client_summary["active"] is True:
            next_steps.append("Live link and observed connection/roam history show no faults.")
        else:
            next_steps.append("Collect the missing or empty controller telemetry and inspect again after client activity.")

    return {
        "client": client_summary,
        "parentRadio": parent_radio,
        "parentSwitchPort": parent_switch_port,
        "pastConnections": past_connections,
        "recentLogs": _prioritize_recent(direct_logs)[:25],
        "infrastructureLogs": _prioritize_recent(infrastructure_logs)[:25],
        "timeWindow": {"hours": hours, "start": _iso(start_ms) if start_ms is not None else None, "end": _iso(now_ms)},
        "coverage": {
            "pastConnections": {
                "status": past_state, "scanned": len(past_rows), "inWindow": len(past_connections),
                "outsideWindow": past_outside_window, "undated": past_undated,
            },
            "logs": {
                "status": logs_state, "scanned": len(all_logs), "outsideWindow": logs_outside_window,
                "undated": logs_undated, "directClientMatches": len(direct_logs),
                "infrastructureMatches": len(infrastructure_logs),
            },
        },
        "roamingSummary": roaming_summary,
        "telemetryAvailability": telemetry_availability,
        "findings": findings,
        "nextSteps": next_steps,
        "warnings": warnings,
    }


def _diagnose_wan(
    client: OmadaClient,
    includeSpeedtest: bool = True,
    hours: int = 24,
) -> dict[str, Any]:
    with client.request_budget(_WAN_DIAGNOSTIC_REQUEST_LIMIT) as budget, client.scoped_cache():
        result = _diagnose_wan_impl(client, includeSpeedtest=includeSpeedtest, hours=hours)
    result["controllerRequests"] = budget.used
    result["requestLimit"] = budget.limit
    if budget.used >= budget.limit:
        result["warnings"].append("The request budget limited WAN diagnostic checks.")
    return result


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
    all_logs, logs_state = _safe_recent_logs(client, hours, warnings)
    recent_logs = [
        entry for entry in all_logs
        if any(
            tok in f"{entry.get('target', '')} {entry.get('module', '')} {entry.get('content', '')}".lower()
            for tok in gw_tokens
        )
    ][:25]

    findings: list[dict[str, str]] = []
    next_steps: list[str] = []
    ports = [p for p in wan.get("ports") or [] if p.get("enabled", True)]
    observed_internet = [p for p in ports if p.get("internetStatusKnown")]
    confirmed_outage = bool(ports) and len(observed_internet) == len(ports) and not any(
        p.get("internetUp") for p in observed_internet
    )

    if not wan.get("hasGateway"):
        known_absence = wan.get("gatewayInventoryKnown")
        findings.append({
            "code": "WAN_NO_GATEWAY" if known_absence else "WAN_GATEWAY_INVENTORY_UNAVAILABLE",
            "severity": "info",
            "detail": ("No Omada gateway is adopted on this site."
                       if known_absence else "Controller data did not establish whether this site has a gateway."),
        })
        next_steps.append("Check the upstream router directly or verify the site's adopted gateway inventory.")
    else:
        if confirmed_outage:
            findings.append({
                "code": "WAN_ALL_LINKS_DOWN",
                "severity": "critical",
                "detail": "All gateway WAN ports report internet offline.",
            })
            next_steps.append("Check ISP modem/fiber link, physical WAN cable, and gateway PPPoE/DHCP authentication.")
        for p in ports:
            if p.get("linkStatusKnown") and not p.get("linkUp"):
                findings.append({
                    "code": "WAN_PORT_LINK_DOWN",
                    "severity": "warning",
                    "detail": f"WAN port {p['port']} ({p['name']}) physical link is down.",
                })
                next_steps.append(f"Check the modem and physical link on {p['name']}.")
            elif p.get("linkUp") and p.get("internetStatusKnown") and not p.get("internetUp"):
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

    if confirmed_outage:
        status = "offline"
    elif any(f["severity"] in ("warning", "critical") for f in findings):
        status = "degraded"
    elif ports and len(observed_internet) == len(ports):
        status = "operational"
    elif not wan.get("hasGateway") and wan.get("gatewayInventoryKnown"):
        status = "no_gateway"
    else:
        status = "unknown"

    if not next_steps:
        if status == "operational":
            next_steps.append("All enabled WAN ports report internet reachability. Check latency and recent gateway logs for intermittent drops.")
        elif status == "degraded":
            next_steps.append("Check the affected WAN ports and compare the reported latency, loss, or errors with the gateway's online detection.")
        else:
            next_steps.append("Check gateway permissions and online detection to obtain WAN reachability evidence.")

    return {
        "wan": wan,
        "status": status,
        "telemetryAvailability": {
            "gatewayInventory": "available" if wan.get("gatewayInventoryKnown") else "unavailable",
            "internetReachability": (
                "empty" if status == "no_gateway" else
                "unavailable" if not observed_internet else
                "available" if len(observed_internet) == len(ports) else "partial"
            ),
            "logs": logs_state,
        },
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
        "recentLogs": {"type": "array", "items": _LOG_SCHEMA},
        "infrastructureLogs": {"type": "array", "items": _LOG_SCHEMA},
        "timeWindow": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 0},
                "start": {"type": ["string", "null"]},
                "end": {"type": "string"},
            },
            "required": ["hours", "start", "end"],
        },
        "coverage": {
            "type": "object",
            "properties": {
                "pastConnections": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "scanned": {"type": "integer", "minimum": 0},
                        "inWindow": {"type": "integer", "minimum": 0},
                        "outsideWindow": {"type": "integer", "minimum": 0},
                        "undated": {"type": "integer", "minimum": 0},
                    },
                },
                "logs": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "scanned": {"type": "integer", "minimum": 0},
                        "outsideWindow": {"type": "integer", "minimum": 0},
                        "undated": {"type": "integer", "minimum": 0},
                        "directClientMatches": {"type": "integer", "minimum": 0},
                        "infrastructureMatches": {"type": "integer", "minimum": 0},
                    },
                },
            },
            "required": ["pastConnections", "logs"],
        },
        "controllerRequests": {"type": "integer", "minimum": 0},
        "requestLimit": {"type": "integer", "minimum": 1},
        "roamingSummary": {
            "type": "object",
            "properties": {
                "sessionCount": {"type": "integer", "minimum": 0},
                "uniqueApCount": {"type": "integer", "minimum": 0},
                "apTransitionCount": {"type": "integer", "minimum": 0},
                "shortSessionCount": {"type": "integer", "minimum": 0},
                "apTransitions": {"type": "array", "items": {"type": "object"}},
                "roamLogEvents": {"type": "array", "items": {"type": "object"}},
                "disconnectLogCount": {"type": "integer", "minimum": 0},
                "connectLogCount": {"type": "integer", "minimum": 0},
                "historyAvailable": {"type": "boolean"},
            },
            "required": [
                "sessionCount", "uniqueApCount", "apTransitionCount",
                "shortSessionCount", "apTransitions", "roamLogEvents",
                "disconnectLogCount", "connectLogCount", "historyAvailable",
            ],
        },
        "telemetryAvailability": {
            "type": "object",
            "properties": {
                "clientDetail": {"type": "string"},
                "activeClients": {"type": "string"},
                "pastConnections": {"type": "string"},
                "logs": {"type": "string"},
                "parentTelemetry": {"type": "string"},
            },
            "required": ["activeClients", "clientDetail", "pastConnections", "logs", "parentTelemetry"],
        },
        "findings": {"type": "array", "items": _DIAGNOSTIC_FINDING_SCHEMA},
        "nextSteps": {"type": "array", "items": {"type": "string"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "client", "pastConnections", "recentLogs", "infrastructureLogs", "roamingSummary",
        "timeWindow", "coverage", "controllerRequests", "requestLimit",
        "telemetryAvailability", "findings", "nextSteps", "warnings",
    ],
}


def _get_controller_status(client: OmadaClient) -> dict[str, Any]:
    """Read controller runtime status, redacted global settings summary, and site NTP state."""
    site = _site(client)
    warnings: list[str] = []
    status_raw, ok_status = try_api_result(
        client,
        "maintenance/controllerStatus",
        warnings,
        label="controller status",
    )
    setting_raw, ok_setting = try_api_result(
        client,
        "controller/setting",
        warnings,
        label="controller settings",
    )
    ntp_raw, ok_ntp = try_api_result(
        client,
        f"sites/{site.site_id}/setting/ntp",
        warnings,
        label="site NTP settings",
    )

    status_map = deep_redact(dict(status_raw)) if ok_status and isinstance(status_raw, dict) else {}
    setting_map = deep_redact(dict(setting_raw)) if ok_setting and isinstance(setting_raw, dict) else {}
    ntp_map = deep_redact(dict(ntp_raw)) if ok_ntp and isinstance(ntp_raw, dict) else None

    return {
        "controllerId": client.controller_id,
        "controllerVersion": getattr(client.auth_info, "controller_version", None),
        "controllerFamily": getattr(client.auth_info, "controller_family", None),
        "site": {"id": site.site_id, "name": site.name},
        "status": status_map,
        "settings": {
            "controllerName": setting_map.get("controllerName"),
            "general": setting_map.get("general"),
            "portSettings": setting_map.get("portSettings"),
            "mailServer": setting_map.get("mailServer"),
            "remoteLogging": setting_map.get("remoteLogging"),
            "radius": setting_map.get("radius"),
            "retain": setting_map.get("retain"),
            "autoBackup": setting_map.get("autoBackup"),
            "cloud": setting_map.get("cloud"),
        } if setting_map else {},
        "siteNtp": ntp_map,
        "warnings": warnings,
    }


_DIAGNOSE_WAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "wan": _WAN_STATUS_SCHEMA,
        "status": {"enum": ["offline", "degraded", "operational", "no_gateway", "unknown"]},
        "telemetryAvailability": {"type": "object"},
        "controllerRequests": {"type": "integer", "minimum": 0},
        "requestLimit": {"type": "integer", "minimum": 1},
        "vpnSummary": {"type": "object"},
        "recentLogs": {"type": "array", "items": {"type": "object"}},
        "findings": {"type": "array", "items": _DIAGNOSTIC_FINDING_SCHEMA},
        "nextSteps": {"type": "array", "items": {"type": "string"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "wan", "status", "telemetryAvailability", "controllerRequests", "requestLimit",
        "vpnSummary", "recentLogs", "findings", "nextSteps", "warnings",
    ],
}


_CONTROLLER_STATUS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "controllerId": {"type": ["string", "null"]},
        "controllerVersion": {"type": ["string", "null"]},
        "controllerFamily": {"type": ["string", "null"]},
        "site": {"type": "object"},
        "status": {"type": "object"},
        "settings": {"type": "object"},
        "siteNtp": {"type": ["object", "null"]},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["site", "status", "settings", "warnings"],
}

