"""Read-only continuous watch and Prometheus metrics exporter (Web API v2).

Reuses a SINGLE persistent authenticated :class:`OmadaClient` session across poll
iterations and scrapes so single-session/shared controller accounts are never evicted
by login-per-poll loops, while strictly enforcing controller read pacing (>= 0.8s).

Zero third-party dependencies — Python 3.10+ standard library only.
"""

from __future__ import annotations

import datetime
import http.server
import json
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, TextIO

from ._helpers import (
    as_float,
    as_int,
    collect_ap_radios_data,
    collect_wan_status_data,
    dhcp_pool_capacity,
    is_device_online,
    normalize_mac,
    try_paginate,
)
from .client import OmadaClient, OmadaError
from .config import Config

__all__ = [
    "MIN_POLL_INTERVAL_SECONDS",
    "collect_telemetry_snapshot",
    "diff_telemetry_snapshots",
    "export_metrics_once",
    "format_prometheus_metrics",
    "run_watch",
    "serve_metrics_http",
]

MIN_POLL_INTERVAL_SECONDS = 0.8


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prom_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _prom_labels(labels: Mapping[str, Any]) -> str:
    if not labels:
        return ""
    parts = [f'{k}="{_prom_escape(v)}"' for k, v in labels.items()]
    return "{" + ",".join(parts) + "}"


def _fetch_active_clients_safe(client: OmadaClient, site_id: str, warnings: List[str]) -> List[Dict[str, Any]]:
    rows, _, ok = try_paginate(
        client,
        f"sites/{site_id}/clients?filters.active=true",
        warnings,
        label="active clients",
    )
    if ok:
        return rows
    # Viewer accounts may receive -1007 on clients?filters.active=true; fall back to insight/clients.
    insight_rows, _, ok_in = try_paginate(
        client,
        f"sites/{site_id}/insight/clients",
        warnings,
        label="insight clients",
    )
    return insight_rows if ok_in else []


def collect_telemetry_snapshot(
    client: OmadaClient,
    *,
    weak_rssi_dbm: float = -75.0,
    retry_spike_pct: float = 15.0,
) -> Dict[str, Any]:
    """Collect a single secret-safe read-only telemetry snapshot from an authenticated session."""
    if client.site is None:
        client.authenticate()
    site = client.site
    assert site is not None  # authenticate() guarantees a resolved site

    with client.scoped_cache():
        return _collect_telemetry_snapshot_impl(
            client,
            site,
            weak_rssi_dbm=weak_rssi_dbm,
            retry_spike_pct=retry_spike_pct,
        )


def _collect_telemetry_snapshot_impl(
    client: OmadaClient,
    site: Any,
    *,
    weak_rssi_dbm: float = -75.0,
    retry_spike_pct: float = 15.0,
) -> Dict[str, Any]:
    warnings: List[str] = []
    raw_devices, _, _ = try_paginate(
        client, f"sites/{site.site_id}/devices", warnings, label="devices",
    )
    clients_raw = _fetch_active_clients_safe(client, site.site_id, warnings)
    lan_networks, _, _ = try_paginate(
        client, f"sites/{site.site_id}/setting/lan/networks", warnings, label="LAN networks",
    )

    devices: List[Dict[str, Any]] = []
    for dev in raw_devices:
        mac = normalize_mac(str(dev.get("mac") or ""))
        if not mac:
            continue
        devices.append({
            "mac": mac,
            "name": str(dev.get("name") or mac),
            "type": str(dev.get("type") or "").lower(),
            "model": str(dev.get("showModel") or dev.get("model") or ""),
            "online": is_device_online(dev),
            "clientCount": as_int(dev.get("clientCount"), 0),
        })

    wan = collect_wan_status_data(
        client, site, devices=raw_devices, include_speedtest=False, mask_wan_ip=True,
    )
    warnings.extend(wan.get("warnings") or [])

    ap_radios: List[Dict[str, Any]] = []
    for dev in raw_devices:
        if str(dev.get("type") or "").lower() != "ap" or not is_device_online(dev):
            continue
        try:
            ap_data = collect_ap_radios_data(
                client, site, dev, include_rf_scan=False, include_available_channels=False,
            )
            warnings.extend(ap_data.get("warnings") or [])
            ap_mac = ap_data.get("mac") or normalize_mac(str(dev.get("mac") or ""))
            ap_name = ap_data.get("name") or str(dev.get("name") or ap_mac)
            for rad in ap_data.get("radios") or []:
                tx_r = as_float(rad.get("txRetryRatePct"), 0.0) or 0.0
                rx_r = as_float(rad.get("rxRetryRatePct"), 0.0) or 0.0
                ap_radios.append({
                    "mac": ap_mac,
                    "name": ap_name,
                    "band": str(rad.get("band") or ""),
                    "channel": rad.get("channel"),
                    "txRetryRatePct": round(tx_r, 2),
                    "rxRetryRatePct": round(rx_r, 2),
                    "utilizationPct": round((as_float(rad.get("txUtilPct"), 0.0) or 0.0) + (as_float(rad.get("rxUtilPct"), 0.0) or 0.0), 2),
                    "interferencePct": rad.get("interferencePct"),
                    "retrySpike": (tx_r >= retry_spike_pct or rx_r >= retry_spike_pct),
                })
        except OmadaError as exc:
            warnings.append(f"AP radio telemetry skipped for {dev.get('name') or dev.get('mac')}: {exc}")

    # Client RSSI tracking + per-VLAN client counting (deduplicated by MAC)
    seen_macs: set[str] = set()
    active_count = 0
    wireless_clients: List[Dict[str, Any]] = []
    weak_clients: List[Dict[str, Any]] = []
    clients_by_net_id: Dict[str, int] = {}
    clients_by_vlan: Dict[int, int] = {}

    for row in clients_raw:
        cmac = normalize_mac(str(row.get("mac") or ""))
        if not cmac or cmac in seen_macs:
            continue
        seen_macs.add(cmac)
        active_count += 1

        nid = str(row.get("netId") or row.get("networkId") or "")
        if nid:
            clients_by_net_id[nid] = clients_by_net_id.get(nid, 0) + 1
        vid = as_int(row.get("vid", row.get("vlan")), -1)
        if vid > 0:
            clients_by_vlan[vid] = clients_by_vlan.get(vid, 0) + 1

        if bool(row.get("wireless")):
            raw_rssi = row.get("rssi")
            sig_lvl = row.get("signalLevel")
            rssi_dbm: Optional[float] = None
            signal_pct: Optional[float] = None
            if raw_rssi is not None:
                rv = as_float(raw_rssi)
                if rv is not None and rv < 0:
                    rssi_dbm = rv
            if rssi_dbm is None and sig_lvl is not None:
                sv = as_float(sig_lvl)
                if sv is not None:
                    if sv < 0:
                        rssi_dbm = sv
                    elif 0 <= sv <= 100:
                        signal_pct = sv
            is_weak = False
            if rssi_dbm is not None and rssi_dbm <= weak_rssi_dbm:
                is_weak = True
            elif rssi_dbm is None and signal_pct is not None and 0 < signal_pct <= 25:
                is_weak = True

            c_rec = {
                "mac": cmac,
                "name": str(row.get("name") or cmac),
                "ap": str(row.get("apName") or row.get("apMac") or ""),
                "band": str(row.get("radioId") if row.get("radioId") is not None else row.get("wifiMode") or ""),
                "ssid": str(row.get("ssid") or ""),
                "rssiDbm": rssi_dbm,
                "signalPct": signal_pct,
                "weak": is_weak,
            }
            wireless_clients.append(c_rec)
            if is_weak:
                weak_clients.append(c_rec)

    dhcp_pools: List[Dict[str, Any]] = []
    for net in lan_networks:
        dhcp = net.get("dhcpSettings")
        if not isinstance(dhcp, Mapping) or not dhcp.get("enable"):
            continue
        cap = dhcp_pool_capacity(dhcp)
        if cap <= 0:
            continue
        nid = str(net.get("id") or "")
        vlan = as_int(net.get("vlan"), 0)
        used = clients_by_net_id.get(nid, clients_by_vlan.get(vlan, 0))
        ratio = round(used / cap, 4) if cap > 0 else 0.0
        dhcp_pools.append({
            "netId": nid,
            "name": str(net.get("name") or f"VLAN{vlan}"),
            "vlan": vlan,
            "capacity": cap,
            "used": used,
            "utilizationRatio": ratio,
            "utilizationPct": round(ratio * 100.0, 2),
        })

    return {
        "timestamp": _utc_now_iso(),
        "site": {"siteId": site.site_id, "name": site.name},
        "devices": devices,
        "wan": {
            "hasGateway": bool(wan.get("hasGateway")),
            "wanMode": str(wan.get("wanMode") or "none"),
            "failoverConfigured": bool(wan.get("failoverConfigured")),
            "linkUpCount": as_int(wan.get("linkUpCount"), 0),
            "internetUpCount": as_int(wan.get("internetUpCount"), 0),
            "ports": [
                {
                    "port": p.get("port"),
                    "name": p.get("name"),
                    "linkUp": bool(p.get("linkUp")),
                    "internetUp": bool(p.get("internetUp")),
                    "latencyMs": p.get("latencyMs"),
                    "lossPct": p.get("lossPct"),
                    "ip": p.get("ip"),
                }
                for p in (wan.get("ports") or [])
            ],
        },
        "apRadios": ap_radios,
        "clients": {
            "activeTotal": active_count,
            "wirelessTotal": len(wireless_clients),
            "weakTotal": len(weak_clients),
            "wireless": wireless_clients,
            "weak": weak_clients,
        },
        "dhcpPools": dhcp_pools,
        "warnings": list(dict.fromkeys(w for w in warnings if w)),
    }


def diff_telemetry_snapshots(
    prev: Mapping[str, Any],
    curr: Mapping[str, Any],
    *,
    weak_rssi_dbm: float = -75.0,
    retry_spike_pct: float = 15.0,
) -> Dict[str, Any]:
    """Compute structured anomaly/transition diffs between consecutive snapshots."""
    changes: List[Dict[str, Any]] = []

    # 1. Device availability transitions
    prev_devs = {d["mac"]: d for d in prev.get("devices") or () if d.get("mac")}
    for d in curr.get("devices") or ():
        mac = d.get("mac")
        old = prev_devs.get(mac)
        if old and bool(old.get("online")) != bool(d.get("online")):
            changes.append({
                "category": "device_status",
                "target": d.get("name") or mac,
                "mac": mac,
                "before": {"online": old.get("online")},
                "after": {"online": d.get("online")},
            })

    # 2. WAN mode & port link/internet failover transitions
    p_wan = prev.get("wan") or {}
    c_wan = curr.get("wan") or {}
    if p_wan.get("wanMode") != c_wan.get("wanMode"):
        changes.append({
            "category": "wan_mode",
            "target": "wan",
            "before": {"wanMode": p_wan.get("wanMode")},
            "after": {"wanMode": c_wan.get("wanMode")},
        })
    p_ports = {str(p.get("port")): p for p in p_wan.get("ports") or ()}
    for port in c_wan.get("ports") or ():
        key = str(port.get("port"))
        old_p = p_ports.get(key)
        if old_p is None:
            continue
        if (bool(old_p.get("linkUp")) != bool(port.get("linkUp"))
                or bool(old_p.get("internetUp")) != bool(port.get("internetUp"))):
            changes.append({
                "category": "wan_failover",
                "target": port.get("name") or key,
                "port": port.get("port"),
                "before": {"linkUp": old_p.get("linkUp"), "internetUp": old_p.get("internetUp")},
                "after": {"linkUp": port.get("linkUp"), "internetUp": port.get("internetUp")},
            })

    # 3. AP TX/RX retry spike transitions
    p_radios = {(r.get("mac"), r.get("band")): r for r in prev.get("apRadios") or ()}
    for rad in curr.get("apRadios") or ():
        key = (rad.get("mac"), rad.get("band"))
        old_r = p_radios.get(key)
        was_spike = bool(old_r.get("retrySpike")) if old_r else False
        now_spike = bool(rad.get("retrySpike"))
        if now_spike != was_spike or (
            now_spike and old_r and (
                abs((rad.get("txRetryRatePct") or 0) - (old_r.get("txRetryRatePct") or 0)) >= 5.0
                or abs((rad.get("rxRetryRatePct") or 0) - (old_r.get("rxRetryRatePct") or 0)) >= 5.0
            )
        ):
            changes.append({
                "category": "ap_retry_spike",
                "target": f"{rad.get('name')} ({rad.get('band')})",
                "mac": rad.get("mac"),
                "band": rad.get("band"),
                "thresholdPct": retry_spike_pct,
                "before": {
                    "txRetryRatePct": old_r.get("txRetryRatePct") if old_r else None,
                    "rxRetryRatePct": old_r.get("rxRetryRatePct") if old_r else None,
                    "retrySpike": was_spike,
                },
                "after": {
                    "txRetryRatePct": rad.get("txRetryRatePct"),
                    "rxRetryRatePct": rad.get("rxRetryRatePct"),
                    "retrySpike": now_spike,
                },
            })

    # 4. Weak-client RSSI trends
    p_wireless = {c["mac"]: c for c in (prev.get("clients") or {}).get("wireless") or () if c.get("mac")}
    for cli in (curr.get("clients") or {}).get("wireless") or ():
        mac = cli.get("mac")
        old_c = p_wireless.get(mac)
        was_weak = bool(old_c.get("weak")) if old_c else False
        now_weak = bool(cli.get("weak"))
        old_rssi = old_c.get("rssiDbm") if old_c else None
        now_rssi = cli.get("rssiDbm")
        significant_drop = (
            old_rssi is not None and now_rssi is not None and now_rssi <= weak_rssi_dbm and (old_rssi - now_rssi) >= 6.0
        )
        if now_weak != was_weak or significant_drop:
            changes.append({
                "category": "weak_client_rssi",
                "target": cli.get("name") or mac,
                "mac": mac,
                "ap": cli.get("ap"),
                "thresholdDbm": weak_rssi_dbm,
                "before": {"weak": was_weak, "rssiDbm": old_rssi, "signalPct": old_c.get("signalPct") if old_c else None},
                "after": {"weak": now_weak, "rssiDbm": now_rssi, "signalPct": cli.get("signalPct")},
            })

    # 5. DHCP pool utilization shifts / high-water crossings
    p_pools = {p["netId"] or str(p["vlan"]): p for p in prev.get("dhcpPools") or ()}
    for pool in curr.get("dhcpPools") or ():
        key = pool["netId"] or str(pool["vlan"])
        old_pool = p_pools.get(key)
        old_pct = old_pool.get("utilizationPct", 0.0) if old_pool else 0.0
        now_pct = pool.get("utilizationPct", 0.0)
        crossed_high = (old_pct < 80.0 <= now_pct) or (old_pct >= 80.0 > now_pct)
        large_shift = old_pool is not None and abs(now_pct - old_pct) >= 10.0
        if crossed_high or large_shift:
            changes.append({
                "category": "dhcp_pool_utilization",
                "target": pool.get("name"),
                "vlan": pool.get("vlan"),
                "before": {"used": old_pool.get("used") if old_pool else None, "utilizationPct": old_pct},
                "after": {"used": pool.get("used"), "capacity": pool.get("capacity"), "utilizationPct": now_pct},
            })

    return {
        "event": "diff" if changes else "heartbeat",
        "timestamp": curr.get("timestamp"),
        "changeCount": len(changes),
        "changes": changes,
    }


def format_prometheus_metrics(snapshot: Mapping[str, Any]) -> str:
    """Render a telemetry snapshot as Prometheus text exposition format v0.0.4."""
    lines: List[str] = []
    site = snapshot.get("site") or {}
    site_name = str(site.get("name") or "")

    def _add_header(metric: str, help_text: str, mtype: str = "gauge") -> None:
        lines.append(f"# HELP {metric} {help_text}")
        lines.append(f"# TYPE {metric} {mtype}")

    _add_header("omada_up", "Whether the Omada telemetry snapshot succeeded (1 = up).")
    lines.append(f'omada_up{_prom_labels({"site": site_name})} 1')

    _add_header("omada_device_up", "Adopted Omada device online state (1 = online, 0 = offline).")
    for d in snapshot.get("devices") or ():
        lbl = _prom_labels({"mac": d.get("mac"), "name": d.get("name"), "type": d.get("type")})
        lines.append(f"omada_device_up{lbl} {1 if d.get('online') else 0}")

    _add_header("omada_device_clients", "Client count reported per adopted Omada device.")
    for d in snapshot.get("devices") or ():
        lbl = _prom_labels({"mac": d.get("mac"), "name": d.get("name"), "type": d.get("type")})
        lines.append(f"omada_device_clients{lbl} {as_int(d.get('clientCount'), 0)}")

    wan = snapshot.get("wan") or {}
    ports = wan.get("ports") or ()
    _add_header("omada_wan_link_up", "WAN port physical link state (1 = up, 0 = down).")
    for p in ports:
        lbl = _prom_labels({"port": str(p.get("port")), "name": p.get("name")})
        lines.append(f"omada_wan_link_up{lbl} {1 if p.get('linkUp') else 0}")

    _add_header("omada_wan_internet_up", "WAN port internet health-check state (1 = online, 0 = offline).")
    for p in ports:
        lbl = _prom_labels({"port": str(p.get("port")), "name": p.get("name")})
        lines.append(f"omada_wan_internet_up{lbl} {1 if p.get('internetUp') else 0}")

    _add_header("omada_wan_failover_active", "Whether WAN is currently configured in failover mode (1 = yes).")
    lines.append(
        f'omada_wan_failover_active{_prom_labels({"mode": wan.get("wanMode", "none")})} '
        f'{1 if wan.get("failoverConfigured") else 0}'
    )

    lat_ports = [p for p in ports if p.get("latencyMs") is not None]
    if lat_ports:
        _add_header("omada_wan_latency_ms", "Measured WAN health-check latency in milliseconds.")
        for p in lat_ports:
            lbl = _prom_labels({"port": str(p.get("port")), "name": p.get("name")})
            lines.append(f"omada_wan_latency_ms{lbl} {p['latencyMs']}")

    loss_ports = [p for p in ports if p.get("lossPct") is not None]
    if loss_ports:
        _add_header("omada_wan_packet_loss_pct", "Measured WAN packet loss percentage.")
        for p in loss_ports:
            lbl = _prom_labels({"port": str(p.get("port")), "name": p.get("name")})
            lines.append(f"omada_wan_packet_loss_pct{lbl} {p['lossPct']}")

    radios = snapshot.get("apRadios") or ()
    _add_header("omada_ap_radio_tx_retry_rate_pct", "AP radio TX retry rate percentage.")
    for r in radios:
        lbl = _prom_labels({"mac": r.get("mac"), "name": r.get("name"), "band": r.get("band")})
        lines.append(f"omada_ap_radio_tx_retry_rate_pct{lbl} {r.get('txRetryRatePct', 0.0)}")

    _add_header("omada_ap_radio_rx_retry_rate_pct", "AP radio RX retry rate percentage.")
    for r in radios:
        lbl = _prom_labels({"mac": r.get("mac"), "name": r.get("name"), "band": r.get("band")})
        lines.append(f"omada_ap_radio_rx_retry_rate_pct{lbl} {r.get('rxRetryRatePct', 0.0)}")

    _add_header("omada_ap_radio_utilization_pct", "AP radio total channel utilization percentage (TX+RX).")
    for r in radios:
        lbl = _prom_labels({"mac": r.get("mac"), "name": r.get("name"), "band": r.get("band")})
        lines.append(f"omada_ap_radio_utilization_pct{lbl} {r.get('utilizationPct', 0.0)}")

    clients = snapshot.get("clients") or {}
    _add_header("omada_clients_active_total", "Total active clients in the Omada site.")
    lines.append(f'omada_clients_active_total{_prom_labels({"site": site_name})} {as_int(clients.get("activeTotal"), 0)}')

    _add_header("omada_weak_clients_total", "Wireless clients currently below the weak-signal threshold.")
    lines.append(f'omada_weak_clients_total{_prom_labels({"site": site_name})} {as_int(clients.get("weakTotal"), 0)}')

    rssi_clients = [c for c in (clients.get("wireless") or ()) if c.get("rssiDbm") is not None]
    if rssi_clients:
        _add_header("omada_client_rssi_dbm", "Wireless client RSSI in dBm.")
        for c in rssi_clients:
            lbl = _prom_labels({"mac": c.get("mac"), "name": c.get("name"), "ap": c.get("ap"), "band": c.get("band")})
            lines.append(f"omada_client_rssi_dbm{lbl} {c['rssiDbm']}")

    sig_clients = [c for c in (clients.get("wireless") or ()) if c.get("signalPct") is not None]
    if sig_clients:
        _add_header("omada_client_signal_pct", "Wireless client signal strength percentage (0-100).")
        for c in sig_clients:
            lbl = _prom_labels({"mac": c.get("mac"), "name": c.get("name"), "ap": c.get("ap"), "band": c.get("band")})
            lines.append(f"omada_client_signal_pct{lbl} {c['signalPct']}")

    pools = snapshot.get("dhcpPools") or ()
    _add_header("omada_dhcp_pool_capacity", "Configured DHCP pool capacity per LAN/VLAN.")
    for p in pools:
        lbl = _prom_labels({"net_id": p.get("netId"), "name": p.get("name"), "vlan": str(p.get("vlan"))})
        lines.append(f"omada_dhcp_pool_capacity{lbl} {as_int(p.get('capacity'), 0)}")

    _add_header("omada_dhcp_pool_used", "Observed active clients mapped to each DHCP-enabled LAN/VLAN.")
    for p in pools:
        lbl = _prom_labels({"net_id": p.get("netId"), "name": p.get("name"), "vlan": str(p.get("vlan"))})
        lines.append(f"omada_dhcp_pool_used{lbl} {as_int(p.get('used'), 0)}")

    _add_header("omada_dhcp_pool_utilization_ratio", "Observed DHCP pool utilization ratio (0.0 to 1.0+).")
    for p in pools:
        lbl = _prom_labels({"net_id": p.get("netId"), "name": p.get("name"), "vlan": str(p.get("vlan"))})
        lines.append(f"omada_dhcp_pool_utilization_ratio{lbl} {p.get('utilizationRatio', 0.0)}")

    return "\n".join(lines) + "\n"


def _emit_line(stream: TextIO, payload: Mapping[str, Any]) -> None:
    stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
    stream.flush()


def run_watch(
    config: Config,
    *,
    interval: float = 30.0,
    iterations: int = 0,
    out: Optional[TextIO] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    client_factory: Optional[Callable[[Config], OmadaClient]] = None,
    weak_rssi_dbm: float = -75.0,
    retry_spike_pct: float = 15.0,
) -> int:
    """Poll telemetry on a single persistent session and emit structured JSON diffs."""
    stream = out if out is not None else sys.stdout
    eff_interval = max(MIN_POLL_INTERVAL_SECONDS, float(interval), float(config.min_interval))
    client = (client_factory or OmadaClient)(config)
    client.authenticate()

    prev: Optional[Dict[str, Any]] = None
    tick = 0
    while True:
        snap = collect_telemetry_snapshot(
            client, weak_rssi_dbm=weak_rssi_dbm, retry_spike_pct=retry_spike_pct,
        )
        tick += 1
        if prev is None:
            _emit_line(stream, {
                "event": "snapshot",
                "iteration": tick,
                "pollIntervalSeconds": eff_interval,
                **snap,
            })
        else:
            diff_evt = diff_telemetry_snapshots(
                prev, snap, weak_rssi_dbm=weak_rssi_dbm, retry_spike_pct=retry_spike_pct,
            )
            diff_evt["iteration"] = tick
            _emit_line(stream, diff_evt)
        prev = snap

        if iterations > 0 and tick >= iterations:
            return 0
        sleep_fn(eff_interval)


def export_metrics_once(
    config: Config,
    *,
    out: Optional[TextIO] = None,
    client_factory: Optional[Callable[[Config], OmadaClient]] = None,
    weak_rssi_dbm: float = -75.0,
    retry_spike_pct: float = 15.0,
) -> int:
    """Authenticate once, capture a telemetry snapshot, and write Prometheus metrics."""
    stream = out if out is not None else sys.stdout
    client = (client_factory or OmadaClient)(config)
    client.authenticate()
    snap = collect_telemetry_snapshot(
        client, weak_rssi_dbm=weak_rssi_dbm, retry_spike_pct=retry_spike_pct,
    )
    stream.write(format_prometheus_metrics(snap))
    stream.flush()
    return 0


def serve_metrics_http(
    config: Config,
    *,
    host: str = "127.0.0.1",
    port: int = 9108,
    min_scrape_interval: float = 5.0,
    client_factory: Optional[Callable[[Config], OmadaClient]] = None,
    weak_rssi_dbm: float = -75.0,
    retry_spike_pct: float = 15.0,
) -> http.server.ThreadingHTTPServer:
    """Create and return an HTTP server serving ``/metrics`` using one persistent session."""
    client = (client_factory or OmadaClient)(config)
    client.authenticate()
    cache_ttl = max(MIN_POLL_INTERVAL_SECONDS, float(min_scrape_interval), float(config.min_interval))
    lock = threading.Lock()
    state: Dict[str, Any] = {"ts": 0.0, "body": b""}

    def _render() -> bytes:
        with lock:
            now = time.monotonic()
            if not state["body"] or (now - state["ts"]) >= cache_ttl:
                snap = collect_telemetry_snapshot(
                    client, weak_rssi_dbm=weak_rssi_dbm, retry_spike_pct=retry_spike_pct,
                )
                state["body"] = format_prometheus_metrics(snap).encode("utf-8")
                state["ts"] = time.monotonic()
            return state["body"]

    class _MetricsHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] == "/healthz":
                body = b"ok\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.split("?", 1)[0] != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            try:
                body = _render()
            except OmadaError as exc:
                err_body = f"# ERROR: {exc}\n".encode("utf-8")
                self.send_response(503)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(err_body)))
                self.end_headers()
                self.wfile.write(err_body)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return http.server.ThreadingHTTPServer((host, int(port)), _MetricsHandler)
