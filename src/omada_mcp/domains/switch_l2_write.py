"""Write domain module: switch_l2_write (Phase B Switch LAGs, Global L2, Port Mirroring)."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import as_int, as_mapping, deep_redact, resolve_device_detail
from ._device_helpers import collect_switch_ports_data
from ._write_common import (
    _committed_result,
    _delete_entity,
    _dry_run_result,
    _field_diff,
    _normalize_mac,
    _require_confirm,
    _resolve_by_id_or_name,
    _site,
    _unwrap_rows,
)
from ._write_fetchers import _fetch_lan_profiles, _fetch_switch_lags, _omada_mac
from .switch_write import _build_switch_port_patch

_STP_MODE_MAP: dict[str, int] = {
    "0": 0,
    "off": 0,
    "disable": 0,
    "disabled": 0,
    "1": 1,
    "stp": 1,
    "2": 2,
    "rstp": 2,
    "3": 3,
    "mstp": 3,
}


def _parse_lag_type(raw: Any, dev_cap: Mapping[str, Any]) -> int:
    lag_cap = as_mapping(dev_cap.get("lagCap"))
    mod_support = bool(lag_cap.get("lacpModSupport", False))
    if isinstance(raw, int) and not isinstance(raw, bool) and raw in (1, 2, 3, 4):
        return raw
    key = str(raw or "static").strip().lower()
    if key in ("1", "static"):
        return 1
    if key in ("2", "lacp"):
        return 3 if mod_support else 2
    if key in ("3", "lacp_active", "lacp-active", "active"):
        return 3
    if key in ("4", "lacp_passive", "lacp-passive", "passive"):
        return 4
    raise OmadaError(
        f"invalid lagType {raw!r}",
        hint="valid values: 'static' (1), 'lacp' (2), 'lacp_active' (3), or 'lacp_passive' (4)",
    )


def _fetch_raw_port(client: OmadaClient, site_id: str, dev_mac: str, port: int) -> dict[str, Any]:
    try:
        detail = client.api_result(f"sites/{site_id}/switches/{dev_mac}/ports/{port}")
        if isinstance(detail, Mapping) and detail.get("port") is not None:
            return dict(detail)
    except OmadaError:
        pass
    rows = _unwrap_rows(client.api_result(f"sites/{site_id}/switches/{dev_mac}/ports"))
    found = next((dict(r) for r in rows if as_int(r.get("port"), 0) == port), None)
    if found is None:
        raise OmadaError(f"port {port} was not found on switch {dev_mac}")
    return found


def _assert_ports_safe_for_l2(
    norm_mac: str,
    port_nums: Sequence[int],
    ports_data: Mapping[str, Any],
    *,
    action_label: str,
    allow_uplink: bool,
    warnings: list[str],
) -> None:
    by_port = {
        as_int(p.get("port"), 0): p
        for p in (ports_data.get("ports") or [])
        if isinstance(p, Mapping)
    }
    reasons: list[str] = []
    for pno in port_nums:
        pinfo = by_port.get(pno)
        if pinfo is None:
            raise OmadaError(f"port {pno} does not exist on switch {norm_mac}")
        if pinfo.get("isUplink"):
            reasons.append(f"port {pno} is an uplink port")
        if pinfo.get("carriesController"):
            reasons.append(f"port {pno} carries controller/MCP host traffic")
    if reasons:
        if not allow_uplink:
            raise OmadaError(
                f"Refusing {action_label} on {norm_mac}: {'; '.join(reasons)}",
                hint="Pass allowUplinkMutation=True only when an out-of-band management path is available.",
            )
        warnings.append(f"ANTI-STRANDING GUARD BYPASSED (allowUplinkMutation=True): {'; '.join(reasons)}.")


def upsert_switch_lag(
    client: OmadaClient,
    mac: str,
    lagId: int,
    ports: Sequence[int],
    lagType: Any = "static",
    name: str | None = None,
    profileId: str | None = None,
    profileName: str | None = None,
    allowUplinkMutation: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a switch LAG / LACP port-channel group (switches/{MAC}/lags or port aggregation)."""
    if not isinstance(lagId, int) or isinstance(lagId, bool) or not (1 <= lagId <= 64):
        raise OmadaError(f"lagId must be a positive integer (1..64), got {lagId!r}")
    if not isinstance(ports, Sequence) or isinstance(ports, (str, bytes)) or len(ports) < 2:
        raise OmadaError("ports must contain at least 2 distinct switch port numbers to form a LAG")
    clean_ports: list[int] = []
    for p in ports:
        if not isinstance(p, int) or isinstance(p, bool) or p <= 0:
            raise OmadaError(f"invalid switch port {p!r} in ports")
        if p not in clean_ports:
            clean_ports.append(p)
    if len(clean_ports) < 2:
        raise OmadaError("ports must contain at least 2 distinct port numbers")

    site = _site(client)
    sw = resolve_device_detail(client, site, mac, expected_type="switch")
    norm_mac = _normalize_mac(str(sw.get("mac") or mac))
    dev_mac = _omada_mac(norm_mac)
    target_id = f"{norm_mac}:lag:{lagId}"
    _require_confirm("upsert_switch_lag", target_id, dryRun, confirm)

    dev_cap = as_mapping(sw.get("devCap"))
    max_lag_num = as_int(dev_cap.get("maxLagNum"), 0)
    max_lag_mem = as_int(dev_cap.get("maxLagMember"), 0)
    if max_lag_num and lagId > max_lag_num:
        raise OmadaError(f"lagId {lagId} exceeds switch maxLagNum ({max_lag_num})")
    if max_lag_mem and len(clean_ports) > max_lag_mem:
        raise OmadaError(f"member count {len(clean_ports)} exceeds switch maxLagMember ({max_lag_mem})")

    ports_data = collect_switch_ports_data(client, site, sw, include_cable_test=False)
    warnings: list[str] = []
    _assert_ports_safe_for_l2(
        norm_mac,
        clean_ports,
        ports_data,
        action_label="LAG configuration",
        allow_uplink=allowUplinkMutation,
        warnings=warnings,
    )

    lags = _fetch_switch_lags(client, site, dev_mac, sw_detail=sw)
    existing_lag = next((dict(r) for r in lags if as_int(r.get("lagId"), -1) == lagId), None)

    resolved_profile_id: str | None = None
    if profileId is not None or profileName is not None:
        profiles = _fetch_lan_profiles(client, site)
        prof = _resolve_by_id_or_name(
            profiles,
            str(profileId if profileId is not None else profileName),
            label="port profile",
        )
        resolved_profile_id = str(prof.get("id") or "")

    type_code = _parse_lag_type(lagType, dev_cap)
    primary_port = clean_ports[0]
    raw_primary = _fetch_raw_port(client, site.site_id, dev_mac, primary_port)

    # Reject hijacking ports currently dedicated to another LAG or active port mirror.
    for lg in lags:
        other_lag_id = as_int(lg.get("lagId"), -1)
        if other_lag_id != lagId:
            other_ports = {as_int(x, 0) for x in (lg.get("ports") or []) if isinstance(x, (int, str))}
            for pno in clean_ports:
                if pno in other_ports:
                    raise OmadaError(
                        f"port {pno} already belongs to LAG {other_lag_id}; remove it before adding to LAG {lagId}"
                    )

    for pno in clean_ports:
        raw_p = raw_primary if pno == primary_port else _fetch_raw_port(client, site.site_id, dev_mac, pno)
        op = str(raw_p.get("operation") or "").lower()
        if op == "mirroring":
            raise OmadaError(f"port {pno} is currently configured for port mirroring; clear mirroring first")
        p_lag = as_mapping(raw_p.get("lagSetting")).get("lagId")
        if op == "aggregating" and p_lag is not None and as_int(p_lag, -1) != lagId:
            raise OmadaError(f"port {pno} already belongs to LAG {p_lag}; remove it before adding to LAG {lagId}")

    lag_name = str(name).strip() if name is not None and str(name).strip() else str(
        (existing_lag or {}).get("name") or f"LAG {lagId}"
    )
    profile_id_val: str = resolved_profile_id or str((existing_lag or raw_primary).get("profileId") or "")
    after_summary: dict[str, Any] = {
        "mac": norm_mac,
        "lagId": lagId,
        "name": lag_name,
        "lagType": type_code,
        "ports": clean_ports,
        "profileId": profile_id_val,
    }
    diff = _field_diff(deep_redact(existing_lag) if existing_lag else {}, after_summary, ["name", "lagType", "ports", "profileId"])

    if existing_lag is not None and sorted(existing_lag.get("ports") or []) == sorted(clean_ports):
        endpoint = f"sites/{site.site_id}/switches/{dev_mac}/lags/{lagId}"
        method = "PATCH"
        payload = _build_switch_port_patch(raw_primary, name=lag_name, profile_id=profile_id_val)
        payload["lagId"] = lagId
        payload["lagType"] = type_code
        payload["ports"] = clean_ports
    else:
        endpoint = f"sites/{site.site_id}/switches/{dev_mac}/ports/{primary_port}"
        method = "PATCH"
        payload = _build_switch_port_patch(raw_primary, name=lag_name, profile_id=profile_id_val)
        payload["operation"] = "aggregating"
        payload["lagSetting"] = {"lagId": lagId, "lagType": type_code, "ports": clean_ports}

    rollback = (
        {
            "tool": "upsert_switch_lag",
            "arguments": {
                "mac": norm_mac,
                "lagId": lagId,
                "ports": list(existing_lag.get("ports") or []),
                "lagType": existing_lag.get("lagType", 1),
                "name": existing_lag.get("name"),
                "allowUplinkMutation": allowUplinkMutation,
                "dryRun": True,
            },
        }
        if existing_lag is not None
        else {
            "tool": "delete_switch_lag",
            "arguments": {"mac": norm_mac, "lagId": lagId, "allowUplinkMutation": allowUplinkMutation, "dryRun": True},
        }
    )

    if dryRun:
        return _dry_run_result(
            tool_name="upsert_switch_lag",
            target_id=target_id,
            before=deep_redact(existing_lag) if existing_lag else None,
            after=after_summary,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    def _read_back() -> dict[str, Any] | None:
        now_lags = _fetch_switch_lags(client, site, dev_mac)
        row = next((dict(r) for r in now_lags if as_int(r.get("lagId"), -1) == lagId), None)
        if row is not None:
            return deep_redact(row)
        p_now = _fetch_raw_port(client, site.site_id, dev_mac, primary_port)
        if str(p_now.get("operation") or "").lower() == "aggregating":
            ls = as_mapping(p_now.get("lagSetting"))
            if as_int(ls.get("lagId"), -1) == lagId:
                return deep_redact({
                    "lagId": lagId,
                    "name": lag_name,
                    "lagType": ls.get("lagType", type_code),
                    "ports": ls.get("ports") or clean_ports,
                })
        return None

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, f"LAG {lagId} not found on switch {norm_mac} after write"
        return True, None

    write_res = client.write(
        endpoint,
        method=method,
        data=payload,
        tool_name="upsert_switch_lag",
        target=target_id,
        before=deep_redact(existing_lag) if existing_lag else None,
        snapshot_payload={"action": "update" if existing_lag else "create", "mac": dev_mac, "lagId": lagId, "lag": copy.deepcopy(existing_lag)},
        read_back=_read_back,
        verify_fn=_verify,
        fields_changed=sorted(diff.keys()) or ["lagSetting"],
    )
    return _committed_result(
        tool_name="upsert_switch_lag",
        target_id=target_id,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def delete_switch_lag(
    client: OmadaClient,
    mac: str,
    lagId: int,
    allowUplinkMutation: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a switch LAG / LACP port-channel group (DELETE switches/{MAC}/lags/{lagId})."""
    if not isinstance(lagId, int) or isinstance(lagId, bool) or lagId <= 0:
        raise OmadaError(f"lagId must be a positive integer, got {lagId!r}")
    site = _site(client)
    sw = resolve_device_detail(client, site, mac, expected_type="switch")
    norm_mac = _normalize_mac(str(sw.get("mac") or mac))
    dev_mac = _omada_mac(norm_mac)
    lags = _fetch_switch_lags(client, site, dev_mac, sw_detail=sw)
    target_lag = next((dict(r) for r in lags if as_int(r.get("lagId"), -1) == lagId), None)
    if target_lag is None:
        raise OmadaError(f"LAG {lagId} was not found on switch {norm_mac}")

    lag_ports = [as_int(p, 0) for p in (target_lag.get("ports") or []) if isinstance(p, (int, str))]
    ports_data = collect_switch_ports_data(client, site, sw, include_cable_test=False)
    warnings: list[str] = []
    if lag_ports:
        _assert_ports_safe_for_l2(
            norm_mac,
            lag_ports,
            ports_data,
            action_label=f"deleting LAG {lagId}",
            allow_uplink=allowUplinkMutation,
            warnings=warnings,
        )

    rollback = (
        {
            "tool": "upsert_switch_lag",
            "arguments": {
                "mac": norm_mac,
                "lagId": lagId,
                "ports": lag_ports,
                "lagType": target_lag.get("lagType", 1),
                "name": target_lag.get("name"),
                "allowUplinkMutation": allowUplinkMutation,
                "dryRun": True,
            },
        }
        if len(lag_ports) >= 2
        else None
    )
    target_id = f"{norm_mac}:lag:{lagId}"
    return _delete_entity(
        client,
        tool_name="delete_switch_lag",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/switches/{dev_mac}/lags/{lagId}",
        before=deep_redact(target_lag),
        snapshot_payload={"action": "delete", "mac": dev_mac, "lagId": lagId, "lag": copy.deepcopy(target_lag)},
        fetch_all=lambda: _fetch_switch_lags(client, site, dev_mac),
        match_fn=lambda row: as_int(row.get("lagId"), -1) == lagId,
        rollback=rollback,
        warnings=warnings,
        dry_run=dryRun,
        confirm=confirm,
        label="lag",
    )


def update_switch_global_features(
    client: OmadaClient,
    mac: str,
    stpMode: Any | None = None,
    stpPriority: int | None = None,
    helloTime: int | None = None,
    maxAge: int | None = None,
    forwardDelay: int | None = None,
    txHoldCount: int | None = None,
    maxHops: int | None = None,
    loopbackDetectEnable: bool | None = None,
    jumboEnable: bool | None = None,
    jumbo: int | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Update switch global L2 settings: STP/RSTP/MSTP mode/timers, loopback detection, and jumbo MTU."""
    if all(
        v is None
        for v in (
            stpMode, stpPriority, helloTime, maxAge, forwardDelay,
            txHoldCount, maxHops, loopbackDetectEnable, jumboEnable, jumbo,
        )
    ):
        raise OmadaError("specify at least one switch global feature field to update")

    site = _site(client)
    sw = resolve_device_detail(client, site, mac, expected_type="switch")
    norm_mac = _normalize_mac(str(sw.get("mac") or mac))
    dev_mac = _omada_mac(norm_mac)
    _require_confirm("update_switch_global_features", norm_mac, dryRun, confirm)

    is_es = bool(sw.get("es", False))
    before_summary = {
        "mac": norm_mac,
        "stp": sw.get("stp"),
        "priority": sw.get("priority"),
        "helloTime": sw.get("helloTime"),
        "maxAge": sw.get("maxAge"),
        "forwardDelay": sw.get("forwardDelay"),
        "txHoldCount": sw.get("txHoldCount"),
        "maxHops": sw.get("maxHops"),
        "loopbackDetectEnable": bool(sw.get("loopbackDetectEnable", False)),
        "jumbo": sw.get("jumbo"),
        "jumboEnable": sw.get("jumboEnable", bool(as_int(sw.get("jumbo"), 1518) > 1518)),
    }

    updates_general = any(v is not None for v in (jumboEnable, jumbo))
    updates_services = any(
        v is not None
        for v in (stpMode, stpPriority, helloTime, maxAge, forwardDelay, txHoldCount, maxHops, loopbackDetectEnable)
    )

    warnings: list[str] = []
    if stpPriority is not None and (not (0 <= int(stpPriority) <= 61440) or int(stpPriority) % 4096 != 0):
        raise OmadaError(f"stpPriority {stpPriority!r} must be a multiple of 4096 between 0 and 61440")
    if jumbo is not None and not (1518 <= int(jumbo) <= 9216):
        raise OmadaError(f"jumbo MTU {jumbo!r} must be between 1518 and 9216")
    if helloTime is not None and not (1 <= int(helloTime) <= 10):
        raise OmadaError(f"helloTime {helloTime!r} must be between 1 and 10")
    if maxAge is not None and not (6 <= int(maxAge) <= 40):
        raise OmadaError(f"maxAge {maxAge!r} must be between 6 and 40")
    if forwardDelay is not None and not (4 <= int(forwardDelay) <= 30):
        raise OmadaError(f"forwardDelay {forwardDelay!r} must be between 4 and 30")
    if txHoldCount is not None and not (1 <= int(txHoldCount) <= 20):
        raise OmadaError(f"txHoldCount {txHoldCount!r} must be between 1 and 20")
    if maxHops is not None and not (1 <= int(maxHops) <= 40):
        raise OmadaError(f"maxHops {maxHops!r} must be between 1 and 40")

    stp_val = as_int(before_summary.get("stp"), 2)
    if stpMode is not None:
        skey = str(stpMode).strip().lower()
        if skey not in _STP_MODE_MAP:
            raise OmadaError(f"invalid stpMode {stpMode!r}; expected 'off' (0), 'stp' (1), 'rstp' (2), or 'mstp' (3)")
        stp_val = _STP_MODE_MAP[skey]
        if stp_val == 0:
            warnings.append("Disabling spanning tree (STP=off) removes L2 loop protection; verify physical topology is loop-free.")

    prio_val = as_int(before_summary.get("priority"), 32768) if stpPriority is None else int(stpPriority)
    ht_val = as_int(before_summary.get("helloTime"), 2) if helloTime is None else int(helloTime)
    ma_val = as_int(before_summary.get("maxAge"), 20) if maxAge is None else int(maxAge)
    fd_val = as_int(before_summary.get("forwardDelay"), 15) if forwardDelay is None else int(forwardDelay)
    tx_val = as_int(before_summary.get("txHoldCount"), 5) if txHoldCount is None else int(txHoldCount)
    mh_val = as_int(before_summary.get("maxHops"), 20) if maxHops is None else int(maxHops)
    lb_val = (
        bool(before_summary.get("loopbackDetectEnable", False))
        if loopbackDetectEnable is None
        else bool(loopbackDetectEnable)
    )
    if 2 * (fd_val - 1) < ma_val or ma_val < 2 * (ht_val + 1):
        warnings.append(
            f"STP timer guideline check: 2*(forwardDelay-1)>={2*(fd_val-1)} vs maxAge={ma_val} vs 2*(helloTime+1)={2*(ht_val+1)}."
        )

    jumbo_val = as_int(before_summary.get("jumbo"), 1518) if jumbo is None else int(jumbo)
    jumbo_en = bool(before_summary.get("jumboEnable", False)) if jumboEnable is None else bool(jumboEnable)
    if jumbo is not None and jumboEnable is None:
        jumbo_en = jumbo_val > 1518

    after_summary = {
        "mac": norm_mac,
        "stp": stp_val,
        "priority": prio_val,
        "helloTime": ht_val,
        "maxAge": ma_val,
        "forwardDelay": fd_val,
        "txHoldCount": tx_val,
        "maxHops": mh_val,
        "loopbackDetectEnable": lb_val,
        "jumbo": jumbo_val,
        "jumboEnable": jumbo_en,
    }
    diff = _field_diff(before_summary, after_summary, [k for k in after_summary if k != "mac"])

    rollback = {
        "tool": "update_switch_global_features",
        "arguments": {
            "mac": norm_mac,
            "stpMode": before_summary.get("stp"),
            "stpPriority": before_summary.get("priority"),
            "helloTime": before_summary.get("helloTime"),
            "maxAge": before_summary.get("maxAge"),
            "forwardDelay": before_summary.get("forwardDelay"),
            "txHoldCount": before_summary.get("txHoldCount"),
            "maxHops": before_summary.get("maxHops"),
            "loopbackDetectEnable": before_summary.get("loopbackDetectEnable"),
            "jumboEnable": before_summary.get("jumboEnable"),
            "jumbo": before_summary.get("jumbo"),
            "dryRun": True,
        },
    }
    if dryRun:
        return _dry_run_result(
            tool_name="update_switch_global_features",
            target_id=norm_mac,
            before=before_summary,
            after=after_summary,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    snap_payload = {"mac": dev_mac, "es": is_es, "before": copy.deepcopy(before_summary), "raw": deep_redact(sw)}
    final_snap: str | None = None

    if updates_general:
        gen_ep = f"sites/{site.site_id}/switches/{'es/' if is_es else ''}{dev_mac}/config/general"
        gen_body: dict[str, Any] = {
            "name": str(sw.get("name") or norm_mac),
            "ledSetting": as_int(sw.get("ledSetting"), 2),
            "tagIds": list(sw.get("tagIds") or []),
            "jumbo": jumbo_val,
            "jumboEnable": jumbo_en,
        }
        wr_gen = client.write(
            gen_ep,
            method="PUT",
            data=gen_body,
            tool_name="update_switch_global_features",
            target=f"{norm_mac}:general",
            before=before_summary,
            snapshot_payload=snap_payload,
            fields_changed=["jumbo", "jumboEnable"],
        )
        final_snap = wr_gen["snapshot"]

    if updates_services:
        svc_ep = f"sites/{site.site_id}/switches/{dev_mac}/config/services"
        if is_es and lb_val and stp_val != 0:
            warnings.append(
                "Easy Smart switch forces stp=0 (off) while loopbackDetectEnable=True; pass loopbackDetectEnable=False to enable STP."
            )
        svc_body: dict[str, Any] = {
            "stp": 0 if (is_es and lb_val) else stp_val,
            "priority": prio_val,
            "helloTime": ht_val,
            "maxAge": ma_val,
            "forwardDelay": fd_val,
            "txHoldCount": tx_val,
            "maxHops": mh_val,
            "loopbackDetectEnable": lb_val,
        }
        if not is_es and isinstance(sw.get("snmp"), Mapping):
            svc_body["snmp"] = copy.deepcopy(dict(sw["snmp"]))
        wr_svc = client.write(
            svc_ep,
            method="PUT",
            data=svc_body,
            tool_name="update_switch_global_features",
            target=f"{norm_mac}:services",
            before=before_summary,
            snapshot_payload=snap_payload,
            fields_changed=["stp", "loopbackDetectEnable"],
        )
        final_snap = wr_svc["snapshot"]

    sw_after = resolve_device_detail(client, site, dev_mac, expected_type="switch")
    after_live = {
        "mac": norm_mac,
        "stp": sw_after.get("stp"),
        "priority": sw_after.get("priority"),
        "helloTime": sw_after.get("helloTime"),
        "maxAge": sw_after.get("maxAge"),
        "forwardDelay": sw_after.get("forwardDelay"),
        "txHoldCount": sw_after.get("txHoldCount"),
        "maxHops": sw_after.get("maxHops"),
        "loopbackDetectEnable": bool(sw_after.get("loopbackDetectEnable", False)),
        "jumbo": sw_after.get("jumbo"),
        "jumboEnable": sw_after.get("jumboEnable", bool(as_int(sw_after.get("jumbo"), 1518) > 1518)),
    }
    return _committed_result(
        tool_name="update_switch_global_features",
        target_id=norm_mac,
        before=before_summary,
        after=after_live,
        diff=diff,
        snapshot=final_snap,
        warnings=warnings,
        rollback=rollback,
    )


def set_switch_port_mirror(
    client: OmadaClient,
    mac: str,
    mirroringPort: int,
    mirroredPorts: Sequence[int],
    mirroredLags: Sequence[int] | None = None,
    allowUplinkMutation: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Configure or clear SPAN port mirroring on a switch analyzer port (operation='mirroring' or 'switching')."""
    if not isinstance(mirroringPort, int) or isinstance(mirroringPort, bool) or mirroringPort <= 0:
        raise OmadaError(f"mirroringPort must be a positive integer, got {mirroringPort!r}")
    if not isinstance(mirroredPorts, Sequence) or isinstance(mirroredPorts, (str, bytes)):
        raise OmadaError("mirroredPorts must be a list of source port integers (pass [] to clear mirroring)")

    clean_sources: list[int] = []
    for p in mirroredPorts:
        if not isinstance(p, int) or isinstance(p, bool) or p <= 0:
            raise OmadaError(f"invalid port {p!r} in mirroredPorts")
        if p == mirroringPort:
            raise OmadaError(f"mirroringPort {mirroringPort} cannot mirror itself")
        if p not in clean_sources:
            clean_sources.append(p)
    clean_lags = [int(lid) for lid in (mirroredLags or []) if isinstance(lid, int) and not isinstance(lid, bool) and lid > 0]

    site = _site(client)
    sw = resolve_device_detail(client, site, mac, expected_type="switch")
    norm_mac = _normalize_mac(str(sw.get("mac") or mac))
    dev_mac = _omada_mac(norm_mac)
    target_id = f"{norm_mac}:mirror:{mirroringPort}"
    _require_confirm("set_switch_port_mirror", target_id, dryRun, confirm)

    dev_cap = as_mapping(sw.get("devCap"))
    max_mirrored = as_int(dev_cap.get("maxMirroredPort"), 0)
    if max_mirrored and len(clean_sources) > max_mirrored:
        raise OmadaError(f"mirroredPorts count {len(clean_sources)} exceeds switch maxMirroredPort ({max_mirrored})")

    ports_data = collect_switch_ports_data(client, site, sw, include_cable_test=False)
    warnings: list[str] = []
    # Only configuring mirroring on the destination port isolates normal forwarding there.
    check_ports = [mirroringPort] if (clean_sources or clean_lags) else []
    if check_ports:
        _assert_ports_safe_for_l2(
            norm_mac,
            check_ports,
            ports_data,
            action_label="enabling port mirroring analyzer mode",
            allow_uplink=allowUplinkMutation,
            warnings=warnings,
        )

    raw_port = _fetch_raw_port(client, site.site_id, dev_mac, mirroringPort)
    before_mirrored_lags = [
        as_int(m.get("lagId"), 0) for m in (raw_port.get("mirroredLags") or []) if isinstance(m, Mapping)
    ]
    before_summary = {
        "mac": norm_mac,
        "mirroringPort": mirroringPort,
        "operation": str(raw_port.get("operation") or "switching"),
        "mirroredPorts": list(raw_port.get("mirroredPorts") or []),
        "mirroredLags": before_mirrored_lags,
    }
    target_op = "mirroring" if (clean_sources or clean_lags) else "switching"
    after_summary = {
        "mac": norm_mac,
        "mirroringPort": mirroringPort,
        "operation": target_op,
        "mirroredPorts": clean_sources,
        "mirroredLags": clean_lags,
    }
    diff = _field_diff(before_summary, after_summary, ["operation", "mirroredPorts", "mirroredLags"])

    payload = _build_switch_port_patch(raw_port)
    payload["operation"] = target_op
    if target_op == "mirroring":
        payload["mirroredPorts"] = clean_sources
        payload["mirroredLags"] = clean_lags

    rollback = {
        "tool": "set_switch_port_mirror",
        "arguments": {
            "mac": norm_mac,
            "mirroringPort": mirroringPort,
            "mirroredPorts": before_summary["mirroredPorts"] if before_summary["operation"] == "mirroring" else [],
            "mirroredLags": before_summary["mirroredLags"] if before_summary["operation"] == "mirroring" else [],
            "allowUplinkMutation": allowUplinkMutation,
            "dryRun": True,
        },
    }
    if dryRun:
        return _dry_run_result(
            tool_name="set_switch_port_mirror",
            target_id=target_id,
            before=before_summary,
            after=after_summary,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/switches/{dev_mac}/ports/{mirroringPort}"

    def _read_back() -> dict[str, Any]:
        p_now = _fetch_raw_port(client, site.site_id, dev_mac, mirroringPort)
        return {
            "mac": norm_mac,
            "mirroringPort": mirroringPort,
            "operation": str(p_now.get("operation") or "switching"),
            "mirroredPorts": list(p_now.get("mirroredPorts") or []),
            "mirroredLags": [
                as_int(m.get("lagId"), 0) for m in (p_now.get("mirroredLags") or []) if isinstance(m, Mapping)
            ],
        }

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, "mirror port read-back failed"
        if after_now.get("operation") != target_op:
            return False, f"expected operation={target_op!r}, got {after_now.get('operation')!r}"
        if target_op == "mirroring" and sorted(after_now.get("mirroredPorts") or []) != sorted(clean_sources):
            return False, "mirroredPorts did not persist cleanly"
        return True, None

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=payload,
        tool_name="set_switch_port_mirror",
        target=target_id,
        before=before_summary,
        snapshot_payload={"mac": dev_mac, "mirroringPort": mirroringPort, "rawPort": copy.deepcopy(raw_port)},
        read_back=_read_back,
        verify_fn=_verify,
        fields_changed=sorted(diff.keys()) or ["operation"],
    )
    return _committed_result(
        tool_name="set_switch_port_mirror",
        target_id=target_id,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )
