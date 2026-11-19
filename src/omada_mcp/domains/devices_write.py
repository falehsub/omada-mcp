"""Write domain module: devices_write."""

from __future__ import annotations

import copy
import time
import uuid
from collections.abc import Mapping
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import (
    CHANNEL_WIDTH_LABELS,
    TX_POWER_LEVEL_LABELS,
    as_int,
    as_mapping,
    resolve_raw_device,
)
from ._device_helpers import (
    _RADIO_ID_TO_BAND,
    collect_rf_scan_data,
    count_ap_clients_by_band,
    parse_rf_scan_payload,
    validate_ap_radio_change,
)
from ._write_common import (
    _BAND_TO_RADIO_ID,
    _DEV_ENDPOINT_PREFIX,
    _LED_MODES,
    _committed_result,
    _dry_run_result,
    _field_diff,
    _match_fields,
    _normalize_mac,
    _require_confirm,
    _resolve_by_id_or_name,
    _site,
)
from ._write_fetchers import _fetch_devices, _omada_mac, _require_gateway
from .clients_read import _fetch_client_rows


def update_device(
    client: OmadaClient,
    mac: str,
    name: str | None = None,
    ledSetting: Any = None,
    locate: bool | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Rename an adopted AP/switch/gateway, set LED mode, or toggle LED locator blink."""
    if name is None and ledSetting is None and locate is None:
        raise OmadaError("specify at least one of name, ledSetting, or locate")

    site = _site(client)
    devices = _fetch_devices(client, site)
    target_dev = _resolve_by_id_or_name(
        devices,
        mac,
        label="device",
        id_key="mac",
        name_key="name",
    )
    dev_mac = _omada_mac(str(target_dev["mac"]))
    norm_mac = _normalize_mac(dev_mac)
    _require_confirm("update_device", norm_mac, dryRun, confirm)

    dev_type = str(target_dev.get("type") or "").strip().lower()
    dev_prefix = _DEV_ENDPOINT_PREFIX.get(dev_type)
    if (name is not None or ledSetting is not None) and dev_prefix is None:
        raise OmadaError(f"unsupported device type {dev_type!r} for general settings PATCH")

    general_patch: dict[str, Any] = {}
    diff: dict[str, Any] = {}
    if name is not None:
        clean_name = str(name).strip()
        if not clean_name:
            raise OmadaError("device name must be non-empty")
        general_patch["name"] = clean_name
        diff["name"] = {"before": target_dev.get("name"), "after": clean_name}
    if ledSetting is not None:
        led_key = str(ledSetting).strip().lower()
        if led_key not in _LED_MODES:
            raise OmadaError(f"invalid ledSetting {ledSetting!r}; expected 'off' (0), 'on' (1), or 'use_site' (2)")
        led_val = _LED_MODES[led_key]
        general_patch["ledSetting"] = led_val
        diff["ledSetting"] = {"before": target_dev.get("ledSetting"), "after": led_val}
    if locate is not None:
        diff["locateEnable"] = {"before": target_dev.get("locateEnable"), "after": bool(locate)}

    before_summary = {
        "mac": target_dev.get("mac"),
        "name": target_dev.get("name"),
        "type": dev_type,
        "ledSetting": target_dev.get("ledSetting"),
        "locateEnable": target_dev.get("locateEnable"),
    }
    after_preview = {
        **before_summary,
        **general_patch,
        **({"locateEnable": bool(locate)} if locate is not None else {}),
    }

    if dryRun:
        return _dry_run_result(
            tool_name="update_device",
            target_id=norm_mac,
            before=before_summary,
            after=after_preview,
            diff=diff,
            warnings=[],
            rollback=None,
        )

    def _read_back_dev() -> dict[str, Any] | None:
        for d in _fetch_devices(client, site):
            if _normalize_mac(d.get("mac", "")) == norm_mac:
                return dict(d)
        return None

    last_res: dict[str, Any] | None = None
    if general_patch:
        def _verify_general(_b: Any, a: Any) -> tuple[bool, str | None]:
            if not isinstance(a, Mapping):
                return False, f"device {norm_mac} missing on read-back"
            return _match_fields(a, general_patch)

        last_res = client.write(
            f"sites/{site.site_id}/{dev_prefix}/{dev_mac}",
            method="PATCH",
            data=general_patch,
            tool_name="update_device",
            target=norm_mac,
            before=before_summary,
            snapshot_payload=target_dev,
            read_back=_read_back_dev,
            verify_fn=_verify_general,
            reauth_prepare=lambda: (_verify_general(None, _read_back_dev())[0], general_patch, before_summary),
            fields_changed=sorted(general_patch.keys()),
        )

    if locate is not None:
        loc_val = bool(locate)
        def _verify_loc(_b: Any, a: Any) -> tuple[bool, str | None]:
            if not isinstance(a, Mapping):
                return False, f"device {norm_mac} missing on read-back"
            return _match_fields(a, {"locateEnable": loc_val})

        last_res = client.write(
            f"sites/{site.site_id}/cmd/devices/{dev_mac}/locate",
            method="POST",
            data={"locateEnable": loc_val},
            tool_name="update_device",
            target=norm_mac,
            before=before_summary,
            snapshot_payload=target_dev,
            read_back=_read_back_dev,
            verify_fn=_verify_loc,
            reauth_prepare=lambda: (_verify_loc(None, _read_back_dev())[0], {"locateEnable": loc_val}, before_summary),
            fields_changed=["locateEnable"],
        )

    after_dev = (last_res or {}).get("after") or after_preview
    after_summary = {
        "mac": after_dev.get("mac"),
        "name": after_dev.get("name"),
        "type": dev_type,
        "ledSetting": after_dev.get("ledSetting"),
        "locateEnable": after_dev.get("locateEnable"),
    }
    return _committed_result(
        tool_name="update_device",
        target_id=norm_mac,
        before=before_summary,
        after=after_summary,
        diff=diff,
        snapshot=(last_res or {}).get("snapshot"),
        warnings=[],
        rollback=None,
    )


def reboot_device(
    client: OmadaClient,
    mac: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Reboot an adopted Omada device (``POST cmd/devices/{MAC}/reboot``)."""
    site = _site(client)
    devices = _fetch_devices(client, site)
    target_dev = _resolve_by_id_or_name(devices, mac, label="device", id_key="mac", name_key="name")
    dev_mac = _omada_mac(str(target_dev["mac"]))
    norm_mac = _normalize_mac(dev_mac)
    _require_confirm("reboot_device", norm_mac, dryRun, confirm)

    dev_type = str(target_dev.get("type") or "").lower()
    warnings = [
        f"disruptive operation: rebooting {dev_type or 'device'} {target_dev.get('name') or norm_mac!r} "
        "drops traffic during restart; confirm maintenance window before dryRun=false",
    ]
    if dev_type == "gateway":
        warnings.append("rebooting the gateway interrupts WAN internet access for the entire site")

    summary = {
        "mac": target_dev.get("mac"),
        "name": target_dev.get("name"),
        "type": dev_type,
        "model": target_dev.get("showModel") or target_dev.get("model"),
        "statusCategory": target_dev.get("statusCategory"),
    }
    diff = {"action": {"before": "running", "after": "reboot_requested"}}
    if dryRun:
        return _dry_run_result(
            tool_name="reboot_device",
            target_id=norm_mac,
            before=summary,
            after={**summary, "rebootTriggered": True},
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    write_res = client.write(
        f"sites/{site.site_id}/cmd/devices/{dev_mac}/reboot",
        method="POST",
        data={},
        tool_name="reboot_device",
        target=norm_mac,
        before=summary,
        snapshot_payload=target_dev,
        fields_changed=["reboot"],
    )
    return _committed_result(
        tool_name="reboot_device",
        target_id=norm_mac,
        before=write_res["before"],
        after={**summary, "rebootTriggered": True},
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )


def update_ap_radio(
    client: OmadaClient,
    deviceMac: str,
    band: str,
    enabled: bool | None = None,
    channel: Any | None = None,
    channelWidth: str | None = None,
    txPowerLevel: Any | None = None,
    txPower: int | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Update one AP radio band (``PUT eaps/{MAC}/config/radios``) preserving sibling bands."""
    band_norm = str(band or "").strip().lower()
    if band_norm == "5g1":
        band_norm = "5g"
    site = _site(client)
    ap_stub = resolve_raw_device(client, site, deviceMac, expected_type="ap")
    norm_mac = _normalize_mac(str(ap_stub.get("mac") or deviceMac))
    dev_mac = _omada_mac(norm_mac)
    target_id = f"{norm_mac}:{band_norm}"
    _require_confirm("update_ap_radio", target_id, dryRun, confirm)

    def _fetch_ap() -> dict[str, Any]:
        raw = client.api_result(f"sites/{site.site_id}/eaps/{dev_mac}")
        if not isinstance(raw, Mapping):
            raise OmadaError(f"failed to fetch AP detail for {norm_mac}")
        return dict(raw)

    ap_detail = _fetch_ap()
    if txPower is not None and txPowerLevel is None:
        txPowerLevel = "custom"
    rs_key, target_wire_channel, validated, warnings = validate_ap_radio_change(
        client,
        site,
        ap_detail,
        band_norm,
        channel=channel,
        channel_width=channelWidth,
        tx_power_level=txPowerLevel,
        tx_power=txPower,
    )

    if not any(v is not None for v in (enabled, channel, channelWidth, txPowerLevel, txPower)):
        raise OmadaError("specify at least one radio attribute to update (enabled, channel, channelWidth, txPowerLevel, txPower)")

    if bool(ap_detail.get("wirelessLinked")):
        warnings.append("AP is wirelessly meshed (wirelessLinked=true); radio/channel changes may disrupt mesh uplink.")

    all_rs_keys = [
        k for k in ("radioSetting2g", "radioSetting5g", "radioSetting5g1", "radioSetting5g2", "radioSetting6g")
        if isinstance(ap_detail.get(k), Mapping)
    ]
    if rs_key not in all_rs_keys:
        all_rs_keys.append(rs_key)

    sibling_before = {k: copy.deepcopy(dict(ap_detail[k])) for k in all_rs_keys if k != rs_key}
    new_rs = copy.deepcopy(dict(ap_detail.get(rs_key) or {}))
    if enabled is not None:
        new_rs["radioEnable"] = bool(enabled)
        if not bool(enabled):
            other_enabled = any(
                bool(dict(ap_detail[k]).get("radioEnable", True))
                for k in all_rs_keys
                if k != rs_key
            )
            if not other_enabled:
                warnings.append("WARNING: Disabling this radio leaves no enabled Wi-Fi radios on this AP.")
    if channel is not None:
        new_rs["channel"] = target_wire_channel
        if target_wire_channel == "0":
            new_rs["freq"] = 0
    if channelWidth is not None:
        new_rs["channelWidth"] = validated["channelWidthCode"]
    if txPowerLevel is not None:
        new_rs["txPowerLevel"] = validated["txPowerLevel"]
        if validated["txPowerLevel"] != 3:
            new_rs.pop("txPower", None)
    if txPower is not None:
        new_rs["txPowerLevel"] = 3
        new_rs["txPower"] = int(txPower)

    put_body: dict[str, Any] = {rs_key: new_rs}
    for sk, sval in sibling_before.items():
        put_body[sk] = sval

    def _radio_view(rs: Mapping[str, Any]) -> dict[str, Any]:
        wcode = str(rs.get("channelWidth") or "")
        plvl = rs.get("txPowerLevel")
        return {
            "radioEnable": bool(rs.get("radioEnable", True)),
            "channel": rs.get("channel"),
            "channelWidth": CHANNEL_WIDTH_LABELS.get(wcode, wcode),
            "channelWidthCode": wcode,
            "txPowerLevel": TX_POWER_LEVEL_LABELS.get(as_int(plvl, -1), plvl),
            "txPower": rs.get("txPower"),
        }

    before_view = _radio_view(ap_detail.get(rs_key) or {})
    after_view = _radio_view(new_rs)
    diff = _field_diff(before_view, after_view, tuple(before_view.keys()))
    rollback = {
        "tool": "update_ap_radio",
        "arguments": {
            "deviceMac": norm_mac,
            "band": band_norm,
            "enabled": before_view["radioEnable"],
            "channel": before_view["channel"],
            "channelWidth": before_view["channelWidthCode"] or "auto",
            "txPowerLevel": as_int((ap_detail.get(rs_key) or {}).get("txPowerLevel"), 4),
            "dryRun": True,
        },
    }
    if dryRun:
        return _dry_run_result(
            tool_name="update_ap_radio",
            target_id=target_id,
            before=before_view,
            after=after_view,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/eaps/{dev_mac}/config/radios"

    def _read_back() -> dict[str, Any]:
        now = _fetch_ap()
        return {
            "target": _radio_view(now.get(rs_key) or {}),
            "siblings": {sk: _radio_view(now.get(sk) or {}) for sk in sibling_before},
        }

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, "AP radio read-back failed"
        tgt = after_now.get("target") or {}
        if enabled is not None and bool(tgt.get("radioEnable")) != bool(enabled):
            return False, f"{rs_key}.radioEnable expected {enabled!r}, got {tgt.get('radioEnable')!r}"
        if channel is not None and str(tgt.get("channel")) != str(target_wire_channel):
            return False, f"{rs_key}.channel expected {target_wire_channel!r}, got {tgt.get('channel')!r}"
        if channelWidth is not None and str(tgt.get("channelWidthCode")) != str(validated["channelWidthCode"]):
            return False, f"{rs_key}.channelWidth expected {validated['channelWidthCode']!r}, got {tgt.get('channelWidthCode')!r}"
        if txPowerLevel is not None and tgt.get("txPowerLevel") != after_view["txPowerLevel"]:
            return False, f"{rs_key}.txPowerLevel did not match the intended setting"
        if txPower is not None and as_int(tgt.get("txPower"), -1) != txPower:
            return False, f"{rs_key}.txPower did not match the intended setting"
        # Verify sibling bands were not altered or wiped.
        sib_now = after_now.get("siblings") or {}
        for sk, sb_raw in sibling_before.items():
            if _radio_view(sb_raw) != sib_now.get(sk):
                return False, f"sibling radio {sk} unexpectedly changed during {rs_key} update"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_view, live)
        return ok, put_body, live

    write_res = client.write(
        endpoint,
        method="PUT",
        data=put_body,
        tool_name="update_ap_radio",
        target=target_id,
        before=before_view,
        snapshot_payload=ap_detail,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()),
    )
    after_target = (write_res["after"] or {}).get("target") if isinstance(write_res["after"], Mapping) else write_res["after"]
    return _committed_result(
        tool_name="update_ap_radio",
        target_id=target_id,
        before=write_res["before"],
        after=after_target,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def _compute_ap_survey_impact(
    client: OmadaClient,
    site: Any,
    norm_mac: str,
    ap_name: str,
    target_bands: list[str],
    ap_map: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Estimate per-radio wireless client disconnect impact before triggering an RF scan."""
    warnings: list[str] = []
    mesh_risk = bool(ap_map.get("wirelessLinked"))
    if mesh_risk:
        warnings.append("WARNING: AP has a wireless mesh uplink; RF scanning can drop downstream mesh hops.")

    client_rows: list[dict[str, Any]] | None = None
    try:
        rows = _fetch_client_rows(client, site)
        wireless_rows = [r for r in rows if r.get("wireless")]
        if not wireless_rows or any(
            r.get("radioId") is not None and (r.get("apMac") or r.get("apName"))
            for r in wireless_rows
        ):
            client_rows = rows
    except OmadaError:
        client_rows = None

    if client_rows is None:
        warnings.append(
            "WARNING: Client band/AP telemetry is unavailable with this account; per-radio disconnect impact is unknown."
        )
        return {
            "impactKnown": False,
            "targetBands": target_bands,
            "affectedClientsByBand": {},
            "totalAffectedClients": None,
            "affectedClients": [],
            "meshDownlinkRisk": mesh_risk,
        }, warnings

    all_counts = count_ap_clients_by_band(norm_mac, ap_name, client_rows)
    affected_by_band = {band: all_counts.get(band, 0) for band in target_bands}
    affected_clients: list[dict[str, Any]] = []
    target_set = set(target_bands)
    ap_name_lower = ap_name.strip().lower()
    for row in client_rows:
        if not row.get("wireless"):
            continue
        row_mac = _normalize_mac(str(row.get("apMac") or ""))
        row_ap_name = str(row.get("apName") or "").strip().lower()
        if row_mac:
            if row_mac != norm_mac:
                continue
        elif ap_name_lower and row_ap_name:
            if row_ap_name != ap_name_lower:
                continue
        else:
            continue
        band = _RADIO_ID_TO_BAND.get(as_int(row.get("radioId"), -1))
        if band and band in target_set:
            affected_clients.append({
                "mac": _normalize_mac(str(row.get("mac") or "")),
                "name": str(row.get("name") or row.get("hostName") or ""),
                "ip": str(row.get("ip") or ""),
                "ssid": str(row.get("ssid") or ""),
                "band": band,
            })

    total_affected = sum(affected_by_band.values())
    for band in target_bands:
        cnt = affected_by_band[band]
        rid = _BAND_TO_RADIO_ID.get(band)
        if cnt > 0:
            warnings.append(
                f"IMPACT: {cnt} client(s) on {band} (radio {rid}) would disconnect for ~15-60 s during scan."
            )
    if total_affected == 0:
        warnings.append(
            f"IMPACT: 0 connected clients currently observed on target band(s) ({', '.join(target_bands)})."
        )
    else:
        warnings.insert(
            0,
            f"WARNING: RF scan will temporarily disconnect {total_affected} client(s) across {', '.join(target_bands)} for ~15-60 seconds.",
        )

    return {
        "impactKnown": True,
        "targetBands": target_bands,
        "affectedClientsByBand": affected_by_band,
        "totalAffectedClients": total_affected,
        "affectedClients": affected_clients,
        "meshDownlinkRisk": mesh_risk,
    }, warnings


def _prepare_rf_scan_plan(
    client: OmadaClient,
    site: Any,
    device_mac: str,
    bands: list[str] | None,
) -> dict[str, Any]:
    ap_stub = resolve_raw_device(client, site, device_mac, expected_type="ap")
    norm_mac = _normalize_mac(str(ap_stub.get("mac") or device_mac))
    dev_mac = _omada_mac(norm_mac)

    ap_detail = client.api_result(f"sites/{site.site_id}/eaps/{dev_mac}")
    ap_map = dict(ap_detail) if isinstance(ap_detail, Mapping) else dict(ap_stub)
    if ap_map.get("supportRFScan") is False:
        raise OmadaError(
            f"AP {ap_map.get('name') or norm_mac} ({norm_mac}) does not support RF scanning",
        )

    radio_ids: list[int] | None = None
    target_bands: list[str] = []
    if bands is not None:
        radio_ids = []
        for b in bands:
            bn = str(b or "").strip().lower()
            if bn not in _BAND_TO_RADIO_ID:
                raise OmadaError(f"invalid band {b!r}", hint="valid bands: 2g, 5g, 5g2, 6g")
            rid = _BAND_TO_RADIO_ID[bn]
            norm_b = _RADIO_ID_TO_BAND.get(rid, bn)
            if rid not in radio_ids:
                radio_ids.append(rid)
            if norm_b not in target_bands:
                target_bands.append(norm_b)
    else:
        for b, keys in (
            ("2g", ("radioSetting2g", "wp2g")),
            ("5g", ("radioSetting5g", "radioSetting5g1", "wp5g", "wp5g1")),
            ("5g2", ("radioSetting5g2", "wp5g2")),
            ("6g", ("radioSetting6g", "wp6g")),
        ):
            if any(k in ap_map for k in keys):
                target_bands.append(b)
        if not target_bands:
            target_bands = ["2g", "5g"]

    dev_cap = as_mapping(ap_map.get("devCap"))
    payload: dict[str, Any] = {}
    if radio_ids is not None and dev_cap.get("supportSingleBandRFScan", True):
        payload["radioIdList"] = radio_ids

    before_rf: dict[str, Any] = {}
    try:
        rf_raw = client.api_result(f"sites/{site.site_id}/eaps/{dev_mac}/tools/rfScan")
        if isinstance(rf_raw, Mapping):
            before_rf = dict(rf_raw)
    except OmadaError:
        pass

    ap_name = str(ap_map.get("name") or norm_mac)
    impact, impact_warnings = _compute_ap_survey_impact(
        client, site, norm_mac, ap_name, target_bands, ap_map,
    )
    parsed_before = parse_rf_scan_payload(before_rf)
    baseline_times = {**parsed_before["bandTimes"], "_top": parsed_before["scanTime"]}
    return {
        "apStub": ap_stub,
        "apMap": ap_map,
        "normMac": norm_mac,
        "devMac": dev_mac,
        "apName": ap_name,
        "payload": payload,
        "radioIds": radio_ids,
        "targetBands": target_bands,
        "beforeRf": before_rf,
        "beforeScanning": bool(parsed_before.get("scanning")),
        "baselineTimes": baseline_times,
        "impact": impact,
        "warnings": impact_warnings,
    }


def start_rf_scan(
    client: OmadaClient,
    deviceMac: str,
    bands: list[str] | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Start an AP RF interference scan (``POST cmd/eaps/{MAC}/tools/rfScan``)."""
    site = _site(client)
    plan = _prepare_rf_scan_plan(client, site, deviceMac, bands)
    norm_mac = plan["normMac"]
    dev_mac = plan["devMac"]
    _require_confirm("start_rf_scan", norm_mac, dryRun, confirm)

    before_rf = plan["beforeRf"]
    before = {
        "mac": norm_mac,
        "name": plan["apName"],
        "scanning": plan["beforeScanning"],
        "impact": plan["impact"],
    }
    diff = {"rfScanTriggered": {"before": False, "after": True}}
    if dryRun:
        return _dry_run_result(
            tool_name="start_rf_scan",
            target_id=norm_mac,
            before=before,
            after={**before, "rfScanTriggered": True, "radioIdList": plan["payload"].get("radioIdList")},
            diff=diff,
            warnings=plan["warnings"],
            rollback=None,
        )

    write_res = client.write(
        f"sites/{site.site_id}/cmd/eaps/{dev_mac}/tools/rfScan",
        method="POST",
        data=plan["payload"],
        tool_name="start_rf_scan",
        target=norm_mac,
        before=before,
        snapshot_payload={"ap": plan["apMap"], "rfScan": before_rf},
        fields_changed=["rfScan"],
    )
    return _committed_result(
        tool_name="start_rf_scan",
        target_id=norm_mac,
        before=write_res["before"],
        after={**before, "rfScanTriggered": True},
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=plan["warnings"],
        rollback=None,
    )


def _survey_trigger_verified(
    survey_after: Any,
    baseline_times: Mapping[str, Any],
    target_bands: list[str],
    *,
    wait: bool,
) -> bool:
    """Return True when post-POST read-back proves the AP started or completed the RF scan."""
    if not isinstance(survey_after, Mapping):
        return False
    if bool(survey_after.get("scanning")):
        return True
    if wait and not bool(survey_after.get("timedOut")):
        return True
    band_times = survey_after.get("bandTimes") or {}
    return any(
        band_times.get(band) is not None and band_times.get(band) != baseline_times.get(band)
        for band in target_bands
    )


def survey_wifi(
    client: OmadaClient,
    deviceMac: str,
    bands: list[str] | None = None,
    wait: bool = True,
    timeoutSeconds: int = 90,
    pollIntervalSeconds: int = 5,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Impact-aware AP RF survey: previews per-radio client disconnects, triggers scan, and optionally polls results."""
    site = _site(client)
    plan = _prepare_rf_scan_plan(client, site, deviceMac, bands)
    norm_mac = plan["normMac"]
    dev_mac = plan["devMac"]
    _require_confirm("survey_wifi", norm_mac, dryRun, confirm)

    before_rf = plan["beforeRf"]
    before = {
        "mac": norm_mac,
        "name": plan["apName"],
        "scanning": plan["beforeScanning"],
        "impact": plan["impact"],
    }
    diff = {"rfSurveyTriggered": {"before": False, "after": True}}
    if dryRun:
        return _dry_run_result(
            tool_name="survey_wifi",
            target_id=norm_mac,
            before=before,
            after={
                **before,
                "rfSurveyTriggered": True,
                "radioIdList": plan["payload"].get("radioIdList"),
                "wait": bool(wait),
            },
            diff=diff,
            warnings=plan["warnings"],
            rollback=None,
        )

    write_res = client.write(
        f"sites/{site.site_id}/cmd/eaps/{dev_mac}/tools/rfScan",
        method="POST",
        data=plan["payload"],
        tool_name="survey_wifi",
        target=norm_mac,
        before=before,
        snapshot_payload={"ap": plan["apMap"], "rfScan": before_rf},
        fields_changed=["rfScan"],
        read_back=lambda: collect_rf_scan_data(
            client,
            site,
            plan["apStub"],
            wait=bool(wait),
            timeout_seconds=as_int(timeoutSeconds, 90),
            poll_interval_seconds=as_int(pollIntervalSeconds, 5),
            target_bands=plan["targetBands"],
            baseline_times=plan["baselineTimes"],
        ),
        verify_fn=lambda _before, survey_after: (isinstance(survey_after, Mapping), None),
        verification_complete=lambda survey_after: _survey_trigger_verified(
            survey_after, plan["baselineTimes"], plan["targetBands"], wait=bool(wait),
        ),
    )
    survey = dict(write_res["after"]) if isinstance(write_res.get("after"), Mapping) else {}
    scanning_now = bool(survey.get("scanning"))
    timed_out_now = bool(survey.get("timedOut"))
    trigger_verified = _survey_trigger_verified(
        survey, plan["baselineTimes"], plan["targetBands"], wait=bool(wait),
    )
    scan_completed = not timed_out_now and not scanning_now and (bool(wait) or trigger_verified)
    warnings = [*plan["warnings"], *survey.get("warnings", [])]
    after_out: dict[str, Any] = {
        "mac": norm_mac,
        "name": plan["apName"],
        "impact": plan["impact"],
        "rfSurveyTriggered": True,
        "triggerVerified": trigger_verified,
        "scanCompleted": scan_completed,
        "status": survey.get("status"),
        "statusLabel": survey.get("statusLabel"),
        "scanning": scanning_now,
        "timedOut": timed_out_now,
        "polls": survey.get("polls"),
        "elapsedSeconds": survey.get("elapsedSeconds"),
        "bandStatuses": survey.get("bandStatuses"),
        "bandStatusLabels": survey.get("bandStatusLabels"),
        "bandTimes": survey.get("bandTimes"),
        "channelCount": len(survey.get("channels") or []),
        "channelsByBand": survey.get("channelsByBand"),
        "rfScan": survey,
    }
    if scanning_now or timed_out_now:
        after_out["resumeHint"] = (
            f"Scan is still in progress; call get_rf_scan(mac={norm_mac!r}, wait=True, timeoutSeconds=600) "
            "to collect results without re-triggering."
        )
    return _committed_result(
        tool_name="survey_wifi",
        target_id=norm_mac,
        before=write_res["before"],
        after=after_out,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=list(dict.fromkeys(warnings)),
        rollback=None,
    )


_NETCHECK_DEVICE_TYPE: dict[str, int] = {
    "ap": 0,
    "eap": 0,
    "switch": 1,
    "stack": 1,
    "gateway": 2,
}


def _validate_diag_target(target: str) -> str:
    clean = str(target or "").strip()
    if not clean or len(clean) > 255 or any(ch.isspace() or ord(ch) < 32 for ch in clean):
        raise OmadaError(
            f"invalid diagnostic target {target!r}",
            hint="pass an IPv4/IPv6 address or hostname without spaces (e.g. '8.8.8.8' or '192.168.1.1')",
        )
    return clean


def _run_network_check(
    client: OmadaClient,
    *,
    tool_name: str,
    test_code: int,
    deviceMac: str,
    target: str,
    count: int | None = None,
    packetSize: int | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    clean_target = _validate_diag_target(target)
    site = _site(client)
    dev_stub = resolve_raw_device(client, site, deviceMac)
    norm_mac = _normalize_mac(str(dev_stub.get("mac") or deviceMac))
    dev_mac = _omada_mac(norm_mac)
    dev_type = str(dev_stub.get("type") or "").strip().lower()
    dev_type_code = _NETCHECK_DEVICE_TYPE.get(dev_type)
    if dev_type_code is None:
        raise OmadaError(f"device {norm_mac} has unsupported type {dev_type!r} for network-check")

    status_cat = dev_stub.get("statusCategory")
    status_val = dev_stub.get("status")
    is_offline = (status_cat is not None and status_cat != 1) or (
        status_cat is None and status_val is not None and status_val not in (1, 14)
    )
    if is_offline:
        raise OmadaError(
            f"device {dev_stub.get('name') or norm_mac} ({norm_mac}) is offline",
            hint="select an online device to run active network diagnostics",
        )

    target_id = f"{norm_mac}:{clean_target}"
    _require_confirm(tool_name, target_id, dryRun, confirm)

    nid = uuid.uuid4().hex
    payload: dict[str, Any] = {
        "deviceType": dev_type_code,
        "source": [dev_mac],
        "destType": 0,
        "dest": clean_target,
        "nid": nid,
    }
    if test_code == 0:
        cnt = 4 if count is None else count
        pkt = 56 if packetSize is None else packetSize
        if isinstance(cnt, bool) or not isinstance(cnt, int) or not (1 <= cnt <= 20):
            raise OmadaError("count must be an integer between 1 and 20")
        if isinstance(pkt, bool) or not isinstance(pkt, int) or not (4 <= pkt <= 1472):
            raise OmadaError("packetSize must be an integer between 4 and 1472 bytes")
        payload["count"] = cnt
        payload["packetSize"] = pkt

    test_label = "ping" if test_code == 0 else "traceroute"
    before = {"mac": norm_mac, "name": dev_stub.get("name"), "deviceType": dev_type, "target": clean_target}
    after_preview = {**before, "test": test_label, **({"count": payload.get("count"), "packetSize": payload.get("packetSize")} if test_code == 0 else {})}
    diff = {"networkCheckTriggered": {"before": False, "after": f"{test_label}:{clean_target}"}}
    warnings = [
        f"Controller executes {test_label} asynchronously on device {norm_mac} (results stream over controller WebSocket when UI-attached)."
    ]

    if dryRun:
        return _dry_run_result(
            tool_name=tool_name,
            target_id=target_id,
            before=before,
            after=after_preview,
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    write_res = client.write(
        f"sites/{site.site_id}/tools/network-check/{test_code}",
        method="POST",
        data=payload,
        tool_name=tool_name,
        target=target_id,
        before=before,
        snapshot_payload={"device": dev_stub, "request": payload},
        fields_changed=[test_label],
    )
    return _committed_result(
        tool_name=tool_name,
        target_id=target_id,
        before=write_res["before"],
        after={**after_preview, "nid": nid, "controllerResult": write_res.get("result")},
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )


def run_ping(
    client: OmadaClient,
    deviceMac: str,
    target: str,
    count: int = 4,
    packetSize: int = 56,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Run an active ICMP ping from an adopted AP, switch, or gateway (``POST tools/network-check/0``)."""
    return _run_network_check(
        client,
        tool_name="run_ping",
        test_code=0,
        deviceMac=deviceMac,
        target=target,
        count=count,
        packetSize=packetSize,
        dryRun=dryRun,
        confirm=confirm,
    )


def run_traceroute(
    client: OmadaClient,
    deviceMac: str,
    target: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Run an active traceroute from an adopted AP, switch, or gateway (``POST tools/network-check/1``)."""
    return _run_network_check(
        client,
        tool_name="run_traceroute",
        test_code=1,
        deviceMac=deviceMac,
        target=target,
        dryRun=dryRun,
        confirm=confirm,
    )


def start_wan_speedtest(
    client: OmadaClient,
    pure: bool = False,
    pollSeconds: int = 0,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Trigger an active WAN gateway speed test (``POST cmd/speedTest`` or ``cmd/speedTestPure``)."""
    if isinstance(pollSeconds, bool) or not isinstance(pollSeconds, int) or not (0 <= pollSeconds <= 15):
        raise OmadaError("pollSeconds must be an integer between 0 and 15")
    site = _site(client)
    gws = _require_gateway(client, site, "WAN speed test")
    target_id = f"site:{site.site_id}"
    _require_confirm("start_wan_speedtest", target_id, dryRun, confirm)

    warnings = [
        "WARNING: Active WAN speed tests briefly saturate the Internet uplink and can raise latency for connected clients."
    ]
    before_status: dict[str, Any] = {}
    try:
        res = client.api_result(f"sites/{site.site_id}/cmd/getSpeedTestResult")
        if isinstance(res, Mapping):
            before_status = dict(res)
    except OmadaError:
        pass

    before = {
        "siteId": site.site_id,
        "gateway": gws[0].get("name") or gws[0].get("mac"),
        "speedTestStatus": before_status.get("speedTestStatus"),
    }
    diff = {"speedTestTriggered": {"before": False, "after": True}}
    if dryRun:
        return _dry_run_result(
            tool_name="start_wan_speedtest",
            target_id=target_id,
            before=before,
            after={**before, "speedTestTriggered": True, "pure": bool(pure)},
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    cmd = "cmd/speedTestPure" if pure else "cmd/speedTest"
    write_res = client.write(
        f"sites/{site.site_id}/{cmd}",
        method="POST",
        data={},
        tool_name="start_wan_speedtest",
        target=target_id,
        before=before,
        snapshot_payload={"gateway": gws[0], "beforeStatus": before_status},
        fields_changed=["speedTest"],
    )

    polled_result: dict[str, Any] | None = None
    if pollSeconds > 0:
        deadline = time.monotonic() + pollSeconds
        while True:
            try:
                raw_poll = client.api_result(f"sites/{site.site_id}/cmd/getSpeedTestResult")
                if isinstance(raw_poll, Mapping):
                    polled_result = dict(raw_poll)
                    status_val = polled_result.get("speedTestStatus")
                    if status_val not in (None, 0, "running") or polled_result.get("speedTestResults"):
                        break
            except OmadaError:
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(min(2.0, max(0.1, deadline - time.monotonic())))

    return _committed_result(
        tool_name="start_wan_speedtest",
        target_id=target_id,
        before=write_res["before"],
        after={
            **before,
            "speedTestTriggered": True,
            "pure": bool(pure),
            "result": polled_result or write_res.get("result"),
        },
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )

