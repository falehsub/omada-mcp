"""Write domain module: devices_write."""

from __future__ import annotations

import copy
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
from ._device_helpers import validate_ap_radio_change
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
from ._write_fetchers import _fetch_devices, _omada_mac


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
            if "locateEnable" in a and bool(a["locateEnable"]) != loc_val:
                return False, f"locateEnable expected {loc_val!r}, got {a.get('locateEnable')!r}"
            return True, None

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


def start_rf_scan(
    client: OmadaClient,
    deviceMac: str,
    bands: list[str] | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Start an AP RF interference scan (``POST cmd/eaps/{MAC}/tools/rfScan``)."""
    site = _site(client)
    ap_stub = resolve_raw_device(client, site, deviceMac, expected_type="ap")
    norm_mac = _normalize_mac(str(ap_stub.get("mac") or deviceMac))
    dev_mac = _omada_mac(norm_mac)
    _require_confirm("start_rf_scan", norm_mac, dryRun, confirm)

    ap_detail = client.api_result(f"sites/{site.site_id}/eaps/{dev_mac}")
    ap_map = dict(ap_detail) if isinstance(ap_detail, Mapping) else dict(ap_stub)
    if ap_map.get("supportRFScan") is False:
        raise OmadaError(
            f"AP {ap_map.get('name') or norm_mac} ({norm_mac}) does not support RF scanning",
        )

    radio_ids: list[int] | None = None
    if bands is not None:
        radio_ids = []
        for b in bands:
            bn = str(b or "").strip().lower()
            if bn not in _BAND_TO_RADIO_ID:
                raise OmadaError(f"invalid band {b!r}", hint="valid bands: 2g, 5g, 5g2, 6g")
            rid = _BAND_TO_RADIO_ID[bn]
            if rid not in radio_ids:
                radio_ids.append(rid)

    warnings = [
        "WARNING: Starting an RF scan temporarily disconnects Wi-Fi clients on scanned radio(s) for ~15-60 seconds."
    ]
    if bool(ap_map.get("wirelessLinked")):
        warnings.append("WARNING: AP has a wireless mesh uplink; RF scanning can drop downstream mesh hops.")

    dev_cap = as_mapping(ap_map.get("devCap"))
    payload: dict[str, Any] = {}
    if radio_ids is not None and dev_cap.get("supportSingleBandRFScan", True):
        payload["radioIdList"] = radio_ids

    before_rf = {}
    try:
        rf_raw = client.api_result(f"sites/{site.site_id}/eaps/{dev_mac}/tools/rfScan")
        if isinstance(rf_raw, Mapping):
            before_rf = dict(rf_raw)
    except OmadaError:
        pass

    before = {"mac": norm_mac, "name": ap_map.get("name"), "status": before_rf.get("status"), "time": before_rf.get("time")}
    diff = {"rfScanTriggered": {"before": False, "after": True}}
    if dryRun:
        return _dry_run_result(
            tool_name="start_rf_scan",
            target_id=norm_mac,
            before=before,
            after={**before, "rfScanTriggered": True, "radioIdList": payload.get("radioIdList")},
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    write_res = client.write(
        f"sites/{site.site_id}/cmd/eaps/{dev_mac}/tools/rfScan",
        method="POST",
        data=payload,
        tool_name="start_rf_scan",
        target=norm_mac,
        before=before,
        snapshot_payload={"ap": ap_map, "rfScan": before_rf},
        fields_changed=["rfScan"],
    )
    return _committed_result(
        tool_name="start_rf_scan",
        target_id=norm_mac,
        before=write_res["before"],
        after={**before, "rfScanTriggered": True},
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )

