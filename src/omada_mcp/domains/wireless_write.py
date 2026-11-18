"""Write domain module: wireless_write."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import as_int, deep_redact, resolve_device_detail, resolve_raw_device
from ._write_common import (
    _SSID_BAND_BITS,
    _SSID_SERVER_ONLY_KEYS,
    _committed_result,
    _delete_entity,
    _dry_run_result,
    _field_diff,
    _match_fields,
    _normalize_mac,
    _redact_ssid,
    _require_confirm,
    _resolve_by_id_or_name,
    _site,
    _validate_vlan_id,
)
from ._write_fetchers import (
    _fetch_clients_filtered,
    _fetch_rate_limit_profiles,
    _fetch_ssids,
    _fetch_wlan_groups,
    _omada_mac,
)


def _parse_ssid_bands(bands: Any) -> int:
    if isinstance(bands, int) and not isinstance(bands, bool):
        if 1 <= bands <= 7:
            return bands
        raise OmadaError(f"band bitmask {bands} must be between 1 and 7")
    if isinstance(bands, str):
        tokens = [t.strip().lower() for t in re.split(r"[,+|/\s]+", bands) if t.strip()]
    elif isinstance(bands, (list, tuple)):
        tokens = [str(t or "").strip().lower() for t in bands if str(t or "").strip()]
    else:
        raise OmadaError("bands must be e.g. ['2g', '5g'] or bitmask 1..7")
    mask = 0
    for tok in tokens:
        if tok == "all":
            mask |= 7
        elif tok in _SSID_BAND_BITS:
            mask |= _SSID_BAND_BITS[tok]
        else:
            raise OmadaError(f"unknown Wi-Fi band {tok!r}; expected '2g', '5g', or '6g'")
    if mask == 0:
        raise OmadaError("at least one Wi-Fi band must be enabled")
    return mask


def _parse_ssid_security(security: str, psk: str | None) -> tuple[int, dict[str, Any] | None]:
    mode = str(security or "wpa2-psk").strip().lower()
    if mode in ("open", "none"):
        return 0, None
    version_map = {
        "wpa-psk": 3,
        "wpa2-psk": 2,
        "wpa-wpa2-psk": 3,
        "wpa3-sae": 4,
        "wpa3": 4,
    }
    if mode not in version_map:
        raise OmadaError(
            f"unsupported SSID security {security!r}; expected 'open', 'wpa2-psk', 'wpa-wpa2-psk', or 'wpa3-sae'",
        )
    key_text = str(psk or "")
    if not (8 <= len(key_text) <= 63):
        raise OmadaError("WPA-PSK passphrase must be between 8 and 63 characters")
    return 3, {
        "securityKey": key_text,
        "encryptionPsk": 3,
        "versionPsk": version_map[mode],
        "gikRekeyPskEnable": False,
    }


def _parse_pmf_mode(pmf: Any) -> int:
    if isinstance(pmf, int) and not isinstance(pmf, bool) and pmf in (1, 2, 3):
        return pmf
    text = str(pmf or "disable").strip().lower()
    mapping = {"mandatory": 1, "required": 1, "1": 1, "capable": 2, "optional": 2, "2": 2, "disable": 3, "off": 3, "3": 3}
    if text not in mapping:
        raise OmadaError(f"invalid pmfMode {pmf!r}; expected 'mandatory' (1), 'capable' (2), or 'disable' (3)")
    return mapping[text]


def _resolve_wlan_group(groups: Sequence[Mapping[str, Any]], selector: str | None) -> dict[str, Any]:
    if not groups:
        raise OmadaError("site has no WLAN groups")
    if selector is not None and str(selector).strip():
        return _resolve_by_id_or_name(groups, str(selector), label="WLAN group")
    if len(groups) == 1:
        return dict(groups[0])
    default = next((dict(g) for g in groups if str(g.get("name", "")).lower() == "default"), None)
    if default is not None:
        return default
    names = ", ".join(str(g.get("name") or g.get("id")) for g in groups)
    raise OmadaError(f"multiple WLAN groups exist ({names}); specify wlanGroup explicitly")


def create_ssid(
    client: OmadaClient,
    name: str,
    wlanGroup: str | None = None,
    bands: Any = None,
    security: str = "wpa2-psk",
    psk: str | None = None,
    vlanId: int | None = None,
    guest: bool = False,
    broadcast: bool = True,
    pmfMode: Any = "disable",
    enable11r: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create a Wi-Fi SSID in a WLAN group with strict PSK redaction in snapshots/output."""
    ssid_name = str(name or "").strip()
    if not ssid_name:
        raise OmadaError("SSID name must be non-empty")
    band_mask = _parse_ssid_bands(["2g", "5g"] if bands is None else bands)
    sec_code, psk_cfg = _parse_ssid_security(security, psk)
    pmf_int = _parse_pmf_mode(pmfMode)
    if sec_code != 0 and psk_cfg and psk_cfg.get("versionPsk") == 4 and pmf_int != 1:
        pmf_int = 1  # WPA3 requires PMF mandatory

    vlan_setting: dict[str, Any]
    if vlanId is not None:
        vid = _validate_vlan_id(vlanId)
        vlan_setting = {"mode": 1, "customConfig": {"bridgeVlan": vid}, "currentVlanId": vid}
    else:
        vlan_setting = {"mode": 0, "customConfig": {"bridgeVlan": 1}, "currentVlanId": None}

    _require_confirm("create_ssid", ssid_name, dryRun, confirm)

    site = _site(client)
    wlan_groups = _fetch_wlan_groups(client, site)
    target_wlan = _resolve_wlan_group(wlan_groups, wlanGroup)
    wlan_id = str(target_wlan["id"])
    existing_ssids = _fetch_ssids(client, site, wlan_id)
    if any(str(s.get("name", "")).strip() == ssid_name for s in existing_ssids):
        raise OmadaError(f"SSID {ssid_name!r} already exists in WLAN group {target_wlan.get('name')!r}", code=-33239)

    body: dict[str, Any] = {
        "name": ssid_name,
        "band": band_mask,
        "guestNetEnable": bool(guest),
        "security": sec_code,
        "broadcast": bool(broadcast),
        "vlanSetting": vlan_setting,
        "rateAndBeaconCtrl": {"rate2gCtrl": 0, "rate5gCtrl": 0, "rate6gCtrl": 0},
        "pmfMode": pmf_int,
        "enable11r": bool(enable11r),
        "greEnable": False,
        "mloEnable": False,
        "wlanScheduleEnable": False,
        "rateLimit": {"downLimitEnable": False, "upLimitEnable": False},
        "ssidRateLimit": {"downLimitEnable": False, "upLimitEnable": False},
        "macFilterEnable": False,
        "multiCastSetting": {
            "multiCastEnable": False,
            "arpCastEnable": False,
            "ipv6CastEnable": False,
            "filterEnable": False,
            "ipv6FilterEnable": False,
        },
        "dhcpOption82": {"dhcpEnable": False},
        "deviceType": 1,
        "prohibitWifiShareEnable": False,
    }
    if psk_cfg is not None:
        body["pskSetting"] = psk_cfg

    redacted_after = _redact_ssid(body)
    diff = {"ssid": {"before": None, "after": redacted_after}}
    warnings = []
    if sec_code == 0:
        warnings.append("creating an OPEN Wi-Fi SSID without encryption")

    if dryRun:
        return _dry_run_result(
            tool_name="create_ssid",
            target_id=ssid_name,
            before=None,
            after=redacted_after,
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    endpoint = f"sites/{site.site_id}/setting/wlans/{wlan_id}/ssids"

    def _read_back() -> list[dict[str, Any]]:
        return _fetch_ssids(client, site, wlan_id)

    expected = {key: body[key] for key in (
        "name", "band", "guestNetEnable", "broadcast", "security", "vlanSetting", "pmfMode", "enable11r",
    )}

    def _verify(_before: Any, rows_now: Any) -> tuple[bool, str | None]:
        if not isinstance(rows_now, list):
            return False, "SSID read-back did not return a list"
        found = next((s for s in rows_now if str(s.get("name")) == ssid_name), None)
        if found is None:
            return False, f"created SSID {ssid_name!r} missing on read-back"
        return _match_fields(found, expected)

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        ok, _ = _verify(None, _read_back())
        return ok, None, None

    write_res = client.write(
        endpoint,
        method="POST",
        data=body,
        tool_name="create_ssid",
        target=ssid_name,
        before=None,
        snapshot_payload={"wlanGroup": target_wlan.get("name"), "existingSsids": [_redact_ssid(s) for s in existing_ssids]},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=None if psk_cfg is not None else _reauth_prepare,
        verification_complete=psk_cfg is None,
        fields_changed=sorted(expected.keys()),
    )
    created_raw = next((s for s in write_res["after"] if str(s.get("name")) == ssid_name), body)
    created_safe = _redact_ssid(created_raw)
    rollback = {
        "tool": "delete_ssid",
        "arguments": {"ssid": str(created_raw.get("id") or ssid_name), "wlanGroup": wlan_id, "dryRun": True},
    }
    if psk_cfg is not None:
        warnings.append("Verify the new passphrase independently. Read-back verifies visible SSID settings.")
    return _committed_result(
        tool_name="create_ssid",
        target_id=ssid_name,
        before=None,
        after=created_safe,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def update_ssid(
    client: OmadaClient,
    ssid: str,
    wlanGroup: str | None = None,
    name: str | None = None,
    bands: Any = None,
    psk: str | None = None,
    vlanId: int | None = None,
    clearVlan: bool = False,
    guest: bool | None = None,
    broadcast: bool | None = None,
    pmfMode: Any = None,
    enable11r: bool | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Update an SSID via full-object PATCH (``setting/wlans/{wlanId}/ssids/{ssidId}``)."""
    if all(
        v is None
        for v in (name, bands, psk, vlanId, guest, broadcast, pmfMode, enable11r)
    ) and not clearVlan:
        raise OmadaError("specify at least one SSID setting to update")

    site = _site(client)
    wlan_groups = _fetch_wlan_groups(client, site)
    target_wlan = _resolve_wlan_group(wlan_groups, wlanGroup)
    wlan_id = str(target_wlan["id"])
    ssids = _fetch_ssids(client, site, wlan_id)
    target_raw = _resolve_by_id_or_name(ssids, ssid, label="SSID")
    ssid_id = str(target_raw["id"])
    _require_confirm("update_ssid", ssid_id, dryRun, confirm)

    patch_body = {k: copy.deepcopy(v) for k, v in target_raw.items() if k not in _SSID_SERVER_ONLY_KEYS}
    diff: dict[str, Any] = {}
    expected: dict[str, Any] = {}

    if name is not None:
        clean_name = str(name).strip()
        if not clean_name:
            raise OmadaError("SSID name must be non-empty")
        diff["name"] = {"before": target_raw.get("name"), "after": clean_name}
        patch_body["name"] = clean_name
        expected["name"] = clean_name
    if bands is not None:
        band_mask = _parse_ssid_bands(bands)
        diff["band"] = {"before": target_raw.get("band"), "after": band_mask}
        patch_body["band"] = band_mask
        expected["band"] = band_mask
    if guest is not None:
        diff["guestNetEnable"] = {"before": target_raw.get("guestNetEnable"), "after": bool(guest)}
        patch_body["guestNetEnable"] = bool(guest)
        expected["guestNetEnable"] = bool(guest)
    if broadcast is not None:
        diff["broadcast"] = {"before": target_raw.get("broadcast"), "after": bool(broadcast)}
        patch_body["broadcast"] = bool(broadcast)
        expected["broadcast"] = bool(broadcast)
    if pmfMode is not None:
        pmf_int = _parse_pmf_mode(pmfMode)
        diff["pmfMode"] = {"before": target_raw.get("pmfMode"), "after": pmf_int}
        patch_body["pmfMode"] = pmf_int
        expected["pmfMode"] = pmf_int
    if enable11r is not None:
        diff["enable11r"] = {"before": target_raw.get("enable11r"), "after": bool(enable11r)}
        patch_body["enable11r"] = bool(enable11r)
        expected["enable11r"] = bool(enable11r)
    if clearVlan:
        new_vs = {"mode": 0, "customConfig": {"bridgeVlan": 1}, "currentVlanId": None}
        diff["vlanSetting"] = {"before": target_raw.get("vlanSetting"), "after": new_vs}
        patch_body["vlanSetting"] = new_vs
    elif vlanId is not None:
        vid = _validate_vlan_id(vlanId)
        new_vs = {"mode": 1, "customConfig": {"bridgeVlan": vid}, "currentVlanId": vid}
        diff["vlanSetting"] = {"before": target_raw.get("vlanSetting"), "after": new_vs}
        patch_body["vlanSetting"] = new_vs
    if psk is not None:
        if int(patch_body.get("security", 0)) == 0:
            raise OmadaError("cannot set psk on an open SSID")
        if not (8 <= len(str(psk)) <= 63):
            raise OmadaError("WPA-PSK passphrase must be 8..63 characters")
        cur_psk = copy.deepcopy(patch_body.get("pskSetting") or {"encryptionPsk": 3, "versionPsk": 2, "gikRekeyPskEnable": False})
        cur_psk["securityKey"] = str(psk)
        patch_body["pskSetting"] = cur_psk
        diff["pskUpdated"] = {"before": False, "after": True}

    before_safe = _redact_ssid(target_raw)
    after_safe = _redact_ssid(patch_body)
    warnings = ["The passphrase needs independent verification and manual restoration if recovery is needed."] if psk is not None else []
    if dryRun:
        preview = _dry_run_result(
            tool_name="update_ssid",
            target_id=ssid_id,
            before=before_safe,
            after=after_safe,
            diff=diff,
            warnings=warnings,
            rollback=None,
        )
        if psk is not None:
            preview["manualRecoveryRequired"] = True
        return preview

    endpoint = f"sites/{site.site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}"

    def _read_back() -> dict[str, Any] | None:
        return next((dict(s) for s in _fetch_ssids(client, site, wlan_id) if str(s.get("id")) == ssid_id), None)

    def _verify(_before: Any, after_row: Any) -> tuple[bool, str | None]:
        if not isinstance(after_row, Mapping):
            return False, f"SSID {ssid_id} missing on read-back"
        ok, reason = _match_fields(after_row, expected)
        if not ok:
            return False, reason
        if clearVlan or vlanId is not None:
            want_vid = None if clearVlan else _validate_vlan_id(vlanId)
            got_vs = after_row.get("vlanSetting") or {}
            if clearVlan and got_vs.get("mode") != 0:
                return False, f"vlanSetting.mode expected 0, got {got_vs.get('mode')!r}"
            if vlanId is not None and got_vs.get("currentVlanId") != want_vid and (got_vs.get("customConfig") or {}).get("bridgeVlan") != want_vid:
                return False, f"vlanId expected {want_vid}, got {got_vs!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        if live is None:
            return False, None, None
        ok, _ = _verify(target_raw, live)
        if ok:
            return True, None, None
        re_body = {k: copy.deepcopy(v) for k, v in live.items() if k not in _SSID_SERVER_ONLY_KEYS}
        for k in expected:
            re_body[k] = copy.deepcopy(patch_body[k])
        if clearVlan or vlanId is not None:
            re_body["vlanSetting"] = copy.deepcopy(patch_body["vlanSetting"])
        return False, re_body, _redact_ssid(live)

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=patch_body,
        tool_name="update_ssid",
        target=ssid_id,
        before=before_safe,
        snapshot_payload={**(before_safe or {}), "secretRestoreRequired": psk is not None},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=None if psk is not None else _reauth_prepare,
        verification_complete=psk is None,
        fields_changed=sorted(diff.keys()),
    )
    result = _committed_result(
        tool_name="update_ssid",
        target_id=ssid_id,
        before=write_res["before"],
        after=_redact_ssid(write_res["after"]),
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )
    if psk is not None:
        result["manualRecoveryRequired"] = True
        result["verificationIncomplete"] = True
    return result


def delete_ssid(
    client: OmadaClient,
    ssid: str,
    wlanGroup: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete an SSID from a WLAN group (``DELETE setting/wlans/{wlanId}/ssids/{ssidId}``)."""
    site = _site(client)
    wlan_groups = _fetch_wlan_groups(client, site)
    target_wlan = _resolve_wlan_group(wlan_groups, wlanGroup)
    wlan_id = str(target_wlan["id"])
    ssids = _fetch_ssids(client, site, wlan_id)
    target_raw = _resolve_by_id_or_name(ssids, ssid, label="SSID")
    ssid_id = str(target_raw["id"])
    before_safe = _redact_ssid(target_raw)
    warnings = ["this is the last SSID in the WLAN group"] if len(ssids) <= 1 else []
    return _delete_entity(
        client,
        tool_name="delete_ssid",
        target_id=ssid_id,
        endpoint=f"sites/{site.site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}",
        before=before_safe,
        snapshot_payload=before_safe,
        fetch_all=lambda: _fetch_ssids(client, site, wlan_id),
        match_fn=lambda row: str(row.get("id")) == ssid_id,
        rollback=None,
        warnings=warnings,
        dry_run=dryRun,
        confirm=confirm,
        label="ssid",
    )


def assign_ap_wlan_group(
    client: OmadaClient,
    deviceMac: str,
    wlanGroup: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Assign an AP to a WLAN group (``PUT eaps/{MAC}/config/wlans``) preserving overrides."""
    site = _site(client)
    ap_stub = resolve_raw_device(client, site, deviceMac, expected_type="ap")
    norm_mac = _normalize_mac(str(ap_stub.get("mac") or deviceMac))
    dev_mac = _omada_mac(norm_mac)
    _require_confirm("assign_ap_wlan_group", norm_mac, dryRun, confirm)

    groups = _fetch_wlan_groups(client, site)
    target_grp = _resolve_wlan_group(groups, wlanGroup)
    target_wlan_id = str(target_grp.get("id") or "")
    if not target_wlan_id:
        raise OmadaError(f"resolved WLAN group {wlanGroup!r} has no id")

    def _fetch_ap() -> dict[str, Any]:
        raw = client.api_result(f"sites/{site.site_id}/eaps/{dev_mac}")
        if not isinstance(raw, Mapping):
            raise OmadaError(f"failed to fetch AP detail for {norm_mac}")
        return dict(raw)

    ap_detail = _fetch_ap()
    before_wlan_id = str(ap_detail.get("wlanId") or "")
    grp_by_id = {str(g.get("id") or ""): str(g.get("name") or "") for g in groups}

    current_overrides = ap_detail.get("ssidOverrides") or []
    if not isinstance(current_overrides, list) or any(not isinstance(row, Mapping) for row in current_overrides):
        raise OmadaError("AP SSID overrides were unavailable before changing the WLAN group")
    safe_before = _redact_override_list(current_overrides)
    credentials_present = any(row["hasPresharedKey"] for row in safe_before)
    overrides = copy.deepcopy(current_overrides)
    for ov in overrides:
        if isinstance(ov, dict):
            ov.pop("psk", None)
            if ap_detail.get("supportVlanPool"):
                ov.pop("vlanId", None)
                ov.setdefault("vlanPoolIds", "1")
            else:
                ov.pop("vlanPoolIds", None)
                ov.setdefault("vlanId", 1)

    body = {"wlanId": target_wlan_id, "ssidOverrides": overrides}
    before_summary = {"mac": norm_mac, "wlanId": before_wlan_id, "wlanGroupName": grp_by_id.get(before_wlan_id, ""),
                      "ssidOverrides": safe_before}
    after_summary = {"mac": norm_mac, "wlanId": target_wlan_id, "wlanGroupName": str(target_grp.get("name") or ""),
                     "ssidOverrides": _redact_override_list(overrides)}
    diff = _field_diff(before_summary, after_summary, ("wlanId", "wlanGroupName", "ssidOverrides"))
    warnings = ["Check the AP's override credentials after apply. Restoring credentials requires manual recovery."] if credentials_present else []
    rollback = {
        "tool": "assign_ap_wlan_group",
        "arguments": {"deviceMac": norm_mac, "wlanGroup": before_wlan_id or grp_by_id.get(before_wlan_id, "Default"), "dryRun": True},
    }
    if dryRun:
        preview = _dry_run_result(
            tool_name="assign_ap_wlan_group",
            target_id=norm_mac,
            before=before_summary,
            after=after_summary,
            diff=diff,
            warnings=warnings,
            rollback=None if credentials_present else rollback,
        )
        if credentials_present:
            preview["manualRecoveryRequired"] = True
        return preview

    endpoint = f"sites/{site.site_id}/eaps/{dev_mac}/config/wlans"

    def _read_back() -> dict[str, Any]:
        now = _fetch_ap()
        wid = str(now.get("wlanId") or "")
        rows = now.get("ssidOverrides")
        safe_rows = _redact_override_list(rows) if isinstance(rows, list) and all(isinstance(r, Mapping) for r in rows) else None
        return {"mac": norm_mac, "wlanId": wid, "wlanGroupName": grp_by_id.get(wid, ""), "ssidOverrides": safe_rows}

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        return _verify_ap_wlan_state(after_summary, after_now)

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_summary, live)
        if not ok and not _verify_ap_wlan_state(before_summary, live)[0]:
            raise OmadaError("AP WLAN assignment changed while recovering the session",
                             hint="inspect the existing assignment and run a new dry run")
        return ok, body, live

    write_res = client.write(
        endpoint,
        method="PUT",
        data=body,
        tool_name="assign_ap_wlan_group",
        target=norm_mac,
        before=before_summary,
        snapshot_payload={**before_summary, "secretRestoreRequired": credentials_present},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=None if credentials_present else _reauth_prepare,
        verification_complete=not credentials_present,
        fields_changed=["wlanId"],
    )
    result = _committed_result(
        tool_name="assign_ap_wlan_group",
        target_id=norm_mac,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None if credentials_present else rollback,
    )
    if credentials_present:
        result["manualRecoveryRequired"] = True
        result["verificationIncomplete"] = True
    return result


def _redact_override_list(overrides: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for entry in overrides:
        item = {key: entry[key] for key in (
            "index", "globalSsid", "ssid", "enable", "ssidEnable", "vlanEnable", "vlanId", "vlanPoolIds",
        ) if key in entry and isinstance(entry[key], (str, int, bool))}
        pool_ids = entry.get("vlanPoolIds")
        if isinstance(pool_ids, list) and all(isinstance(value, (str, int)) for value in pool_ids):
            item["vlanPoolIds"] = list(pool_ids)
        item["hasPresharedKey"] = any(entry.get(key) for key in (
            "psk", "securityKey", "pskSetting", "ppskSetting", "hasPresharedKey",
        ))
        cleaned.append(item)
    return cleaned


def _verify_ap_wlan_state(expected: Mapping[str, Any], actual: Any) -> tuple[bool, str | None]:
    if not isinstance(actual, Mapping) or str(actual.get("wlanId") or "") != expected.get("wlanId"):
        return False, "AP WLAN group did not match the intended group"

    def overrides(state: Mapping[str, Any]) -> list[dict[str, Any]] | None:
        raw = state.get("ssidOverrides")
        if not isinstance(raw, list) or any(not isinstance(row, Mapping) for row in raw):
            return None
        rows = _redact_override_list(raw)
        for row in rows:
            row.pop("hasPresharedKey", None)
            for key in ("index", "vlanId"):
                if key in row:
                    row[key] = as_int(row[key], -1)
            for key in ("enable", "ssidEnable", "vlanEnable"):
                if key in row:
                    row[key] = row[key] in (True, "true", "1")
        return sorted(rows, key=lambda row: (row.get("index", -1), row.get("globalSsid", "")))

    expected_rows = overrides(expected)
    if expected_rows is None or overrides(actual) != expected_rows:
        return False, "AP SSID overrides did not match the intended configuration"
    return True, None


def upsert_rate_limit_profile(
    client: OmadaClient,
    name: str,
    profileId: str | None = None,
    downLimitEnable: bool | None = None,
    downLimitKbps: int | None = None,
    upLimitEnable: bool | None = None,
    upLimitKbps: int | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a client bandwidth rate-limit profile (``setting/profiles/rateLimits``)."""
    prof_name = str(name or "").strip()
    if not prof_name:
        raise OmadaError("rate limit profile name must be non-empty")

    site = _site(client)
    profiles = _fetch_rate_limit_profiles(client, site)
    existing: dict[str, Any] | None = None
    if profileId:
        existing = _resolve_by_id_or_name(profiles, str(profileId), label="rate limit profile")
    else:
        matches = [dict(p) for p in profiles if str(p.get("name") or "").strip() == prof_name]
        if matches:
            existing = matches[0]

    is_update = existing is not None
    if existing is not None and bool(existing.get("isDefault")) and prof_name != str(existing.get("name") or ""):
        raise OmadaError(f"cannot rename built-in default rate-limit profile {existing.get('name')!r}")

    existing_id = str(existing.get("id") or "") if existing else ""
    target_id = existing_id or prof_name
    _require_confirm("upsert_rate_limit_profile", target_id, dryRun, confirm)

    dl_en = (
        bool(downLimitEnable)
        if downLimitEnable is not None
        else (bool(existing.get("downLimitEnable", False)) if existing else downLimitKbps is not None)
    )
    ul_en = (
        bool(upLimitEnable)
        if upLimitEnable is not None
        else (bool(existing.get("upLimitEnable", False)) if existing else upLimitKbps is not None)
    )
    dl_val = as_int(downLimitKbps, 0) if downLimitKbps is not None else as_int((existing or {}).get("downLimit"), 0)
    ul_val = as_int(upLimitKbps, 0) if upLimitKbps is not None else as_int((existing or {}).get("upLimit"), 0)

    if dl_en and dl_val <= 0:
        raise OmadaError("downLimitKbps must be > 0 when downLimitEnable is true")
    if ul_en and ul_val <= 0:
        raise OmadaError("upLimitKbps must be > 0 when upLimitEnable is true")

    body: dict[str, Any] = {
        "name": prof_name,
        "downLimitEnable": dl_en,
        "downLimit": dl_val if dl_en else 0,
        "downLimitUnit": 1,
        "upLimitEnable": ul_en,
        "upLimit": ul_val if ul_en else 0,
        "upLimitUnit": 1,
    }

    before_clean = deep_redact(existing) if existing else None
    after_preview = {**(before_clean or {}), **body}
    diff = _field_diff(
        before_clean or {},
        after_preview,
        ["name", "downLimitEnable", "downLimit", "downLimitUnit", "upLimitEnable", "upLimit", "upLimitUnit"],
    )
    dry_rollback = (
        {
            "tool": "upsert_rate_limit_profile",
            "arguments": {
                "profileId": existing_id,
                "name": existing.get("name"),
                "downLimitEnable": bool(existing.get("downLimitEnable", False)),
                "downLimitKbps": as_int(existing.get("downLimit"), 0) if existing.get("downLimitEnable") else None,
                "upLimitEnable": bool(existing.get("upLimitEnable", False)),
                "upLimitKbps": as_int(existing.get("upLimit"), 0) if existing.get("upLimitEnable") else None,
                "dryRun": True,
            },
        }
        if existing is not None
        else None
    )
    if dryRun:
        return _dry_run_result(
            tool_name="upsert_rate_limit_profile",
            target_id=target_id,
            before=before_clean,
            after=after_preview,
            diff=diff,
            warnings=[],
            rollback=dry_rollback,
        )

    existing_ids = {str(p.get("id")) for p in profiles if p.get("id")}
    endpoint = (
        f"sites/{site.site_id}/setting/profiles/rateLimits/{existing_id}"
        if is_update
        else f"sites/{site.site_id}/setting/profiles/rateLimits"
    )
    method = "PATCH" if is_update else "POST"

    def _read_back() -> dict[str, Any] | None:
        rows = _fetch_rate_limit_profiles(client, site)
        if existing_id:
            return next((dict(r) for r in rows if str(r.get("id")) == existing_id), None)
        created = next(
            (dict(r) for r in rows if str(r.get("name") or "").strip() == prof_name and str(r.get("id")) not in existing_ids),
            None,
        )
        return created or next((dict(r) for r in rows if str(r.get("name") or "").strip() == prof_name), None)

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, f"rate limit profile {prof_name!r} not found after {method}"
        expected = {key: body[key] for key in ("name", "downLimitEnable", "upLimitEnable")}
        for direction, enabled in (("down", dl_en), ("up", ul_en)):
            if enabled:
                expected[f"{direction}Limit"] = body[f"{direction}Limit"]
                expected[f"{direction}LimitUnit"] = body[f"{direction}LimitUnit"]
        return _match_fields(after_now, expected)

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(existing, live)
        return ok, body, live

    write_res = client.write(
        endpoint,
        method=method,
        data=body,
        tool_name="upsert_rate_limit_profile",
        target=target_id,
        before=before_clean,
        snapshot_payload={"action": "update" if is_update else "create", "profile": copy.deepcopy(existing), "existingIds": sorted(existing_ids), "name": prof_name},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()) or ["downLimit", "upLimit"],
    )
    after_obj = deep_redact(write_res["after"])
    new_id = str((write_res["after"] or {}).get("id") or existing_id or target_id)
    committed_rb = (
        dry_rollback
        if is_update
        else {"tool": "delete_rate_limit_profile", "arguments": {"profile": new_id, "dryRun": True}}
    )
    return _committed_result(
        tool_name="upsert_rate_limit_profile",
        target_id=target_id,
        before=write_res["before"],
        after=after_obj,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=committed_rb,
    )


def delete_rate_limit_profile(
    client: OmadaClient,
    profile: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a rate-limit profile after checking it is not the Default profile or in use."""
    site = _site(client)
    profiles = _fetch_rate_limit_profiles(client, site)
    target_prof = _resolve_by_id_or_name(profiles, profile, label="rate limit profile")
    target_id = str(target_prof.get("id") or "")
    if bool(target_prof.get("isDefault")) or int(target_prof.get("resource", 0) or 0) != 0:
        raise OmadaError(
            f"refusing to delete default/protected rate-limit profile {target_prof.get('name') or target_id!r}",
        )

    refs: list[str] = []
    try:
        for grp in _fetch_wlan_groups(client, site):
            gid = str(grp.get("id") or "")
            if not gid:
                continue
            for ssid in _fetch_ssids(client, site, gid):
                rl_block = ssid.get("rateLimit") or {}
                if isinstance(rl_block, Mapping) and str(rl_block.get("rateLimitId") or rl_block.get("id") or "") == target_id:
                    refs.append(f"SSID:{ssid.get('name') or ssid.get('id')}")
    except OmadaError:
        pass
    try:
        for cli in _fetch_clients_filtered(client, site, active=None):
            rl_cli = cli.get("rateLimit") or {}
            if str(cli.get("rateLimitId") or "") == target_id or (
                isinstance(rl_cli, Mapping) and str(rl_cli.get("rateLimitId") or rl_cli.get("id") or "") == target_id
            ):
                refs.append(f"Client:{cli.get('name') or cli.get('mac')}")
    except OmadaError:
        pass
    if refs:
        raise OmadaError(
            f"cannot delete rate-limit profile {target_prof.get('name')!r}: referenced by {', '.join(refs[:8])}",
            hint="remove the rate-limit profile binding from SSIDs/clients before deleting it",
        )

    rollback = {
        "tool": "upsert_rate_limit_profile",
        "arguments": {
            "name": target_prof.get("name"),
            "downLimitEnable": bool(target_prof.get("downLimitEnable", False)),
            "downLimitKbps": as_int(target_prof.get("downLimit"), 0) if target_prof.get("downLimitEnable") else None,
            "upLimitEnable": bool(target_prof.get("upLimitEnable", False)),
            "upLimitKbps": as_int(target_prof.get("upLimit"), 0) if target_prof.get("upLimitEnable") else None,
            "dryRun": True,
        },
    }
    return _delete_entity(
        client,
        tool_name="delete_rate_limit_profile",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/profiles/rateLimits/{target_id}",
        before=deep_redact(target_prof),
        snapshot_payload={"action": "delete", "profile": copy.deepcopy(target_prof)},
        fetch_all=lambda: _fetch_rate_limit_profiles(client, site),
        match_fn=lambda row: str(row.get("id") or "") == target_id,
        rollback=rollback,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="rateLimitProfile",
    )


def set_ap_ssid_overrides(
    client: OmadaClient,
    mac: str,
    overrides: Sequence[Mapping[str, Any]],
    wlanGroup: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Configure per-AP SSID overrides (custom SSID name, enable/disable, VLAN, or PSK; secrets redacted)."""
    if not isinstance(overrides, Sequence) or isinstance(overrides, (str, bytes)) or not overrides:
        raise OmadaError("overrides must be a non-empty list of SSID override patch objects")

    site = _site(client)
    ap = resolve_device_detail(client, site, mac, expected_type="ap")
    dev_mac = _omada_mac(str(ap.get("mac") or ""))
    norm_mac = _normalize_mac(dev_mac)
    _require_confirm("set_ap_ssid_overrides", norm_mac, dryRun, confirm)

    wlan_groups = _fetch_wlan_groups(client, site)
    target_wlan_id = str(ap.get("wlanId") or "")
    if wlanGroup is not None and str(wlanGroup).strip():
        target_wlan = _resolve_wlan_group(wlan_groups, wlanGroup)
        target_wlan_id = str(target_wlan["id"])
    elif not target_wlan_id and wlan_groups:
        target_wlan_id = str(_resolve_wlan_group(wlan_groups, None)["id"])

    raw_existing = [dict(o) for o in (ap.get("ssidOverrides") or []) if isinstance(o, Mapping)]
    updated_overrides = copy.deepcopy(raw_existing)
    if not updated_overrides and target_wlan_id:
        for s in _fetch_ssids(client, site, target_wlan_id):
            updated_overrides.append({
                "index": s.get("idInt") or s.get("index"),
                "globalSsid": s.get("name"),
                "ssid": s.get("name"),
                "enable": False,
                "ssidEnable": bool(s.get("broadcast", True)),
                "vlanEnable": False,
                "vlanId": 1,
            })

    touched_psk = False
    for patch in overrides:
        if not isinstance(patch, Mapping):
            raise OmadaError("each override entry must be an object")
        selector = patch.get("index") if patch.get("index") is not None else (
            patch.get("globalSsid") or patch.get("ssid")
        )
        if selector in (None, ""):
            raise OmadaError("each override entry must identify an SSID via index, globalSsid, or ssid")
        match_idx: int | None = None
        sel_text = str(selector).strip()
        for idx, cur in enumerate(updated_overrides):
            if str(cur.get("index") or "") == sel_text or str(cur.get("globalSsid") or "") == sel_text or str(cur.get("ssid") or "") == sel_text:
                match_idx = idx
                break
        if match_idx is None:
            raise OmadaError(f"AP {norm_mac} has no SSID matching {selector!r} to override")

        target_item = updated_overrides[match_idx]
        if "enable" in patch:
            target_item["enable"] = bool(patch["enable"])
        if "ssidEnable" in patch:
            target_item["ssidEnable"] = bool(patch["ssidEnable"])
        if patch.get("newSsid") is not None or (patch.get("ssid") is not None and patch.get("globalSsid") is not None):
            new_ssid_val = str(patch.get("newSsid") if patch.get("newSsid") is not None else patch.get("ssid") or "").strip()
            if not new_ssid_val or len(new_ssid_val.encode("utf-8")) > 32:
                raise OmadaError("override SSID name must be 1..32 bytes")
            target_item["ssid"] = new_ssid_val
            target_item.setdefault("enable", True)
        if "vlanEnable" in patch:
            target_item["vlanEnable"] = bool(patch["vlanEnable"])
        if patch.get("vlanId") is not None:
            target_item["vlanId"] = _validate_vlan_id(patch["vlanId"])
            target_item["vlanEnable"] = bool(patch.get("vlanEnable", True))
        if patch.get("psk") is not None:
            psk_val = str(patch["psk"])
            if not (8 <= len(psk_val) <= 63):
                raise OmadaError("override WPA-PSK passphrase must be 8..63 characters")
            target_item["psk"] = psk_val
            touched_psk = True

    before_summary: dict[str, Any] = {
        "mac": norm_mac,
        "wlanId": str(ap.get("wlanId") or ""),
        "ssidOverrides": _redact_override_list(raw_existing),
    }
    after_summary = {
        "mac": norm_mac,
        "wlanId": target_wlan_id,
        "ssidOverrides": _redact_override_list(updated_overrides),
    }
    diff = _field_diff(before_summary, after_summary, ["wlanId", "ssidOverrides"])
    warnings: list[str] = []
    secret_restore_required = touched_psk or any(
        entry["hasPresharedKey"] for entry in before_summary["ssidOverrides"]
    )
    if secret_restore_required:
        warnings.append("AP SSID override credentials are excluded from snapshots. Restore them manually if recovery is needed.")

    rollback_overrides = _redact_override_list(raw_existing)
    for item in rollback_overrides:
        item.pop("psk", None)
        item.pop("hasPresharedKey", None)
    rollback = {
        "tool": "set_ap_ssid_overrides",
        "arguments": {
            "mac": norm_mac,
            "wlanGroup": str(ap.get("wlanId") or ""),
            "overrides": rollback_overrides,
            "dryRun": True,
        },
    }
    if dryRun:
        preview = _dry_run_result(
            tool_name="set_ap_ssid_overrides",
            target_id=norm_mac,
            before=before_summary,
            after=after_summary,
            diff=diff,
            warnings=warnings,
            rollback=None if secret_restore_required else rollback,
        )
        if secret_restore_required:
            preview["manualRecoveryRequired"] = True
        return preview

    body = {"wlanId": target_wlan_id, "ssidOverrides": updated_overrides}
    endpoint = f"sites/{site.site_id}/eaps/{dev_mac}/config/wlans"

    def _read_back() -> dict[str, Any]:
        now = resolve_device_detail(client, site, dev_mac, expected_type="ap")
        now_ov = [o for o in (now.get("ssidOverrides") or []) if isinstance(o, Mapping)]
        return {
            "mac": norm_mac,
            "wlanId": str(now.get("wlanId") or ""),
            "ssidOverrides": _redact_override_list(now_ov),
        }

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        return _verify_ap_wlan_state(after_summary, after_now)

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        if _verify(before_summary, live)[0]:
            return True, None, live
        if not _verify_ap_wlan_state(before_summary, live)[0]:
            raise OmadaError("AP override state changed while recovering the controller session",
                             hint="inspect current overrides and run a new dry run")
        return False, body, live

    snap_safe = {
        "mac": norm_mac,
        "wlanId": str(ap.get("wlanId") or ""),
        "ssidOverrides": rollback_overrides,
        "secretRestoreRequired": secret_restore_required,
    }
    write_res = client.write(
        endpoint,
        method="PUT",
        data=body,
        tool_name="set_ap_ssid_overrides",
        target=norm_mac,
        before=before_summary,
        snapshot_payload=snap_safe,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=None if touched_psk else _reauth_prepare,
        verification_complete=not touched_psk,
        fields_changed=sorted(diff.keys()) or ["ssidOverrides"],
    )
    result = _committed_result(
        tool_name="set_ap_ssid_overrides",
        target_id=norm_mac,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None if secret_restore_required else rollback,
    )
    if secret_restore_required:
        result["manualRecoveryRequired"] = True
    if touched_psk:
        result["verificationIncomplete"] = True
        result["warnings"].append("Visible AP override fields were verified. The new passphrase requires independent verification.")
    return result


def run_wlan_optimization(
    client: OmadaClient,
    action: str = "trigger",
    mode: str | int | None = None,
    channelDeployEnable2g: bool | None = None,
    channelDeployEnable5g: bool | None = None,
    channelDeployEnable6g: bool | None = None,
    powerAdjustEnable2g: bool | None = None,
    powerAdjustEnable5g: bool | None = None,
    powerAdjustEnable6g: bool | None = None,
    chanWidth2g: int | None = None,
    chanWidth5g: int | None = None,
    chanWidth6g: int | None = None,
    scheduleEnable: bool | None = None,
    timingType: int | None = None,
    hour: int | None = None,
    minute: int | None = None,
    dayOfWeek: int | None = None,
    dayOfMonth: int | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Configure AI RF Planning settings/schedule and optionally trigger or cancel WLAN optimization."""
    act = str(action or "trigger").strip().lower()
    if act not in ("trigger", "configure", "cancel"):
        raise OmadaError(f"invalid action {action!r}; expected 'trigger', 'configure', or 'cancel'")

    site = _site(client)
    target_id = f"rfPlanning:{act}"
    _require_confirm("run_wlan_optimization", target_id, dryRun, confirm)

    res_before = client.api_result(f"sites/{site.site_id}/rfPlanning")
    if not isinstance(res_before, Mapping):
        raise OmadaError("rfPlanning settings unavailable on this controller")
    before_cfg = deep_redact(dict(res_before))

    has_config_updates = any(
        v is not None
        for v in (
            mode, channelDeployEnable2g, channelDeployEnable5g, channelDeployEnable6g,
            powerAdjustEnable2g, powerAdjustEnable5g, powerAdjustEnable6g,
            chanWidth2g, chanWidth5g, chanWidth6g,
        )
    )
    has_sched_updates = any(
        v is not None for v in (scheduleEnable, timingType, hour, minute, dayOfWeek, dayOfMonth)
    )
    if act == "configure" and not has_config_updates and not has_sched_updates:
        raise OmadaError("action='configure' requires at least one config or schedule field")

    mode_int = as_int(before_cfg.get("mode"), 0)
    if mode is not None:
        m_str = str(mode).strip().lower()
        if m_str in ("0", "auto"):
            mode_int = 0
        elif m_str in ("1", "custom"):
            mode_int = 1
        else:
            raise OmadaError(f"invalid mode {mode!r}; expected 'auto' (0) or 'custom' (1)")

    c2 = bool(before_cfg.get("channelDeployEnable2g", True)) if channelDeployEnable2g is None else bool(channelDeployEnable2g)
    c5 = bool(before_cfg.get("channelDeployEnable5g", True)) if channelDeployEnable5g is None else bool(channelDeployEnable5g)
    c6 = bool(before_cfg.get("channelDeployEnable6g", True)) if channelDeployEnable6g is None else bool(channelDeployEnable6g)
    p2 = bool(before_cfg.get("powerAdjustEnable2g", True)) if powerAdjustEnable2g is None else bool(powerAdjustEnable2g)
    p5 = bool(before_cfg.get("powerAdjustEnable5g", True)) if powerAdjustEnable5g is None else bool(powerAdjustEnable5g)
    p6 = bool(before_cfg.get("powerAdjustEnable6g", True)) if powerAdjustEnable6g is None else bool(powerAdjustEnable6g)
    cw2 = as_int(before_cfg.get("chanWidth2g"), 0) if chanWidth2g is None else int(chanWidth2g)
    cw5 = as_int(before_cfg.get("chanWidth5g"), 0) if chanWidth5g is None else int(chanWidth5g)
    cw6 = as_int(before_cfg.get("chanWidth6g"), 0) if chanWidth6g is None else int(chanWidth6g)

    config_payload: dict[str, Any] = {"mode": 0}
    if mode_int == 1 or (mode is None and any(
        v is not None for v in (channelDeployEnable2g, channelDeployEnable5g, channelDeployEnable6g,
                                powerAdjustEnable2g, powerAdjustEnable5g, powerAdjustEnable6g,
                                chanWidth2g, chanWidth5g, chanWidth6g)
    )):
        mode_int = 1
        config_payload = {
            "mode": 1,
            "customSetting": {
                "channelDeployEnable": bool(c2 or c5 or c6),
                "powerAdjustEnable": bool(p2 or p5 or p6),
                "channelWidthDeployEnable": bool(cw2 or cw5 or cw6 or before_cfg.get("channelWidthDeployEnable", True)),
                "bandDeployEnable": bool(before_cfg.get("bandDeployEnable", True)),
                "channelDeployEnable2g": c2,
                "channelDeployEnable5g": c5,
                "channelDeployEnable6g": c6,
                "powerAdjustEnable2g": p2,
                "powerAdjustEnable5g": p5,
                "powerAdjustEnable6g": p6,
                "chanWidth2g": cw2,
                "chanWidth5g": cw5,
                "chanWidth6g": cw6,
            },
        }

    occ_before = dict(before_cfg.get("occurrence") or {"timingType": 1, "hour": 0, "minute": 0})
    sched_en = bool(before_cfg.get("scheduleEnable", False)) if scheduleEnable is None else bool(scheduleEnable)
    occ_after: dict[str, Any] = {
        "timingType": as_int(occ_before.get("timingType"), 1) if timingType is None else int(timingType),
        "hour": as_int(occ_before.get("hour"), 0) if hour is None else int(hour),
        "minute": as_int(occ_before.get("minute"), 0) if minute is None else int(minute),
    }
    if dayOfWeek is not None or occ_after["timingType"] == 2:
        occ_after["dayOfWeek"] = as_int(occ_before.get("dayOfWeek"), 0) if dayOfWeek is None else int(dayOfWeek)
    if dayOfMonth is not None or occ_after["timingType"] == 3:
        occ_after["dayOfMonth"] = as_int(occ_before.get("dayOfMonth"), 1) if dayOfMonth is None else int(dayOfMonth)
    sched_payload = {"scheduleEnable": sched_en, "occurrence": occ_after}

    after_preview = copy.deepcopy(before_cfg)
    if has_config_updates:
        after_preview["mode"] = mode_int
        if "customSetting" in config_payload:
            after_preview.update(config_payload["customSetting"])
    if has_sched_updates:
        after_preview["scheduleEnable"] = sched_en
        after_preview["occurrence"] = occ_after
    after_preview["action"] = act

    warnings: list[str] = []
    if act == "trigger":
        warnings.append(
            "AI WLAN optimization adjusts AP channels and transmit power; wireless clients may briefly roam or reconnect."
        )

    diff = _field_diff(before_cfg, after_preview, ["mode", "scheduleEnable", "occurrence", "chanWidth2g", "chanWidth5g", "chanWidth6g"])
    diff["action"] = {"before": "idle", "after": act}

    rollback = (
        {
            "tool": "run_wlan_optimization",
            "arguments": {
                "action": "configure",
                "mode": as_int(before_cfg.get("mode"), 0),
                "channelDeployEnable2g": before_cfg.get("channelDeployEnable2g"),
                "channelDeployEnable5g": before_cfg.get("channelDeployEnable5g"),
                "channelDeployEnable6g": before_cfg.get("channelDeployEnable6g"),
                "powerAdjustEnable2g": before_cfg.get("powerAdjustEnable2g"),
                "powerAdjustEnable5g": before_cfg.get("powerAdjustEnable5g"),
                "powerAdjustEnable6g": before_cfg.get("powerAdjustEnable6g"),
                "chanWidth2g": before_cfg.get("chanWidth2g"),
                "chanWidth5g": before_cfg.get("chanWidth5g"),
                "chanWidth6g": before_cfg.get("chanWidth6g"),
                "scheduleEnable": before_cfg.get("scheduleEnable"),
                "dryRun": True,
            },
        }
        if (has_config_updates or has_sched_updates)
        else None
    )

    if dryRun:
        return _dry_run_result(
            tool_name="run_wlan_optimization",
            target_id=target_id,
            before=before_cfg,
            after=after_preview,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    snap_payload = {"action": act, "configBefore": copy.deepcopy(before_cfg)}
    final_snap: str | None = None
    if has_config_updates:
        wr_cfg = client.write(
            f"sites/{site.site_id}/rfPlanning/config",
            method="PUT",
            data=config_payload,
            tool_name="run_wlan_optimization",
            target=f"{target_id}:config",
            before=before_cfg,
            snapshot_payload=snap_payload,
            fields_changed=["rfPlanningConfig"],
        )
        final_snap = wr_cfg["snapshot"]
    if has_sched_updates:
        wr_sched = client.write(
            f"sites/{site.site_id}/rfPlanning/schedule",
            method="PUT",
            data=sched_payload,
            tool_name="run_wlan_optimization",
            target=f"{target_id}:schedule",
            before=before_cfg,
            snapshot_payload=snap_payload,
            fields_changed=["rfPlanningSchedule"],
        )
        final_snap = wr_sched["snapshot"]

    if act == "trigger":
        try:
            wr = client.write(
                f"sites/{site.site_id}/cmd/rfPlanning/optimization",
                method="POST",
                data={},
                tool_name="run_wlan_optimization",
                target=target_id,
                before=before_cfg,
                snapshot_payload=snap_payload,
                fields_changed=["rfOptimizationTriggered"],
            )
            final_snap = wr["snapshot"]
        except OmadaError as exc:
            if exc.code == -1600:
                wr = client.write(
                    f"sites/{site.site_id}/cmd/rfPlanning",
                    method="POST",
                    data=before_cfg,
                    tool_name="run_wlan_optimization",
                    target=target_id,
                    before=before_cfg,
                    snapshot_payload=snap_payload,
                    fields_changed=["rfOptimizationTriggered"],
                )
                final_snap = wr["snapshot"]
            else:
                raise
    elif act == "cancel":
        wr = client.write(
            f"sites/{site.site_id}/cmd/rfPlanning/cancel",
            method="POST",
            data={},
            tool_name="run_wlan_optimization",
            target=target_id,
            before=before_cfg,
            snapshot_payload=snap_payload,
            fields_changed=["rfOptimizationCancelled"],
        )
        final_snap = wr["snapshot"]

    after_live = client.api_result(f"sites/{site.site_id}/rfPlanning")
    after_out = deep_redact(dict(after_live)) if isinstance(after_live, Mapping) else after_preview
    after_out["action"] = act
    return _committed_result(
        tool_name="run_wlan_optimization",
        target_id=target_id,
        before=before_cfg,
        after=after_out,
        diff=diff,
        snapshot=final_snap,
        warnings=warnings,
        rollback=rollback,
    )


