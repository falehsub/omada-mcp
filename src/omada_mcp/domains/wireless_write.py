"""Write domain module: wireless_write."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import resolve_raw_device
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
from ._write_fetchers import _fetch_ssids, _fetch_wlan_groups, _omada_mac


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

    expected = {"name": ssid_name, "band": band_mask, "guestNetEnable": bool(guest), "broadcast": bool(broadcast), "security": sec_code}

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
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(expected.keys()),
    )
    created_raw = next((s for s in write_res["after"] if str(s.get("name")) == ssid_name), body)
    created_safe = _redact_ssid(created_raw)
    rollback = {
        "tool": "delete_ssid",
        "arguments": {"ssid": str(created_raw.get("id") or ssid_name), "wlanGroup": wlan_id, "dryRun": True},
    }
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
    if dryRun:
        return _dry_run_result(
            tool_name="update_ssid",
            target_id=ssid_id,
            before=before_safe,
            after=after_safe,
            diff=diff,
            warnings=[],
            rollback=None,
        )

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
        if psk is not None and "pskSetting" in patch_body:
            re_body["pskSetting"] = copy.deepcopy(patch_body["pskSetting"])
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
        snapshot_payload=before_safe,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()),
    )
    return _committed_result(
        tool_name="update_ssid",
        target_id=ssid_id,
        before=write_res["before"],
        after=_redact_ssid(write_res["after"]),
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=None,
    )


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

    overrides = copy.deepcopy(list(ap_detail.get("ssidOverrides") or []))
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
    before_summary = {"mac": norm_mac, "wlanId": before_wlan_id, "wlanGroupName": grp_by_id.get(before_wlan_id, "")}
    after_summary = {"mac": norm_mac, "wlanId": target_wlan_id, "wlanGroupName": str(target_grp.get("name") or "")}
    diff = _field_diff(before_summary, after_summary, ("wlanId", "wlanGroupName"))
    rollback = {
        "tool": "assign_ap_wlan_group",
        "arguments": {"deviceMac": norm_mac, "wlanGroup": before_wlan_id or grp_by_id.get(before_wlan_id, "Default"), "dryRun": True},
    }
    if dryRun:
        return _dry_run_result(
            tool_name="assign_ap_wlan_group",
            target_id=norm_mac,
            before=before_summary,
            after=after_summary,
            diff=diff,
            warnings=[],
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/eaps/{dev_mac}/config/wlans"

    def _read_back() -> dict[str, Any]:
        now = _fetch_ap()
        wid = str(now.get("wlanId") or "")
        return {"mac": norm_mac, "wlanId": wid, "wlanGroupName": grp_by_id.get(wid, "")}

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping) or str(after_now.get("wlanId")) != target_wlan_id:
            return False, f"AP wlanId expected {target_wlan_id!r}, got {after_now.get('wlanId')!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_summary, live)
        return ok, body, live

    write_res = client.write(
        endpoint,
        method="PUT",
        data=body,
        tool_name="assign_ap_wlan_group",
        target=norm_mac,
        before=before_summary,
        snapshot_payload=ap_detail,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["wlanId"],
    )
    return _committed_result(
        tool_name="assign_ap_wlan_group",
        target_id=norm_mac,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=rollback,
    )

