"""Write domain module: switch_write."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import DUPLEX_LABELS as PORT_DUPLEX_LABELS
from ._common import LINK_SPEED_LABELS as PORT_LINK_SPEED_LABELS
from ._common import as_int, resolve_raw_device
from ._device_helpers import collect_switch_ports_data
from ._write_common import (
    _DUPLEX_TO_CODE,
    _LINK_SPEED_TO_CODE,
    _PORT_PROFILE_POE_TO_CODE,
    _committed_result,
    _delete_entity,
    _dry_run_result,
    _field_diff,
    _normalize_mac,
    _parse_code_map,
    _require_confirm,
    _resolve_by_id_or_name,
    _site,
    _unwrap_rows,
)
from ._write_fetchers import (
    _fetch_lan_collection,
    _fetch_lan_profiles,
    _omada_mac,
    _resolve_lan_network,
)


def _switch_port_summary(port_obj: Mapping[str, Any], info_obj: Mapping[str, Any] | None = None) -> dict[str, Any]:
    speed_code = as_int(port_obj.get("linkSpeed"), 0)
    duplex_code = as_int(port_obj.get("duplex"), 0)
    summary: dict[str, Any] = {
        "port": as_int(port_obj.get("port"), 0),
        "name": str(port_obj.get("name") or f"Port{port_obj.get('port', '')}"),
        "disable": bool(port_obj.get("disable", False)),
        "operation": str(port_obj.get("operation") or "switching"),
        "profileId": str(port_obj.get("profileId") or ""),
        "profileName": str(port_obj.get("profileName") or ""),
        "profileOverrideEnable": bool(port_obj.get("profileOverrideEnable", False)),
        "poe": port_obj.get("poe"),
        "linkSpeed": PORT_LINK_SPEED_LABELS.get(speed_code, str(speed_code)),
        "duplex": PORT_DUPLEX_LABELS.get(duplex_code, str(duplex_code)),
        "nativeNetworkId": port_obj.get("nativeNetworkId"),
        "tagNetworkIds": list(port_obj.get("tagNetworkIds") or []),
        "untagNetworkIds": list(port_obj.get("untagNetworkIds") or []),
        "portIsolationEnable": bool(port_obj.get("portIsolationEnable", False)),
        "lldpMedEnable": bool(port_obj.get("lldpMedEnable", False)),
        "spanningTreeEnable": bool(port_obj.get("spanningTreeEnable", False)),
    }
    if info_obj:
        summary["isUplink"] = bool(info_obj.get("isUplink"))
        summary["isLagMember"] = bool(info_obj.get("isLagMember"))
        summary["carriesController"] = bool(info_obj.get("carriesController"))
    return summary


def _build_switch_port_patch(
    base_port: Mapping[str, Any],
    *,
    name: str | None = None,
    profile_id: str | None = None,
    profile_override_enable: bool | None = None,
    poe: int | None = None,
    link_speed: int | None = None,
    duplex: int | None = None,
    native_network_id: str | None = None,
    tagged_network_ids: Sequence[str] | None = None,
    untagged_network_ids: Sequence[str] | None = None,
    port_isolation_enable: bool | None = None,
    lldp_med_enable: bool | None = None,
    spanning_tree_enable: bool | None = None,
    legacy_disable: bool | None = None,
) -> dict[str, Any]:
    """Construct an Omada ``editPortModel``-compliant payload for ``switches/{MAC}/ports/{port}``."""
    override_enabled = (
        bool(profile_override_enable)
        if profile_override_enable is not None
        else bool(base_port.get("profileOverrideEnable", False))
    )
    body: dict[str, Any] = {
        "name": str(base_port.get("name") or "") if name is None else str(name),
        "profileId": str(base_port.get("profileId") or "") if profile_id is None else str(profile_id),
        "profileOverrideEnable": override_enabled,
        "profileVlanOverrideEnable": bool(base_port.get("profileVlanOverrideEnable", True)),
        "dot1pPriority": as_int(base_port.get("dot1pPriority"), 0),
        "trustMode": as_int(base_port.get("trustMode"), 0),
        "linkSpeed": as_int(base_port.get("linkSpeed"), 0) if link_speed is None else int(link_speed),
        "duplex": as_int(base_port.get("duplex"), 0) if duplex is None else int(duplex),
    }
    if legacy_disable is not None:
        body["disable"] = bool(legacy_disable)
    if base_port.get("nativeNetworkId") is not None or native_network_id is not None:
        body["nativeNetworkId"] = (
            str(base_port.get("nativeNetworkId") or "")
            if native_network_id is None
            else (str(native_network_id) if native_network_id else None)
        )
    vlan_custom = (
        tagged_network_ids is not None
        or untagged_network_ids is not None
        or native_network_id is not None
    )
    if vlan_custom:
        body["networkTagsSetting"] = 2
        if tagged_network_ids is not None:
            body["tagNetworkIds"] = [str(x) for x in tagged_network_ids]
        elif base_port.get("tagNetworkIds") is not None:
            body["tagNetworkIds"] = list(base_port.get("tagNetworkIds") or [])
        if untagged_network_ids is not None:
            body["untagNetworkIds"] = [str(x) for x in untagged_network_ids]
        elif base_port.get("untagNetworkIds") is not None:
            body["untagNetworkIds"] = list(base_port.get("untagNetworkIds") or [])
    elif "networkTagsSetting" in base_port:
        body["networkTagsSetting"] = base_port.get("networkTagsSetting")

    # Omada UI editPortModel only sends override-controlled fields when profileOverrideEnable=True.
    if override_enabled:
        body["operation"] = str(base_port.get("operation") or "switching")
        if poe is not None:
            body["poe"] = int(poe)
        elif base_port.get("poe") is not None:
            body["poe"] = base_port.get("poe")
        if port_isolation_enable is not None:
            body["portIsolationEnable"] = bool(port_isolation_enable)
        elif "portIsolationEnable" in base_port:
            body["portIsolationEnable"] = bool(base_port.get("portIsolationEnable", False))
        if lldp_med_enable is not None:
            body["lldpMedEnable"] = bool(lldp_med_enable)
        elif "lldpMedEnable" in base_port:
            body["lldpMedEnable"] = bool(base_port.get("lldpMedEnable", True))
        if bool(body.get("lldpMedEnable")) and "topoNotifyEnable" in base_port:
            body["topoNotifyEnable"] = bool(base_port.get("topoNotifyEnable", False))
        if spanning_tree_enable is not None:
            body["spanningTreeEnable"] = bool(spanning_tree_enable)
        elif "spanningTreeEnable" in base_port:
            body["spanningTreeEnable"] = bool(base_port.get("spanningTreeEnable", False))
        for opt_k in ("bandWidthCtrlType", "flowControlEnable", "eeeEnable", "fastLeaveEnable", "loopbackDetectEnable", "dot1x"):
            if opt_k in base_port and base_port[opt_k] is not None:
                body[opt_k] = base_port[opt_k]
    return body


def update_switch_port(
    client: OmadaClient,
    deviceMac: str,
    port: int,
    enabled: bool | None = None,
    name: str | None = None,
    profileId: str | None = None,
    profileName: str | None = None,
    profileOverrideEnable: bool | None = None,
    poeEnabled: bool | None = None,
    linkSpeed: Any | None = None,
    duplex: Any | None = None,
    nativeNetworkId: str | None = None,
    taggedNetworkIds: list[str] | None = None,
    untaggedNetworkIds: list[str] | None = None,
    portIsolationEnable: bool | None = None,
    lldpMedEnable: bool | None = None,
    spanningTreeEnable: bool | None = None,
    allowUplinkMutation: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Update switch port profile, enablement, PoE mode, speed/duplex, or overrides."""
    if not isinstance(port, int) or isinstance(port, bool) or port <= 0:
        raise OmadaError(f"port must be a positive integer, got {port!r}")
    site = _site(client)
    sw_dev = resolve_raw_device(client, site, deviceMac, expected_type="switch")
    norm_mac = _normalize_mac(str(sw_dev.get("mac") or deviceMac))
    dev_mac = _omada_mac(norm_mac)
    target_id = f"{norm_mac}:{port}"
    _require_confirm("update_switch_port", target_id, dryRun, confirm)

    ports_data = collect_switch_ports_data(client, site, sw_dev, include_cable_test=False)
    port_info = next((p for p in ports_data.get("ports") or [] if as_int(p.get("port"), 0) == port), None)
    if port_info is None:
        raise OmadaError(f"port {port} was not found on switch {sw_dev.get('name') or norm_mac} ({norm_mac})")

    def _fetch_raw_port() -> dict[str, Any]:
        try:
            detail = client.api_result(f"sites/{site.site_id}/switches/{dev_mac}/ports/{port}")
            if isinstance(detail, Mapping) and detail.get("port") is not None:
                return dict(detail)
        except OmadaError:
            pass
        rows = _unwrap_rows(client.api_result(f"sites/{site.site_id}/switches/{dev_mac}/ports"))
        found = next((dict(r) for r in rows if as_int(r.get("port"), 0) == port), None)
        if found is None:
            raise OmadaError(f"raw port {port} disappeared from switch {norm_mac}")
        return found

    raw_port = _fetch_raw_port()
    profiles = _fetch_lan_profiles(client, site)
    disable_prof = next((p for p in profiles if as_int(p.get("type"), -1) == 1 or str(p.get("name") or "").strip().lower() == "disable"), None)
    all_prof = next((p for p in profiles if as_int(p.get("type"), -1) == 0 or str(p.get("name") or "").strip().lower() == "all"), None)

    target_profile_id: str | None = None
    target_profile_name: str | None = None
    if profileId is not None or profileName is not None:
        if profileId and profileName:
            p_by_id = _resolve_by_id_or_name(profiles, str(profileId), label="port profile")
            p_by_name = _resolve_by_id_or_name(profiles, str(profileName), label="port profile")
            if str(p_by_id.get("id")) != str(p_by_name.get("id")):
                raise OmadaError(f"conflicting profileId={profileId!r} and profileName={profileName!r}")
            prof = p_by_id
        else:
            prof = _resolve_by_id_or_name(
                profiles,
                str(profileId if profileId is not None else profileName),
                label="port profile",
            )
        target_profile_id = str(prof.get("id") or "")
        target_profile_name = str(prof.get("name") or "")
    elif enabled is False:
        if disable_prof is None or not disable_prof.get("id"):
            raise OmadaError(
                "built-in Disable port profile (type=1) was not found on this controller",
                hint="Pass an explicit profileId/profileName or ensure default switch profiles exist.",
            )
        target_profile_id = str(disable_prof["id"])
        target_profile_name = str(disable_prof.get("name") or "Disable")
    elif enabled is True:
        cur_pid = str(raw_port.get("profileId") or "")
        is_currently_disabled = bool(raw_port.get("disable")) or (
            disable_prof is not None and cur_pid == str(disable_prof.get("id") or "")
        )
        if is_currently_disabled:
            if all_prof is None or not all_prof.get("id"):
                raise OmadaError(
                    "port is disabled and no profileId/profileName was specified to re-enable it",
                    hint="Supply profileName (e.g. 'All') or profileId.",
                )
            target_profile_id = str(all_prof["id"])
            target_profile_name = str(all_prof.get("name") or "All")

    disabling_by_profile = disable_prof is not None and target_profile_id == str(disable_prof.get("id") or "")
    is_disabling = (enabled is False) or disabling_by_profile
    mutating_profile_or_vlan = (
        target_profile_id is not None and target_profile_id != str(raw_port.get("profileId") or "")
    ) or any(v is not None for v in (nativeNetworkId, taggedNetworkIds, untaggedNetworkIds, portIsolationEnable))

    is_uplink = bool(port_info.get("isUplink"))
    is_lag = bool(port_info.get("isLagMember")) or str(raw_port.get("operation") or "").lower() == "aggregating"
    carries_ctrl = bool(port_info.get("carriesController"))

    warnings: list[str] = []
    guard_reasons: list[str] = []
    if is_uplink:
        guard_reasons.append("detected switch uplink port")
    if is_lag:
        guard_reasons.append(f"LAG member port (lagId={port_info.get('lagId')})")
    if carries_ctrl:
        guard_reasons.append("carries controller/MCP host traffic")

    if (is_disabling or mutating_profile_or_vlan) and guard_reasons:
        msg = f"Refusing port disable/profile/VLAN change on {norm_mac} port {port}: " + "; ".join(guard_reasons)
        if not allowUplinkMutation:
            raise OmadaError(
                msg,
                hint="Pass allowUplinkMutation=True only with an out-of-band management path if this change is intentional.",
            )
        warnings.append(f"ANTI-STRANDING GUARD BYPASSED (allowUplinkMutation=True): {'; '.join(guard_reasons)}.")

    override_fields_set = any(v is not None for v in (poeEnabled, portIsolationEnable, lldpMedEnable, spanningTreeEnable))
    effective_override: bool | None
    if override_fields_set:
        if profileOverrideEnable is False:
            raise OmadaError(
                "cannot disable profileOverrideEnable while modifying poeEnabled/portIsolationEnable/lldpMedEnable/spanningTreeEnable",
                hint="Omit profileOverrideEnable or set profileOverrideEnable=True.",
            )
        effective_override = True
    else:
        effective_override = profileOverrideEnable

    poe_code: int | None = None
    if poeEnabled is not None:
        if not bool(port_info.get("poeSupported")) and poeEnabled:
            raise OmadaError(f"port {port} on switch {norm_mac} does not support PoE")
        poe_code = 1 if poeEnabled else 0

    downlinks = [d for d in (port_info.get("downlinkDevices") or []) if isinstance(d, Mapping)]
    powered_downlinks = [
        f"{d.get('name') or d.get('mac')} ({d.get('type') or 'device'})"
        for d in downlinks
        if str(d.get("type") or "").lower() in ("ap", "switch")
    ]
    if poeEnabled is False or is_disabling:
        if carries_ctrl and not allowUplinkMutation:
            raise OmadaError(
                f"Refusing to remove PoE or disable port {port} on {norm_mac}: port carries controller/MCP host traffic",
                hint="Pass allowUplinkMutation=True if overriding intentionally.",
            )
        if powered_downlinks:
            warnings.append(
                f"Disabling/removing PoE on port {port} affects connected adopted device(s): {', '.join(powered_downlinks)}."
            )

    speed_code = _parse_code_map(linkSpeed, _LINK_SPEED_TO_CODE, label="linkSpeed") if linkSpeed is not None else None
    duplex_code = _parse_code_map(duplex, _DUPLEX_TO_CODE, label="duplex") if duplex is not None else None

    if not any(
        v is not None
        for v in (
            enabled,
            name,
            target_profile_id,
            profileOverrideEnable,
            poe_code,
            speed_code,
            duplex_code,
            nativeNetworkId,
            taggedNetworkIds,
            untaggedNetworkIds,
            portIsolationEnable,
            lldpMedEnable,
            spanningTreeEnable,
        )
    ):
        raise OmadaError("specify at least one switch port attribute to update")

    body = _build_switch_port_patch(
        raw_port,
        name=name,
        profile_id=target_profile_id,
        profile_override_enable=effective_override,
        poe=poe_code,
        link_speed=speed_code,
        duplex=duplex_code,
        native_network_id=nativeNetworkId,
        tagged_network_ids=taggedNetworkIds,
        untagged_network_ids=untaggedNetworkIds,
        port_isolation_enable=portIsolationEnable,
        lldp_med_enable=lldpMedEnable,
        spanning_tree_enable=spanningTreeEnable,
    )

    before_summary = _switch_port_summary(raw_port, port_info)
    after_preview_raw = {**raw_port, **body}
    if target_profile_name:
        after_preview_raw["profileName"] = target_profile_name
    if disabling_by_profile:
        after_preview_raw["disable"] = True
    elif enabled is True:
        after_preview_raw["disable"] = False
    after_summary = _switch_port_summary(after_preview_raw, port_info)
    diff = _field_diff(before_summary, after_summary, tuple(before_summary.keys()))
    if not diff:
        warnings.append("Requested switch port state matches current controller configuration.")

    rollback = {
        "tool": "update_switch_port",
        "arguments": {
            "deviceMac": norm_mac,
            "port": port,
            "name": raw_port.get("name"),
            "profileId": raw_port.get("profileId"),
            "profileOverrideEnable": bool(raw_port.get("profileOverrideEnable", False)),
            "linkSpeed": raw_port.get("linkSpeed", 0),
            "duplex": raw_port.get("duplex", 0),
            "allowUplinkMutation": allowUplinkMutation,
            "dryRun": True,
        },
    }
    if dryRun:
        return _dry_run_result(
            tool_name="update_switch_port",
            target_id=target_id,
            before=before_summary,
            after=after_summary,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/switches/{dev_mac}/ports/{port}"

    def _read_back() -> dict[str, Any]:
        return _switch_port_summary(_fetch_raw_port(), port_info)

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, "switch port read-back did not return an object"
        if name is not None and str(after_now.get("name")) != str(name):
            return False, f"port name expected {name!r}, got {after_now.get('name')!r}"
        if target_profile_id is not None and str(after_now.get("profileId")) != target_profile_id:
            return False, f"profileId expected {target_profile_id!r}, got {after_now.get('profileId')!r}"
        if effective_override is not None and bool(after_now.get("profileOverrideEnable")) != bool(effective_override):
            return False, f"profileOverrideEnable expected {effective_override!r}"
        if poe_code is not None and body.get("profileOverrideEnable") and as_int(after_now.get("poe"), -1) != poe_code:
            return False, f"poe expected {poe_code!r}, got {after_now.get('poe')!r}"
        if speed_code is not None:
            exp_s = PORT_LINK_SPEED_LABELS.get(speed_code, str(speed_code))
            if str(after_now.get("linkSpeed")) != exp_s:
                return False, f"linkSpeed expected {exp_s!r}, got {after_now.get('linkSpeed')!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_summary, live)
        return ok, body, live

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=body,
        tool_name="update_switch_port",
        target=target_id,
        before=before_summary,
        snapshot_payload=raw_port,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()),
    )
    return _committed_result(
        tool_name="update_switch_port",
        target_id=target_id,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def cycle_poe_port(
    client: OmadaClient,
    deviceMac: str,
    port: int,
    allowUplinkMutation: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Momentarily power-cycle PoE on a switch port (``POST cmd/switches/{MAC}/ports/{port}/restart``)."""
    if not isinstance(port, int) or isinstance(port, bool) or port <= 0:
        raise OmadaError(f"port must be a positive integer, got {port!r}")
    site = _site(client)
    sw_dev = resolve_raw_device(client, site, deviceMac, expected_type="switch")
    norm_mac = _normalize_mac(str(sw_dev.get("mac") or deviceMac))
    dev_mac = _omada_mac(norm_mac)
    target_id = f"{norm_mac}:{port}"
    _require_confirm("cycle_poe_port", target_id, dryRun, confirm)

    ports_data = collect_switch_ports_data(client, site, sw_dev, include_cable_test=False)
    port_info = next((p for p in ports_data.get("ports") or [] if as_int(p.get("port"), 0) == port), None)
    if port_info is None:
        raise OmadaError(f"port {port} was not found on switch {norm_mac}")
    if not bool(port_info.get("poeSupported")):
        raise OmadaError(
            f"port {port} on switch {norm_mac} does not support PoE",
            hint="Select a PoE-capable port.",
        )

    warnings: list[str] = []
    guard_reasons: list[str] = []
    if port_info.get("carriesController"):
        guard_reasons.append("carries controller/MCP host traffic")
    if port_info.get("isUplink"):
        guard_reasons.append("detected switch uplink port")
    if port_info.get("isLagMember"):
        guard_reasons.append(f"LAG member port (lagId={port_info.get('lagId')})")
    if guard_reasons:
        msg = f"Refusing to PoE-cycle port {port} on {norm_mac}: " + "; ".join(guard_reasons)
        if not allowUplinkMutation:
            raise OmadaError(
                msg,
                hint="Pass allowUplinkMutation=True only during an out-of-band maintenance window.",
            )
        warnings.append(f"ANTI-STRANDING GUARD BYPASSED (allowUplinkMutation=True): {'; '.join(guard_reasons)}.")
    downlinks = [d for d in (port_info.get("downlinkDevices") or []) if isinstance(d, Mapping)]
    adopted_targets = [
        f"{d.get('name') or d.get('mac')} ({d.get('type') or 'device'})"
        for d in downlinks
        if str(d.get("type") or "").lower() in ("ap", "switch")
    ]
    if adopted_targets:
        warnings.append(
            f"WARNING: PoE cycle will briefly power off connected adopted device(s): {', '.join(adopted_targets)}."
        )
    if as_int(port_info.get("poeMode"), 1) == 0:
        warnings.append("Port PoE mode is currently off (poeMode=0); cycling may have no effect.")

    before = {
        "mac": norm_mac,
        "port": port,
        "name": port_info.get("name"),
        "poeMode": port_info.get("poeMode"),
        "poeDelivering": port_info.get("poeDelivering"),
        "poePowerW": port_info.get("poePowerW"),
        "downlinkDevices": downlinks,
    }
    diff = {"poeCycle": {"before": False, "after": True}}
    if dryRun:
        return _dry_run_result(
            tool_name="cycle_poe_port",
            target_id=target_id,
            before=before,
            after={**before, "poeCycleTriggered": True},
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    write_res = client.write(
        f"sites/{site.site_id}/cmd/switches/{dev_mac}/ports/{port}/restart",
        method="POST",
        data={},
        tool_name="cycle_poe_port",
        target=target_id,
        before=before,
        snapshot_payload=port_info,
        fields_changed=["poeCycle"],
    )
    return _committed_result(
        tool_name="cycle_poe_port",
        target_id=target_id,
        before=write_res["before"],
        after={**before, "poeCycleTriggered": True},
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )


def upsert_port_profile(
    client: OmadaClient,
    name: str,
    profileId: str | None = None,
    poeMode: Any | None = None,
    nativeNetworkId: str | None = None,
    nativeNetworkName: str | None = None,
    taggedNetworkIds: list[str] | None = None,
    untaggedNetworkIds: list[str] | None = None,
    portIsolationEnable: bool | None = None,
    lldpMedEnable: bool | None = None,
    spanningTreeEnable: bool | None = None,
    loopbackDetectEnable: bool | None = None,
    flowControlEnable: bool | None = None,
    eeeEnable: bool | None = None,
    dot1x: int | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a switch port profile (``setting/lan/profiles``)."""
    prof_name = str(name or "").strip()
    if not prof_name:
        raise OmadaError("port profile name must be non-empty")
    site = _site(client)
    profiles = _fetch_lan_profiles(client, site)

    existing: dict[str, Any] | None = None
    if profileId:
        existing = _resolve_by_id_or_name(profiles, str(profileId), label="port profile")
    else:
        matches = [dict(p) for p in profiles if str(p.get("name") or "").strip() == prof_name]
        if matches:
            existing = matches[0]

    if existing is not None and bool(existing.get("prohibitModify")):
        raise OmadaError(
            f"port profile {existing.get('name')!r} is protected (prohibitModify=true) and cannot be modified",
            hint="Create a custom port profile instead of modifying built-in protected profiles.",
        )

    target_id = str(existing.get("id")) if existing is not None and existing.get("id") else prof_name
    _require_confirm("upsert_port_profile", target_id, dryRun, confirm)

    resolved_native_id = nativeNetworkId
    if nativeNetworkName is not None and nativeNetworkId is None:
        nets = _fetch_lan_collection(client, site)
        net = _resolve_lan_network(nets, vlan=nativeNetworkName)
        resolved_native_id = str(net.get("id") or "")

    poe_code: int | None = None
    if poeMode is not None:
        poe_code = _parse_code_map(poeMode, _PORT_PROFILE_POE_TO_CODE, label="poeMode")

    def _summarize_prof(p: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "id": str(p.get("id") or ""),
            "name": str(p.get("name") or ""),
            "poe": p.get("poe"),
            "nativeNetworkId": p.get("nativeNetworkId"),
            "tagNetworkIds": list(p.get("tagNetworkIds") or []),
            "untagNetworkIds": list(p.get("untagNetworkIds") or []),
            "portIsolationEnable": bool(p.get("portIsolationEnable", False)),
            "lldpMedEnable": bool(p.get("lldpMedEnable", True)),
            "spanningTreeEnable": bool(p.get("spanningTreeEnable", True)),
            "loopbackDetectEnable": bool(p.get("loopbackDetectEnable", False)),
            "flowControlEnable": bool(p.get("flowControlEnable", False)),
            "eeeEnable": bool(p.get("eeeEnable", False)),
            "dot1x": p.get("dot1x", 2),
        }

    base: dict[str, Any] = copy.deepcopy(existing) if existing is not None else {
        "name": prof_name,
        "poe": 2,
        "vlanConfigEnable": False,
        "networkTagsSetting": 2,
        "nativeNetworkId": None,
        "tagNetworkIds": [],
        "untagNetworkIds": [],
        "voiceNetworkEnable": False,
        "voiceNetworkId": None,
        "voiceDscpEnable": False,
        "dot1x": 2,
        "portIsolationEnable": False,
        "lldpMedEnable": True,
        "topoNotifyEnable": False,
        "bandWidthCtrlType": 0,
        "spanningTreeEnable": True,
        "loopbackDetectEnable": False,
        "loopbackDetectVlanBasedEnable": False,
        "flowControlEnable": False,
        "eeeEnable": False,
        "fastLeaveEnable": False,
        "dot1pPriority": 0,
        "trustMode": 0,
    }
    base["name"] = prof_name
    if poe_code is not None:
        base["poe"] = poe_code
    if resolved_native_id is not None:
        base["nativeNetworkId"] = resolved_native_id or None
    if taggedNetworkIds is not None:
        base["tagNetworkIds"] = [str(x) for x in taggedNetworkIds]
        base["networkTagsSetting"] = 2
    if untaggedNetworkIds is not None:
        base["untagNetworkIds"] = [str(x) for x in untaggedNetworkIds]
        base["networkTagsSetting"] = 2
    if portIsolationEnable is not None:
        base["portIsolationEnable"] = bool(portIsolationEnable)
    if lldpMedEnable is not None:
        base["lldpMedEnable"] = bool(lldpMedEnable)
    if spanningTreeEnable is not None:
        base["spanningTreeEnable"] = bool(spanningTreeEnable)
        if spanningTreeEnable:
            base["loopbackDetectEnable"] = False
    if loopbackDetectEnable is not None:
        base["loopbackDetectEnable"] = bool(loopbackDetectEnable)
        if loopbackDetectEnable:
            base["spanningTreeEnable"] = False
    if flowControlEnable is not None:
        base["flowControlEnable"] = bool(flowControlEnable)
    if eeeEnable is not None:
        base["eeeEnable"] = bool(eeeEnable)
    if dot1x is not None:
        base["dot1x"] = int(dot1x)

    # Strip server-assigned keys on PATCH/POST
    wire_body = copy.deepcopy(base)
    for k in ("id", "site", "flag", "prohibitModify", "type", "resource", "networkConflict", "supportESEnable"):
        wire_body.pop(k, None)

    before_summary = _summarize_prof(existing) if existing is not None else None
    after_preview = _summarize_prof(base)
    diff = (
        _field_diff(before_summary, after_preview, tuple(after_preview.keys()))
        if before_summary is not None
        else {"profile": {"before": None, "after": after_preview}}
    )

    if dryRun:
        return _dry_run_result(
            tool_name="upsert_port_profile",
            target_id=target_id,
            before=before_summary,
            after=after_preview,
            diff=diff,
            warnings=[],
            rollback=None,
        )

    method = "PATCH" if existing is not None else "POST"
    endpoint = f"sites/{site.site_id}/setting/lan/profiles/{existing['id']}" if existing is not None else f"sites/{site.site_id}/setting/lan/profiles"

    def _read_back() -> dict[str, Any] | None:
        rows = _fetch_lan_profiles(client, site)
        found = None
        if existing is not None:
            found = next((r for r in rows if str(r.get("id")) == str(existing["id"])), None)
        if found is None:
            found = next((r for r in rows if str(r.get("name")) == prof_name), None)
        return _summarize_prof(found) if found else None

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, f"port profile {prof_name!r} missing on read-back"
        if str(after_now.get("name")) != prof_name:
            return False, f"profile name expected {prof_name!r}, got {after_now.get('name')!r}"
        if poe_code is not None and as_int(after_now.get("poe"), -1) != poe_code:
            return False, f"profile poe expected {poe_code!r}, got {after_now.get('poe')!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_summary, live)
        return ok, (wire_body if existing is not None else None), live

    snapshot_payload = (
        {"action": "update", "profile": existing}
        if existing is not None
        else {"action": "create", "name": prof_name, "existingIds": [str(p.get("id")) for p in profiles if p.get("id")]}
    )
    write_res = client.write(
        endpoint,
        method=method,
        data=wire_body,
        tool_name="upsert_port_profile",
        target=target_id,
        before=before_summary,
        snapshot_payload=snapshot_payload,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()),
    )
    after_prof = write_res["after"]
    rollback = {
        "tool": "delete_port_profile",
        "arguments": {"profile": str((after_prof or {}).get("id") or prof_name), "dryRun": True},
    } if existing is None and isinstance(after_prof, Mapping) else None
    return _committed_result(
        tool_name="upsert_port_profile",
        target_id=target_id,
        before=write_res["before"],
        after=after_prof,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


def delete_port_profile(
    client: OmadaClient,
    profile: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a custom wired LAN switch port profile (``DELETE setting/lan/profiles/{id}``)."""
    site = _site(client)
    profiles = _fetch_lan_profiles(client, site)
    target = _resolve_by_id_or_name(profiles, profile, label="port profile")
    if bool(target.get("prohibitModify")):
        raise OmadaError(
            f"port profile {target.get('name')!r} is protected (prohibitModify=true) and cannot be deleted",
            code=-1001,
            hint="Only custom port profiles can be deleted.",
        )
    target_id = str(target["id"])
    return _delete_entity(
        client,
        tool_name="delete_port_profile",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/lan/profiles/{target_id}",
        before=target,
        snapshot_payload={"action": "delete", "profile": target},
        fetch_all=lambda: _fetch_lan_profiles(client, site),
        match_fn=lambda row: str(row.get("id")) == target_id,
        rollback=None,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="portProfile",
    )

