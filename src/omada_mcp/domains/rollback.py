"""Write domain module: rollback."""

from __future__ import annotations

import copy
import json
import urllib.parse
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ..client import OmadaClient, OmadaError, SiteInfo
from ._common import as_int, as_mapping, deep_redact, resolve_device_detail, resolve_raw_device
from ._device_helpers import collect_switch_ports_data
from ._write_common import (
    _NON_REVERSIBLE_SNAPSHOT_TOOLS,
    _committed_result,
    _dry_run_result,
    _field_diff,
    _match_fields,
    _normalize_mac,
    _require_confirm,
    _site,
)
from ._write_fetchers import (
    _ensure_lan_patch_body,
    _fetch_devices,
    _fetch_dhcp_reservations,
    _fetch_groups,
    _fetch_lan_collection,
    _fetch_lan_dns_rules,
    _fetch_lan_pair,
    _fetch_lan_profiles,
    _fetch_mdns_rules,
    _fetch_poe_schedules,
    _fetch_policy_routes,
    _fetch_port_forwards,
    _fetch_rate_limit_profiles,
    _fetch_schedules,
    _fetch_static_routes,
    _fetch_switch_lags,
    _fetch_typed_acls,
    _omada_mac,
    _strip_client_volatiles,
)
from ._write_safety import (
    _check_dhcp_pools_safety,
    _check_lan_delete_safety,
    _check_vlan_isolation_safety,
)
from .clients_write import _client_lock_wire_aps, _lookup_client_record
from .services_write import _resolve_upnp_targets
from .switch_l2_write import _assert_ports_safe_for_l2, _fetch_raw_port
from .switch_write import _build_switch_port_patch, _check_port_safety_guard, _switch_port_summary
from .wireless_write import _redact_override_list, _verify_ap_wlan_state

_SWITCH_PORT_RESTORE_FIELDS = (
    "name", "disable", "profileId", "profileOverrideEnable", "poe", "linkSpeed", "duplex",
    "nativeNetworkId", "tagNetworkIds", "untagNetworkIds", "portIsolationEnable",
    "lldpMedEnable", "spanningTreeEnable",
)
_LAN_UPDATE_FIELDS = ("name", "domain", "igmpSnoopEnable", "icmpPingEnable", "dhcpSettings")
_DHCP_POOL_FIELDS = ("ipRangePool", "ipaddrStart", "ipaddrEnd", "ipRangeStart", "ipRangeEnd")
_DHCP_UPDATE_FIELDS = ("enable", "leasetime", "leaseTime", "dhcpns", "dnsMode", "dnsEnable", "priDns", "sndDns", "dns1", "dns2")
_DELETE_ONLY_SECRET_ROLLBACKS = ("upsert_wireguard_tunnel", "upsert_wireguard_peer", "upsert_ddns")


def _override_has_credential(row: Mapping[str, Any]) -> bool:
    return any(bool(row.get(key)) for key in ("psk", "securityKey", "pskSetting", "ppskSetting", "hasPresharedKey"))


def _resolve_snapshot_file(client: OmadaClient, snapshot_id: str) -> Path:
    sid = str(snapshot_id or "").strip()
    if not sid or "/" in sid or "\\" in sid or ".." in sid or "\x00" in sid or not sid.endswith(".json"):
        raise OmadaError(
            f"invalid snapshotId {snapshot_id!r}",
            hint="snapshotId must be a .json filename directly inside OMADA_SNAPSHOT_DIR.",
        )
    snap_root = client._snapshot_dir()
    if not snap_root.exists():
        raise OmadaError(f"snapshot directory does not exist: {snap_root}")
    root_resolved = snap_root.resolve(strict=True)
    candidate = snap_root / sid
    if not candidate.exists():
        raise OmadaError(f"snapshot file not found: {sid}")
    if candidate.is_symlink():
        raise OmadaError(f"refusing symlinked snapshot file: {sid}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise OmadaError(f"snapshotId {sid!r} resolves outside OMADA_SNAPSHOT_DIR") from exc
    if not resolved.is_file():
        raise OmadaError(f"snapshot target is not a regular file: {sid}")
    return resolved


def _check_rollback_not_superseded(
    client: OmadaClient,
    sid: str,
    orig_target: str,
    snap_timestamp: str,
    *,
    force: bool,
    scope: Mapping[str, Any],
    resource: Any,
) -> None:
    """Require newer writes on this resource to be restored in reverse order."""
    if force or not orig_target:
        return
    audit_path = client._snapshot_dir() / "audit.jsonl"
    if not audit_path.exists():
        return
    try:
        lines = audit_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    entries: list[dict[str, Any]] = []
    for raw_line in lines:
        text = raw_line.strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            entries.append(row)

    sid_idx = next((idx for idx, row in enumerate(entries) if row.get("snapshot") == sid), None)
    newer: dict[str, dict[str, Any]] = {}
    if sid_idx is not None:
        candidates = entries[sid_idx + 1:]
    else:
        candidates = [row for row in entries if snap_timestamp and str(row.get("timestamp") or "") > snap_timestamp]

    for row in candidates:
        if any(row.get(key) is not None and value != row[key] for key, value in scope.items()):
            continue
        target = row.get("target")
        result = row.get("result")
        if row.get("tool") == "rollback_from_snapshot":
            if (isinstance(target, str) and result == "success" and row.get("verified") is True
                    and scope and all(row.get(key) == value for key, value in scope.items())):
                newer.pop(target, None)
            continue
        row_resource = row.get("resource")
        if isinstance(resource, Mapping) and isinstance(row_resource, Mapping):
            same_resource = resource == row_resource
        else:
            same_resource = target == orig_target
        row_snapshot = row.get("snapshot")
        if same_resource and isinstance(row_snapshot, str) and result in ("success", "accepted", "verification_failed", "error"):
            newer[row_snapshot] = row

    if newer:
        latest = next(reversed(newer.values()))
        raise OmadaError(
            f"stale snapshot {sid!r}: newer unresolved write {latest.get('snapshot')!r} "
            f"({latest.get('tool')}) modified target {orig_target!r}",
            hint="restore the newer write first, or inspect current state before using force=true",
        )


def _validate_snapshot_scope(
    client: OmadaClient,
    site: SiteInfo,
    snapshot: Mapping[str, Any],
    snapshot_id: str,
    dry_run: bool,
) -> dict[str, str]:
    version = snapshot.get("version", 1)
    if type(version) is not int or version not in (1, 2):
        raise OmadaError(f"snapshot {snapshot_id!r} has an unsupported version")
    if version == 1:
        if not dry_run:
            raise OmadaError(
                f"legacy snapshot {snapshot_id!r} is preview-only because controller and site provenance are missing",
                hint="inspect the snapshot and use the corresponding configuration tool to preview a manual restore",
            )
        return {}

    if not client.controller_id:
        raise OmadaError(f"cannot check controller identity for snapshot {snapshot_id!r}")
    scope = {"controllerId": client.controller_id, "baseUrl": client.config.base_url.rstrip("/"), "siteId": site.site_id}
    if any(snapshot.get(key) != value for key, value in scope.items()):
        raise OmadaError(
            f"snapshot {snapshot_id!r} does not belong to the active controller and site",
            hint="select the controller and site named in the snapshot before restoring it",
        )
    return scope


def rollback_from_snapshot(
    client: OmadaClient,
    snapshotId: str,
    dryRun: bool = True,
    confirm: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Restore pre-mutation state from a saved snapshot in ``OMADA_SNAPSHOT_DIR``."""
    snap_path = _resolve_snapshot_file(client, snapshotId)
    sid = snap_path.name

    try:
        envelope = json.loads(snap_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OmadaError(f"failed to parse snapshot {sid!r}: {exc}") from exc
    if not isinstance(envelope, Mapping) or "tool" not in envelope or "data" not in envelope:
        raise OmadaError(f"snapshot {sid!r} is missing required 'tool' or 'data' fields")

    orig_tool = str(envelope["tool"] or "")
    orig_target = str(envelope.get("target") or "")
    snap_timestamp = str(envelope.get("timestamp") or "")
    snap_data = envelope.get("data")
    snap_fields = envelope.get("fieldsChanged")

    if orig_tool in _NON_REVERSIBLE_SNAPSHOT_TOOLS:
        raise OmadaError(
            f"snapshot {sid!r} was captured by non-reversible action {orig_tool!r} and cannot be rolled back",
        )

    site = _site(client)
    scope = _validate_snapshot_scope(client, site, envelope, sid, dryRun)
    inverse_delete = isinstance(snap_data, Mapping) and snap_data.get("created") is True and orig_tool in _DELETE_ONLY_SECRET_ROLLBACKS
    if isinstance(snap_data, Mapping) and not inverse_delete and (snap_data.get("manualRecoveryRequired") or snap_data.get("secretRestoreRequired")):
        raise OmadaError(
            f"snapshot {sid!r} requires manual restoration of credentials",
            hint="restore the configuration with the intended credentials; snapshots do not retain them",
        )
    _check_rollback_not_superseded(client, sid, orig_target, snap_timestamp, force=bool(force),
                                   scope=scope, resource=envelope.get("resource"))
    _require_confirm("rollback_from_snapshot", sid, dryRun, confirm)

    warnings: list[str] = [f"Rolling back snapshot {sid} created by {orig_tool} (target={orig_target})."]
    if not scope:
        warnings.append("Legacy snapshot is preview-only because its original controller and site cannot be established.")

    def _run_restore(
        *,
        method: str,
        endpoint: str,
        payload: Any,
        live_before: Any,
        restore_preview: Any,
        read_back_fn: Callable[[], Any],
        verify_fn: Callable[[Any, Any], tuple[bool, str | None]],
        revalidate: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        if isinstance(live_before, Mapping) and isinstance(restore_preview, Mapping):
            diff = _field_diff(live_before, restore_preview, tuple(restore_preview))
        else:
            diff = _field_diff({"state": live_before}, {"state": restore_preview}, ("state",))
        if dryRun:
            return _dry_run_result(
                tool_name="rollback_from_snapshot",
                target_id=sid,
                before=deep_redact(live_before),
                after=deep_redact(restore_preview),
                diff=deep_redact(diff),
                warnings=warnings,
                rollback=None,
            )

        def _reauth_prep() -> tuple[bool, dict[str, Any] | None, Any]:
            _validate_snapshot_scope(client, _site(client), envelope, sid, dryRun)
            now = read_back_fn()
            ok, _ = verify_fn(live_before, now)
            if not ok and revalidate is not None:
                if now != live_before:
                    raise OmadaError("rollback target changed during session recovery; preview the restore again")
                revalidate()
            return ok, (payload if method != "POST" else None), now

        write_res = client.write(
            endpoint,
            method=method,
            data=payload,
            tool_name="rollback_from_snapshot",
            target=sid,
            before=live_before,
            snapshot_payload={"rolledBackSnapshot": sid, "liveBefore": live_before},
            read_back=read_back_fn,
            verify_fn=verify_fn,
            reauth_prepare=_reauth_prep,
            fields_changed=[f"rollback:{orig_tool}"],
        )
        return _committed_result(
            tool_name="rollback_from_snapshot",
            target_id=sid,
            before=deep_redact(write_res["before"]),
            after=deep_redact(write_res["after"]),
            diff=deep_redact(diff),
            snapshot=write_res["snapshot"],
            warnings=warnings,
            rollback=None,
        )

    # ---- Dispatch table by originating tool ----
    if orig_tool == "set_upnp" and isinstance(snap_data, Mapping):
        desired = bool(snap_data.get("enable", False))
        ep = f"sites/{site.site_id}/setting/upnp"
        live = client.api_result(ep)
        live_obj = dict(live) if isinstance(live, Mapping) else {"enable": False}
        if desired:
            rb_wan, rb_nets = _resolve_upnp_targets(
                client,
                site,
                snap_data,
                wan_port_ids=snap_data.get("wanPortIds") if isinstance(snap_data.get("wanPortIds"), list) else None,
                network_ids=snap_data.get("networkIds") if isinstance(snap_data.get("networkIds"), list) else None,
            )
            payload: dict[str, Any] = {"enable": True, "wanPortIds": rb_wan, "networkIds": rb_nets}
        else:
            payload = {"enable": False}
        return _run_restore(
            method="PUT",
            endpoint=ep,
            payload=payload,
            live_before=live_obj,
            restore_preview={**live_obj, **payload},
            read_back_fn=lambda: dict(client.api_result(ep) or {}),
            verify_fn=lambda _b, a: (bool(a.get("enable")) == desired, f"enable expected {desired!r}"),
        )

    if orig_tool in ("set_client_fixed_ip", "release_client_fixed_ip", "update_client", "set_client_lock_to_ap", "set_client_rate_limit") and isinstance(snap_data, Mapping):
        norm_mac = _normalize_mac(orig_target or str(snap_data.get("mac") or ""))
        wire_mac = _omada_mac(norm_mac)
        live = _lookup_client_record(client, site, norm_mac, wire_mac)
        body = _strip_client_volatiles(snap_data)
        if orig_tool == "set_client_rate_limit" and "rateLimit" in snap_data:
            body["rateLimit"] = copy.deepcopy(snap_data["rateLimit"])
        if isinstance(body.get("clientLockToApSetting"), Mapping):
            lk = dict(body["clientLockToApSetting"])
            if lk.get("enable"):
                lk["aps"] = _client_lock_wire_aps(lk)
            body["clientLockToApSetting"] = lk
        ep = f"sites/{site.site_id}/clients/{wire_mac}"
        return _run_restore(
            method="PATCH",
            endpoint=ep,
            payload=body,
            live_before=_strip_client_volatiles(live),
            restore_preview=body,
            read_back_fn=lambda: _lookup_client_record(client, site, norm_mac, wire_mac),
            verify_fn=lambda _b, a: (
                bool(a)
                and (orig_tool != "set_client_lock_to_ap" or bool((a.get("clientLockToApSetting") or {}).get("enable")) == bool((snap_data.get("clientLockToApSetting") or {}).get("enable"))),
                "restored client state verification failed",
            ),
        )

    if orig_tool == "set_client_blocked" and isinstance(snap_data, Mapping):
        norm_mac = _normalize_mac(orig_target or str(snap_data.get("mac") or ""))
        wire_mac = _omada_mac(norm_mac)
        was_blocked = bool(snap_data.get("blocked", snap_data.get("block", False)))
        live = _lookup_client_record(client, site, norm_mac, wire_mac)
        ep = f"sites/{site.site_id}/cmd/clients/{wire_mac}/{'block' if was_blocked else 'unblock'}"
        return _run_restore(
            method="POST",
            endpoint=ep,
            payload={},
            live_before={"blocked": bool(live.get("blocked", live.get("block", False)))},
            restore_preview={"blocked": was_blocked},
            read_back_fn=lambda: {"blocked": bool(_lookup_client_record(client, site, norm_mac, wire_mac).get("blocked", False))},
            verify_fn=lambda _b, a: (bool(a.get("blocked")) == was_blocked, f"blocked expected {was_blocked!r}"),
        )

    if orig_tool == "update_device" and isinstance(snap_data, Mapping):
        dev = resolve_raw_device(client, site, orig_target or str(snap_data.get("mac") or ""))
        wire_mac = _omada_mac(str(dev.get("mac") or orig_target))
        dtype = str(dev.get("type") or snap_data.get("type") or "").lower()
        seg = "gateways" if dtype == "gateway" else ("switches" if dtype == "switch" else "eaps")
        ep = f"sites/{site.site_id}/{seg}/{wire_mac}"
        body = {k: snap_data[k] for k in ("name", "ledSetting") if k in snap_data}
        if not body:
            body = {"name": snap_data.get("name", dev.get("name"))}
        live_detail = dict(client.api_result(ep) or {})
        return _run_restore(
            method="PATCH",
            endpoint=ep,
            payload=body,
            live_before={k: live_detail.get(k) for k in body},
            restore_preview=body,
            read_back_fn=lambda: dict(client.api_result(ep) or {}),
            verify_fn=lambda _b, a: ("name" not in body or a.get("name") == body["name"], "device name mismatch"),
        )

    if orig_tool == "update_switch_port" and isinstance(snap_data, Mapping):
        parts = orig_target.rsplit(":", 1)
        if len(parts) != 2:
            raise OmadaError(f"cannot parse switch MAC and port from target {orig_target!r}")
        norm_mac, port_str = parts[0], parts[1]
        port_num = as_int(port_str, 0)
        if port_num < 1:
            raise OmadaError(f"invalid port number in rollback target {orig_target!r}")
        wire_mac = _omada_mac(norm_mac)
        ep = f"sites/{site.site_id}/switches/{wire_mac}/ports/{port_num}"
        live_port = _fetch_raw_port(client, site.site_id, wire_mac, port_num)
        selected = snap_fields if isinstance(snap_fields, list) else snap_data
        fields = [key for key in _SWITCH_PORT_RESTORE_FIELDS if key in selected]
        intended = {**live_port, **{key: snap_data[key] for key in fields if key in snap_data}}
        body = _build_switch_port_patch(intended)
        if any(key in fields for key in ("nativeNetworkId", "tagNetworkIds", "untagNetworkIds")):
            for key in ("networkTagsSetting", "tagNetworkIds", "untagNetworkIds"):
                if key in snap_data:
                    body[key] = copy.deepcopy(snap_data[key])
        live_summary = _switch_port_summary(live_port)
        saved_summary = _switch_port_summary(intended)
        expected = {key: saved_summary[key] for key in fields if key in body or key == "disable"}
        desired_summary = {**live_summary, **expected}

        def _guard_port_restore() -> None:
            switch = resolve_raw_device(client, site, wire_mac, expected_type="switch")
            ports = collect_switch_ports_data(client, site, switch, include_cable_test=False)
            port = next((p for p in ports.get("ports") or [] if as_int(p.get("port"), 0) == port_num), None)
            if port is None:
                raise OmadaError(f"port {port_num} was not found on switch {norm_mac}")
            _check_port_safety_guard(
                port,
                action="restore",
                norm_mac=norm_mac,
                port=port_num,
                allow_uplink_mutation=False,
                warnings=warnings,
            )

        guarded = any(key != "name" and value != live_summary[key] for key, value in expected.items())
        if guarded:
            _guard_port_restore()
        return _run_restore(
            method="PATCH",
            endpoint=ep,
            payload=body,
            live_before=live_summary,
            restore_preview=desired_summary,
            read_back_fn=lambda: _switch_port_summary(
                _fetch_raw_port(client, site.site_id, wire_mac, port_num),
            ),
            verify_fn=lambda _b, a: _match_fields(a, expected),
            revalidate=_guard_port_restore if guarded else None,
        )

    if orig_tool == "update_ap_radio" and isinstance(snap_data, Mapping):
        mac_part = orig_target.rsplit(":", 1)[0]
        wire_mac = _omada_mac(mac_part)
        ep = f"sites/{site.site_id}/eaps/{wire_mac}/config/radios"
        rs_keys = [k for k in ("radioSetting2g", "radioSetting5g", "radioSetting5g1", "radioSetting5g2", "radioSetting6g") if isinstance(snap_data.get(k), Mapping)]
        body = {k: copy.deepcopy(dict(snap_data[k])) for k in rs_keys}
        live_ap = dict(client.api_result(f"sites/{site.site_id}/eaps/{wire_mac}") or {})
        live_view = {k: live_ap.get(k) for k in rs_keys}
        return _run_restore(
            method="PUT",
            endpoint=ep,
            payload=body,
            live_before=live_view,
            restore_preview=body,
            read_back_fn=lambda: {k: dict(client.api_result(f"sites/{site.site_id}/eaps/{wire_mac}") or {}).get(k) for k in rs_keys},
            verify_fn=lambda _b, a: (
                all((a.get(k) or {}).get("channel") == body[k].get("channel") for k in rs_keys),
                "AP radio channels did not match snapshot after rollback",
            ),
        )

    if orig_tool in ("assign_ap_wlan_group", "set_ap_ssid_overrides") and isinstance(snap_data, Mapping):
        wire_mac = _omada_mac(str(snap_data.get("mac") or orig_target))
        wlan_id = str(snap_data.get("wlanId") or "")
        saved_overrides = [dict(o) for o in (snap_data.get("ssidOverrides") or []) if isinstance(o, Mapping)]
        if any(_override_has_credential(o) for o in saved_overrides):
            raise OmadaError(
                "AP WLAN rollback requires manual restoration of override credentials",
                hint="use the Omada UI with the intended passphrases; snapshots do not retain them",
            )

        def _read_ap_wlan() -> dict[str, Any]:
            ap = resolve_device_detail(client, site, wire_mac, expected_type="ap")
            overrides = [o for o in (ap.get("ssidOverrides") or []) if isinstance(o, Mapping)]
            return {
                "wlanId": str(ap.get("wlanId") or ""),
                "ssidOverrides": _redact_override_list(overrides),
                "hasOverrideCredentials": any(_override_has_credential(o) for o in overrides),
            }

        def _require_no_current_credentials(view: Mapping[str, Any]) -> None:
            if view.get("hasOverrideCredentials"):
                raise OmadaError(
                    "AP WLAN rollback could overwrite current override credentials",
                    hint="restore the configuration in the Omada UI with the intended passphrases",
                )

        if wire_mac and wlan_id:
            live_wlan = _read_ap_wlan()
            _require_no_current_credentials(live_wlan)
            body = {"wlanId": wlan_id, "ssidOverrides": saved_overrides}
            return _run_restore(
                method="PUT",
                endpoint=f"sites/{site.site_id}/eaps/{wire_mac}/config/wlans",
                payload=body,
                live_before=live_wlan,
                restore_preview=body,
                read_back_fn=_read_ap_wlan,
                verify_fn=lambda _b, a: _verify_ap_wlan_state(body, a),
                revalidate=lambda: _require_no_current_credentials(_read_ap_wlan()),
            )

    # Collections: LAN networks, ACLs, Port Profiles, Policy Routes, LAN DNS, DHCP, Port Forward, Static Routes, mDNS, IP Groups, Client settings
    if orig_tool in ("update_lan_network", "set_vlan_isolation", "set_vlan_dhcp_pools") and isinstance(snap_data, Mapping):
        lan_obj = as_mapping(snap_data.get("interface")) or snap_data
        nid = str(lan_obj.get("id") or "")
        if nid:
            def _read_lan() -> dict[str, Any]:
                collection, interface = _fetch_lan_pair(client, site, net_id=nid)
                return {"collection": collection, "interface": interface}

            live = _read_lan()
            body, _ = _ensure_lan_patch_body(live["interface"])
            if orig_tool == "set_vlan_isolation":
                fields = ["isolation"]
            elif orig_tool == "set_vlan_dhcp_pools":
                fields = ["dhcpSettings"]
            else:
                selected = snap_fields if isinstance(snap_fields, list) else lan_obj
                fields = [key for key in _LAN_UPDATE_FIELDS if key in selected]

            for key in fields:
                if key == "dhcpSettings":
                    dhcp_fields = _DHCP_POOL_FIELDS if orig_tool == "set_vlan_dhcp_pools" else _DHCP_UPDATE_FIELDS
                    snapshot_dhcp = as_mapping(lan_obj.get(key))
                    desired_dhcp = dict(as_mapping(body.get(key)))
                    for field in dhcp_fields:
                        if field in snapshot_dhcp:
                            desired_dhcp[field] = copy.deepcopy(snapshot_dhcp[field])
                        else:
                            desired_dhcp.pop(field, None)
                    body[key] = desired_dhcp
                elif key in lan_obj:
                    body[key] = copy.deepcopy(lan_obj[key])
                elif key == "isolation":
                    body[key] = False
                else:
                    raise OmadaError(f"cannot restore LAN field {key!r}: previous value is absent from the snapshot")

            expected = {key: body[key] for key in fields}

            def _check_lan_restore(interface: Mapping[str, Any]) -> None:
                if "isolation" in expected:
                    _check_vlan_isolation_safety(client, interface, bool(expected["isolation"]))
                if "dhcpSettings" in expected:
                    dhcp = as_mapping(expected["dhcpSettings"])
                    pools = dhcp.get("ipRangePool") or []
                    if not pools and dhcp.get("ipaddrStart") and dhcp.get("ipaddrEnd"):
                        pools = [{"ipaddrStart": dhcp["ipaddrStart"], "ipaddrEnd": dhcp["ipaddrEnd"]}]
                    if pools and (orig_tool == "set_vlan_dhcp_pools" or dhcp.get("enable")):
                        _check_dhcp_pools_safety(client, interface, pools, _fetch_devices(client, site))

            def _verify_lan(_before: Any, pair: Any) -> tuple[bool, str | None]:
                interface = as_mapping(as_mapping(pair).get("interface"))
                collection = as_mapping(as_mapping(pair).get("collection"))
                required = dict(expected)
                if "dhcpSettings" in expected:
                    intended_dhcp = as_mapping(expected["dhcpSettings"])
                    observed_dhcp = as_mapping(interface.get("dhcpSettings"))
                    if orig_tool == "set_vlan_dhcp_pools":
                        wanted = intended_dhcp.get("ipRangePool") or []
                        for endpoint_dhcp in (observed_dhcp, as_mapping(collection.get("dhcpSettings"))):
                            if "ipRangePool" in endpoint_dhcp and (endpoint_dhcp.get("ipRangePool") or []) != wanted:
                                return False, "LAN DHCP pool did not restore on both controller views"
                        required["dhcpSettings"] = {key: intended_dhcp[key] for key in ("ipRangePool", "ipaddrStart", "ipaddrEnd") if key in intended_dhcp}
                    else:
                        required["dhcpSettings"] = {key: intended_dhcp[key] for key in _DHCP_UPDATE_FIELDS if key in intended_dhcp}
                        unset_dns = {key for key in ("priDns", "sndDns", "dns1", "dns2") if key not in intended_dhcp}
                        if any(observed_dhcp.get(key) for key in unset_dns):
                            return False, "LAN DHCP manual DNS fields did not clear"
                if "isolation" in collection and "isolation" in expected and bool(collection["isolation"]) != bool(expected["isolation"]):
                    return False, "LAN isolation did not restore on both controller views"
                return _match_fields(interface, required)

            _check_lan_restore(live["interface"])
            collection_preview = {**live["collection"], **{key: body[key] for key in fields if key in live["collection"]}}
            return _run_restore(
                method="PATCH",
                endpoint=f"sites/{site.site_id}/setting/lan/networks/{nid}",
                payload=body,
                live_before=live,
                restore_preview={"collection": collection_preview, "interface": body},
                read_back_fn=_read_lan,
                verify_fn=_verify_lan,
                revalidate=lambda: _check_lan_restore(_read_lan()["interface"]),
            )

    if orig_tool == "create_lan_network" and isinstance(snap_data, Mapping):
        existing_ids = {str(r.get("id")) for r in (snap_data.get("existingNetworks") or []) if isinstance(r, Mapping) and r.get("id")}
        rows = _fetch_lan_collection(client, site)
        target = next((r for r in rows if str(r.get("name")) == orig_target and str(r.get("id")) not in existing_ids), None)
        if target is None or not target.get("id"):
            raise OmadaError(f"cannot locate created LAN network {orig_target!r} to delete on rollback")
        nid = str(target["id"])

        def _read_created_lan() -> dict[str, Any] | None:
            return next((row for row in _fetch_lan_collection(client, site) if str(row.get("id")) == nid), None)

        def _guard_lan_delete() -> None:
            collection = _read_created_lan()
            if collection is None:
                raise OmadaError(f"cannot locate created LAN network {nid!r} to delete on rollback")
            _check_lan_delete_safety(client, collection)
            if collection.get("purpose") == "interface":
                _, interface = _fetch_lan_pair(client, site, net_id=nid)
                if interface.get("gatewaySubnet") != collection.get("gatewaySubnet"):
                    _check_lan_delete_safety(client, interface)

        _guard_lan_delete()
        return _run_restore(
            method="DELETE",
            endpoint=f"sites/{site.site_id}/setting/lan/networks/{nid}",
            payload=None,
            live_before=target,
            restore_preview=None,
            read_back_fn=_read_created_lan,
            verify_fn=lambda _b, a: (a is None, f"LAN network {nid} still present"),
            revalidate=_guard_lan_delete,
        )

    if orig_tool == "delete_lan_network" and isinstance(snap_data, Mapping):
        body = {k: copy.deepcopy(v) for k, v in snap_data.items() if k not in ("id", "site", "resource", "default")}
        rows = _fetch_lan_collection(client, site)
        live = next((r for r in rows if str(r.get("name")) == str(snap_data.get("name"))), None)
        if live is not None:
            raise OmadaError(f"LAN network {snap_data.get('name')!r} already exists on controller")
        return _run_restore(
            method="POST",
            endpoint=f"sites/{site.site_id}/setting/lan/networks",
            payload=body,
            live_before=None,
            restore_preview=snap_data,
            read_back_fn=lambda: next((r for r in _fetch_lan_collection(client, site) if str(r.get("name")) == str(snap_data.get("name"))), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == str(snap_data.get("name")), "recreated LAN network missing on read-back"),
        )

    if orig_tool in ("upsert_dhcp_reservation", "delete_dhcp_reservation") and isinstance(snap_data, Mapping):
        if "existingReservations" in snap_data:
            wire_mac = _omada_mac(orig_target)
            norm_mac = _normalize_mac(wire_mac)
            rows = _fetch_dhcp_reservations(client, site)
            target = next((r for r in rows if _normalize_mac(r.get("mac", "")) == norm_mac), None)
            if target is None:
                raise OmadaError(f"cannot locate created DHCP reservation {norm_mac!r} to delete on rollback")
            del_mac = urllib.parse.quote(str(target["mac"]), safe="")
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/service/dhcp/{del_mac}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_dhcp_reservations(client, site),
                verify_fn=lambda _b, a: (all(_normalize_mac(r.get("mac", "")) != norm_mac for r in a), f"DHCP reservation {norm_mac} still present"),
            )
        norm_mac = _normalize_mac(str(snap_data.get("mac") or orig_target))
        rows = _fetch_dhcp_reservations(client, site)
        live = next((r for r in rows if _normalize_mac(r.get("mac", "")) == norm_mac), None)
        body = {k: copy.deepcopy(v) for k, v in snap_data.items() if k not in ("id", "site", "resource")}
        method = "PUT" if live is not None else "POST"
        mac_q = urllib.parse.quote(str(live["mac"]), safe="") if live is not None else ""
        ep = f"sites/{site.site_id}/setting/service/dhcp/{mac_q}" if method == "PUT" else f"sites/{site.site_id}/setting/service/dhcp"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=snap_data,
            read_back_fn=lambda: next((r for r in _fetch_dhcp_reservations(client, site) if _normalize_mac(r.get("mac", "")) == norm_mac), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("ip")) == str(snap_data.get("ip")), "DHCP reservation rollback verification failed"),
        )

    if orig_tool in ("upsert_port_forward", "delete_port_forward") and isinstance(snap_data, Mapping):
        if "existingPortForwards" in snap_data:
            existing_ids = {str(r.get("id")) for r in (snap_data.get("existingPortForwards") or []) if isinstance(r, Mapping) and r.get("id")}
            rows = _fetch_port_forwards(client, site)
            target = next((r for r in rows if (str(r.get("name")) == orig_target or str(r.get("id")) == orig_target) and str(r.get("id")) not in existing_ids), None)
            if target is None or not target.get("id"):
                raise OmadaError(f"cannot locate created port forward {orig_target!r} to delete on rollback")
            rid = str(target["id"])
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/transmission/portForwardings/{rid}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_port_forwards(client, site),
                verify_fn=lambda _b, a: (all(str(r.get("id")) != rid for r in a), f"port forward {rid} still present"),
            )
        rid = str(snap_data.get("id") or "")
        rows = _fetch_port_forwards(client, site)
        live = next((r for r in rows if str(r.get("id")) == rid), None)
        body = {k: copy.deepcopy(v) for k, v in snap_data.items() if k not in ("id", "site", "resource")}
        method = "PUT" if live is not None else "POST"
        ep = f"sites/{site.site_id}/setting/transmission/portForwardings/{rid}" if method == "PUT" else f"sites/{site.site_id}/setting/transmission/portForwardings"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=snap_data,
            read_back_fn=lambda: next((r for r in _fetch_port_forwards(client, site) if str(r.get("name")) == str(snap_data.get("name"))), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == str(snap_data.get("name")), "port forward rollback verification failed"),
        )

    if orig_tool in ("upsert_static_route", "delete_static_route") and isinstance(snap_data, Mapping):
        if "existingStaticRoutes" in snap_data:
            existing_ids = {str(r.get("id")) for r in (snap_data.get("existingStaticRoutes") or []) if isinstance(r, Mapping) and r.get("id")}
            rows = _fetch_static_routes(client, site)
            target = next((r for r in rows if (str(r.get("name")) == orig_target or str(r.get("id")) == orig_target) and str(r.get("id")) not in existing_ids), None)
            if target is None or not target.get("id"):
                raise OmadaError(f"cannot locate created static route {orig_target!r} to delete on rollback")
            rid = str(target["id"])
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/transmission/staticRoutings/{rid}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_static_routes(client, site),
                verify_fn=lambda _b, a: (all(str(r.get("id")) != rid for r in a), f"static route {rid} still present"),
            )
        rid = str(snap_data.get("id") or "")
        rows = _fetch_static_routes(client, site)
        live = next((r for r in rows if str(r.get("id")) == rid), None)
        body = {k: copy.deepcopy(v) for k, v in snap_data.items() if k not in ("id", "site", "resource")}
        method = "PUT" if live is not None else "POST"
        ep = f"sites/{site.site_id}/setting/transmission/staticRoutings/{rid}" if method == "PUT" else f"sites/{site.site_id}/setting/transmission/staticRoutings"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=snap_data,
            read_back_fn=lambda: next((r for r in _fetch_static_routes(client, site) if str(r.get("name")) == str(snap_data.get("name"))), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == str(snap_data.get("name")), "static route rollback verification failed"),
        )

    if orig_tool in ("upsert_mdns_rule", "delete_mdns_rule") and isinstance(snap_data, Mapping):
        if "existingMdnsRules" in snap_data:
            existing_ids = {str(r.get("id")) for r in (snap_data.get("existingMdnsRules") or []) if isinstance(r, Mapping) and r.get("id")}
            rows = _fetch_mdns_rules(client, site)
            target = next((r for r in rows if (str(r.get("name")) == orig_target or str(r.get("id")) == orig_target) and str(r.get("id")) not in existing_ids), None)
            if target is None or not target.get("id"):
                raise OmadaError(f"cannot locate created mDNS rule {orig_target!r} to delete on rollback")
            rid = str(target["id"])
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/service/mdns/{rid}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_mdns_rules(client, site),
                verify_fn=lambda _b, a: (all(str(r.get("id")) != rid for r in a), f"mDNS rule {rid} still present"),
            )
        rid = str(snap_data.get("id") or "")
        rows = _fetch_mdns_rules(client, site)
        live = next((r for r in rows if str(r.get("id")) == rid), None)
        body = {k: copy.deepcopy(v) for k, v in snap_data.items() if k not in ("id", "site", "resource")}
        method = "PUT" if live is not None else "POST"
        ep = f"sites/{site.site_id}/setting/service/mdns/{rid}" if method == "PUT" else f"sites/{site.site_id}/setting/service/mdns"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=snap_data,
            read_back_fn=lambda: next((r for r in _fetch_mdns_rules(client, site) if str(r.get("name")) == str(snap_data.get("name"))), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == str(snap_data.get("name")), "mDNS rule rollback verification failed"),
        )

    if orig_tool == "create_ip_group" and isinstance(snap_data, Mapping) and "existingIpGroups" in snap_data:
        existing_ids = {str(r.get("groupId") or r.get("id")) for r in (snap_data.get("existingIpGroups") or []) if isinstance(r, Mapping)}
        rows = _fetch_groups(client, site)
        target = next((r for r in rows if str(r.get("name")) == orig_target and str(r.get("groupId") or r.get("id")) not in existing_ids), None)
        if target is None:
            raise OmadaError(f"cannot locate created IP group {orig_target!r} to delete on rollback")
        gid = str(target.get("groupId") or target.get("id") or "")
        return _run_restore(
            method="DELETE",
            endpoint=f"sites/{site.site_id}/setting/profiles/groups/0/{gid}",
            payload=None,
            live_before=target,
            restore_preview=None,
            read_back_fn=lambda: _fetch_groups(client, site),
            verify_fn=lambda _b, a: (all(str(r.get("groupId") or r.get("id") or "") != gid for r in a), f"IP group {gid} still present"),
        )

    if orig_tool in ("upsert_port_group", "delete_port_group", "upsert_mac_group", "delete_mac_group") and isinstance(snap_data, Mapping):
        gtype = int(snap_data.get("groupType", 1 if "port_group" in orig_tool else 2))
        if snap_data.get("action") == "create":
            existing_ids = set(snap_data.get("existingIds") or [])
            rows = [r for r in _fetch_groups(client, site) if int(r.get("type", 0)) == gtype]
            target = next(
                (r for r in rows if str(r.get("name")) == str(snap_data.get("name")) and str(r.get("groupId") or r.get("id") or "") not in existing_ids),
                None,
            )
            if target is None:
                raise OmadaError(f"cannot locate created group {snap_data.get('name')!r} to delete on rollback")
            gid = str(target.get("groupId") or target.get("id") or "")
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/profiles/groups/{gtype}/{gid}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_groups(client, site),
                verify_fn=lambda _b, a: (all(str(r.get("groupId") or r.get("id") or "") != gid for r in a), f"group {gid} still present"),
            )
        grp = as_mapping(snap_data.get("group")) or snap_data
        gid = str(grp.get("groupId") or grp.get("id") or "")
        grp_name_rb = str(grp.get("name") or "")
        rows = [r for r in _fetch_groups(client, site) if int(r.get("type", 0)) == gtype]
        live = next((r for r in rows if str(r.get("groupId") or r.get("id") or "") == gid), None)
        body = {k: copy.deepcopy(v) for k, v in grp.items() if k not in ("id", "groupId", "site", "resource", "count", "portType", "portMaskList")}
        method = "PATCH" if live is not None and gid else "POST"
        ep = f"sites/{site.site_id}/setting/profiles/groups/{gtype}/{gid}" if method == "PATCH" else f"sites/{site.site_id}/setting/profiles/groups"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=grp,
            read_back_fn=lambda: next((r for r in _fetch_groups(client, site) if int(r.get("type", 0)) == gtype and str(r.get("name")) == grp_name_rb), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == grp_name_rb, "group rollback verification failed"),
        )

    if orig_tool in ("upsert_schedule", "delete_schedule") and isinstance(snap_data, Mapping):
        if snap_data.get("action") == "create":
            existing_ids = set(snap_data.get("existingIds") or [])
            rows = _fetch_schedules(client, site)
            target = next((r for r in rows if str(r.get("name")) == str(snap_data.get("name")) and str(r.get("id") or "") not in existing_ids), None)
            if target is None or not target.get("id"):
                raise OmadaError(f"cannot locate created schedule {snap_data.get('name')!r} to delete on rollback")
            tid = str(target["id"])
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/profiles/timeranges/{tid}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_schedules(client, site),
                verify_fn=lambda _b, a: (all(str(r.get("id")) != tid for r in a), f"schedule {tid} still present"),
            )
        sched = as_mapping(snap_data.get("schedule")) or snap_data
        tid = str(sched.get("id") or "")
        sched_name_rb = str(sched.get("name") or "")
        body = {k: copy.deepcopy(v) for k, v in sched.items() if k not in ("id", "site", "resource", "entryId")}
        live = next((r for r in _fetch_schedules(client, site) if str(r.get("id")) == tid), None)
        method = "PATCH" if live is not None and tid else "POST"
        ep = f"sites/{site.site_id}/setting/profiles/timeranges/{tid}" if method == "PATCH" else f"sites/{site.site_id}/setting/profiles/timeranges"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=sched,
            read_back_fn=lambda: next((r for r in _fetch_schedules(client, site) if str(r.get("name")) == sched_name_rb), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == sched_name_rb, "schedule rollback verification failed"),
        )

    if orig_tool in ("upsert_port_profile", "delete_port_profile") and isinstance(snap_data, Mapping):
        if snap_data.get("action") == "create":
            existing_ids = set(snap_data.get("existingIds") or [])
            rows = _fetch_lan_profiles(client, site)
            target = next((r for r in rows if str(r.get("name")) == snap_data.get("name") and str(r.get("id")) not in existing_ids), None)
            if target is None:
                raise OmadaError(f"cannot locate newly created port profile {snap_data.get('name')!r} to delete on rollback")
            pid = str(target["id"])
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/lan/profiles/{pid}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_lan_profiles(client, site),
                verify_fn=lambda _b, a: (all(str(r.get("id")) != pid for r in a), f"port profile {pid} still exists"),
            )
        prof = as_mapping(snap_data.get("profile")) or snap_data
        pid = str(prof.get("id") or "")
        prof_name_rb = str(prof.get("name"))
        wire_body = {k: copy.deepcopy(v) for k, v in prof.items() if k not in ("id", "site", "flag", "prohibitModify", "type", "resource", "networkConflict", "supportESEnable")}
        live = next((r for r in _fetch_lan_profiles(client, site) if str(r.get("id")) == pid), None)
        method = "PATCH" if live is not None and pid else "POST"
        ep = f"sites/{site.site_id}/setting/lan/profiles/{pid}" if method == "PATCH" else f"sites/{site.site_id}/setting/lan/profiles"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=wire_body,
            live_before=live,
            restore_preview=prof,
            read_back_fn=lambda: next((r for r in _fetch_lan_profiles(client, site) if str(r.get("name")) == prof_name_rb), {}),
            verify_fn=lambda _b, a: (bool(a) and str(a.get("name")) == prof_name_rb, "port profile rollback mismatch"),
        )

    if orig_tool in ("upsert_policy_route", "delete_policy_route") and isinstance(snap_data, Mapping):
        if snap_data.get("action") == "create":
            existing_ids = set(snap_data.get("existingIds") or [])
            rows = _fetch_policy_routes(client, site)
            target = next((r for r in rows if str(r.get("name")) == snap_data.get("name") and str(r.get("id")) not in existing_ids), None)
            if target is None:
                raise OmadaError(f"cannot locate created policy route {snap_data.get('name')!r} to delete on rollback")
            rid = str(target["id"])
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/transmission/policyRoutings/{rid}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_policy_routes(client, site),
                verify_fn=lambda _b, a: (all(str(r.get("id")) != rid for r in a), f"policy route {rid} still present"),
            )
        rule = as_mapping(snap_data.get("rule")) or snap_data
        rid = str(rule.get("id") or "")
        rule_name_rb = str(rule.get("name"))
        body = {k: copy.deepcopy(v) for k, v in rule.items() if k not in ("id", "site", "resource")}
        rows = _fetch_policy_routes(client, site)
        live = next((r for r in rows if str(r.get("id")) == rid), None)
        method = "PUT" if live is not None else "POST"
        ep = f"sites/{site.site_id}/setting/transmission/policyRoutings/{rid}" if method == "PUT" else f"sites/{site.site_id}/setting/transmission/policyRoutings"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=rule,
            read_back_fn=lambda: next((r for r in _fetch_policy_routes(client, site) if str(r.get("name")) == rule_name_rb), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == rule_name_rb, "policy route rollback verification failed"),
        )

    if orig_tool in ("upsert_lan_dns_rule", "delete_lan_dns_rule") and isinstance(snap_data, Mapping):
        if snap_data.get("action") == "create":
            existing_ids = set(snap_data.get("existingIds") or [])
            rows = _fetch_lan_dns_rules(client, site)
            target = next((r for r in rows if str(r.get("name")) == snap_data.get("name") and str(r.get("id")) not in existing_ids), None)
            if target is None:
                raise OmadaError(f"cannot locate created LAN DNS rule {snap_data.get('name')!r} to delete on rollback")
            did = str(target["id"])
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/lan/dns/{did}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_lan_dns_rules(client, site),
                verify_fn=lambda _b, a: (all(str(r.get("id")) != did for r in a), f"LAN DNS rule {did} still present"),
            )
        rule = as_mapping(snap_data.get("rule")) or snap_data
        did = str(rule.get("id") or "")
        dns_rule_name_rb = str(rule.get("name"))
        body = {k: copy.deepcopy(v) for k, v in rule.items() if k not in ("id", "site", "resource")}
        rows = _fetch_lan_dns_rules(client, site)
        live = next((r for r in rows if str(r.get("id")) == did), None)
        method = "PATCH" if live is not None else "POST"
        ep = f"sites/{site.site_id}/setting/lan/dns/{did}" if method == "PATCH" else f"sites/{site.site_id}/setting/lan/dns"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=rule,
            read_back_fn=lambda: next((r for r in _fetch_lan_dns_rules(client, site) if str(r.get("name")) == dns_rule_name_rb), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == dns_rule_name_rb, "LAN DNS rollback verification failed"),
        )

    if orig_tool in ("create_gateway_acl", "create_switch_acl", "create_eap_acl") and isinstance(snap_data, Mapping):
        acl_type = int(snap_data.get("type", 1 if orig_tool == "create_switch_acl" else (2 if orig_tool == "create_eap_acl" else 0)))
        existing_ids = {str(r.get("id")) for r in (snap_data.get("existingAcls") or []) if isinstance(r, Mapping) and r.get("id")}
        rows = _fetch_typed_acls(client, site, acl_type)
        target = next((r for r in rows if str(r.get("name")) == orig_target and str(r.get("id")) not in existing_ids), None)
        if target is None:
            target = next((r for r in rows if str(r.get("name")) == orig_target), None)
        if target is None or not target.get("id"):
            raise OmadaError(f"cannot locate created ACL {orig_target!r} (type={acl_type}) to delete on rollback")
        aid = str(target["id"])
        return _run_restore(
            method="DELETE",
            endpoint=f"sites/{site.site_id}/setting/firewall/acls/{aid}?type={acl_type}",
            payload=None,
            live_before=target,
            restore_preview=None,
            read_back_fn=lambda: _fetch_typed_acls(client, site, acl_type),
            verify_fn=lambda _b, a: (all(str(r.get("id")) != aid for r in a), f"ACL {aid} still present"),
        )

    if orig_tool in ("update_gateway_acl", "set_acl_rule_status", "delete_gateway_acl") and isinstance(snap_data, Mapping):
        acl_type = int(snap_data.get("type", 0))
        aid = str(snap_data.get("id") or "")
        rows = _fetch_typed_acls(client, site, acl_type)
        live = next((r for r in rows if str(r.get("id")) == aid), None)
        body = {k: copy.deepcopy(v) for k, v in snap_data.items() if k not in ("id", "site", "index", "resource")}
        method = "PUT" if live is not None and aid else "POST"
        ep = f"sites/{site.site_id}/setting/firewall/acls/{aid}?type={acl_type}" if method == "PUT" else f"sites/{site.site_id}/setting/firewall/acls?type={acl_type}"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=snap_data,
            read_back_fn=lambda: next((r for r in _fetch_typed_acls(client, site, acl_type) if str(r.get("name")) == str(snap_data.get("name"))), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == str(snap_data.get("name")), "ACL rollback verification failed"),
        )

    if orig_tool in ("upsert_rate_limit_profile", "delete_rate_limit_profile") and isinstance(snap_data, Mapping):
        if snap_data.get("action") == "create":
            existing_ids = set(snap_data.get("existingIds") or [])
            rows = _fetch_rate_limit_profiles(client, site)
            target = next(
                (r for r in rows if str(r.get("name")) == str(snap_data.get("name")) and str(r.get("id")) not in existing_ids),
                None,
            ) or next((r for r in rows if str(r.get("name")) == str(snap_data.get("name"))), None)
            if target is None or not target.get("id"):
                raise OmadaError(f"cannot locate created rate-limit profile {snap_data.get('name')!r} to delete on rollback")
            pid = str(target["id"])
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/profiles/rateLimits/{pid}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_rate_limit_profiles(client, site),
                verify_fn=lambda _b, a: (all(str(r.get("id")) != pid for r in a), f"rate-limit profile {pid} still present"),
            )
        prof = as_mapping(snap_data.get("profile")) or snap_data
        pid = str(prof.get("id") or "")
        pname = str(prof.get("name") or "")
        body = {
            "name": pname,
            "downLimitEnable": bool(prof.get("downLimitEnable", False)),
            "downLimit": as_int(prof.get("downLimit"), 0) if prof.get("downLimitEnable") else 0,
            "downLimitUnit": as_int(prof.get("downLimitUnit"), 1) or 1,
            "upLimitEnable": bool(prof.get("upLimitEnable", False)),
            "upLimit": as_int(prof.get("upLimit"), 0) if prof.get("upLimitEnable") else 0,
            "upLimitUnit": as_int(prof.get("upLimitUnit"), 1) or 1,
        }
        rows = _fetch_rate_limit_profiles(client, site)
        live = next((r for r in rows if str(r.get("id")) == pid), None)
        method = "PATCH" if live is not None and pid else "POST"
        ep = f"sites/{site.site_id}/setting/profiles/rateLimits/{pid}" if method == "PATCH" else f"sites/{site.site_id}/setting/profiles/rateLimits"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=prof,
            read_back_fn=lambda: next((r for r in _fetch_rate_limit_profiles(client, site) if str(r.get("name")) == pname), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == pname, "rate-limit rollback verification failed"),
        )

    if orig_tool in ("upsert_poe_schedule", "bind_poe_schedule", "delete_poe_schedule") and isinstance(snap_data, Mapping):
        if snap_data.get("action") == "create":
            rows = _fetch_poe_schedules(client, site)
            target = next((r for r in rows if str(r.get("name")) == str(snap_data.get("name"))), None)
            if target is None or not target.get("id"):
                raise OmadaError(f"cannot locate created PoE schedule {snap_data.get('name')!r} to delete on rollback")
            pid = str(target["id"])
            return _run_restore(
                method="DELETE",
                endpoint=f"sites/{site.site_id}/setting/service/poeSchedules/{pid}",
                payload=None,
                live_before=target,
                restore_preview=None,
                read_back_fn=lambda: _fetch_poe_schedules(client, site),
                verify_fn=lambda _b, a: (all(str(r.get("id")) != pid for r in a), f"PoE schedule {pid} still present"),
            )
        poe = as_mapping(snap_data.get("poeSchedule")) or snap_data
        pname = str(poe.get("name") or "")
        rows = _fetch_poe_schedules(client, site)
        live = next((r for r in rows if str(r.get("name")) == pname), None)
        pid = str(live["id"]) if live and live.get("id") else str(poe.get("id") or "")
        body = {
            "name": pname,
            "status": bool(poe.get("status", True)),
            "turnOnTime": str(poe.get("turnOnTime") or ""),
            "poePortsMap": copy.deepcopy(poe.get("poePortsMap") or {}),
        }
        method = "PUT" if live is not None and pid else "POST"
        ep = f"sites/{site.site_id}/setting/service/poeSchedules/{pid}" if method == "PUT" else f"sites/{site.site_id}/setting/service/poeSchedules"
        return _run_restore(
            method=method,
            endpoint=ep,
            payload=body,
            live_before=live,
            restore_preview=poe,
            read_back_fn=lambda: next((r for r in _fetch_poe_schedules(client, site) if str(r.get("name")) == pname), None),
            verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name")) == pname, "PoE schedule rollback verification failed"),
        )

    if orig_tool == "update_switch_global_features" and isinstance(snap_data, Mapping):
        before_sw = as_mapping(snap_data.get("before"))
        raw_sw = as_mapping(snap_data.get("raw"))
        dev_mac = _omada_mac(str(snap_data.get("mac") or orig_target))
        is_es = bool(snap_data.get("es", False))
        if before_sw and orig_target.endswith(":general"):
            gen_body = {
                "name": str(raw_sw.get("name") or dev_mac),
                "ledSetting": as_int(raw_sw.get("ledSetting"), 2),
                "tagIds": list(raw_sw.get("tagIds") or []),
                "jumbo": before_sw.get("jumbo", 1518),
                "jumboEnable": bool(before_sw.get("jumboEnable", False)),
            }
            live_sw = resolve_device_detail(client, site, dev_mac, expected_type="switch")
            return _run_restore(
                method="PUT",
                endpoint=f"sites/{site.site_id}/switches/{'es/' if is_es else ''}{dev_mac}/config/general",
                payload=gen_body,
                live_before=deep_redact(live_sw),
                restore_preview=before_sw,
                read_back_fn=lambda: deep_redact(resolve_device_detail(client, site, dev_mac, expected_type="switch")),
                verify_fn=lambda _b, a: (isinstance(a, Mapping) and a.get("jumbo") == gen_body["jumbo"], "switch general features rollback verification failed"),
            )
        if before_sw:
            svc_body = {
                "stp": 0 if (is_es and before_sw.get("loopbackDetectEnable")) else before_sw.get("stp", 2),
                "priority": before_sw.get("priority", 32768),
                "helloTime": before_sw.get("helloTime", 2),
                "maxAge": before_sw.get("maxAge", 20),
                "forwardDelay": before_sw.get("forwardDelay", 15),
                "txHoldCount": before_sw.get("txHoldCount", 5),
                "maxHops": before_sw.get("maxHops", 20),
                "loopbackDetectEnable": bool(before_sw.get("loopbackDetectEnable", False)),
            }
            live_sw = resolve_device_detail(client, site, dev_mac, expected_type="switch")
            return _run_restore(
                method="PUT",
                endpoint=f"sites/{site.site_id}/switches/{dev_mac}/config/services",
                payload=svc_body,
                live_before=deep_redact(live_sw),
                restore_preview=before_sw,
                read_back_fn=lambda: deep_redact(resolve_device_detail(client, site, dev_mac, expected_type="switch")),
                verify_fn=lambda _b, a: (isinstance(a, Mapping) and a.get("stp") == svc_body["stp"], "switch global features rollback verification failed"),
            )

    if orig_tool == "set_switch_port_mirror" and isinstance(snap_data, Mapping):
        dev_mac = _omada_mac(str(snap_data.get("mac") or ""))
        mport = as_int(snap_data.get("mirroringPort"), 0)
        raw_p = as_mapping(snap_data.get("rawPort")) or {}
        if dev_mac and mport > 0:
            def _raw_mirror_port() -> dict[str, Any]:
                return _fetch_raw_port(client, site.site_id, dev_mac, mport)

            def _mirror_state(port: Mapping[str, Any]) -> dict[str, Any]:
                return {
                    "operation": str(port.get("operation") or "switching"),
                    "mirroredPorts": sorted(as_int(p, 0) for p in (port.get("mirroredPorts") or [])),
                    "mirroredLags": sorted(as_int(p.get("lagId") if isinstance(p, Mapping) else p, 0) for p in (port.get("mirroredLags") or [])),
                }

            live_port = _raw_mirror_port()
            mirror_before = _mirror_state(live_port)
            payload = _build_switch_port_patch(live_port)
            op = str(raw_p.get("operation") or "switching")
            expected_mirror = _mirror_state(raw_p)
            payload["operation"] = op
            if op == "mirroring":
                payload["mirroredPorts"] = expected_mirror["mirroredPorts"]
                payload["mirroredLags"] = expected_mirror["mirroredLags"]
            else:
                expected_mirror = {"operation": op}

            def _guard_mirror_restore() -> None:
                switch = resolve_raw_device(client, site, dev_mac, expected_type="switch")
                ports = collect_switch_ports_data(client, site, switch, include_cable_test=False)
                port = next((p for p in ports.get("ports") or [] if as_int(p.get("port"), 0) == mport), None)
                if port is None:
                    raise OmadaError(f"mirror destination port {mport} disappeared")
                _check_port_safety_guard(
                    port,
                    action="restore mirror destination",
                    norm_mac=_normalize_mac(dev_mac),
                    port=mport,
                    allow_uplink_mutation=False,
                    warnings=warnings,
                )

            _guard_mirror_restore()
            return _run_restore(
                method="PATCH",
                endpoint=f"sites/{site.site_id}/switches/{dev_mac}/ports/{mport}",
                payload=payload,
                live_before=mirror_before,
                restore_preview=expected_mirror,
                read_back_fn=lambda: _mirror_state(_raw_mirror_port()),
                verify_fn=lambda _b, a: _match_fields(a, expected_mirror),
                revalidate=_guard_mirror_restore,
            )

    if orig_tool in ("upsert_switch_lag", "delete_switch_lag") and isinstance(snap_data, Mapping):
        dev_mac = _omada_mac(str(snap_data.get("mac") or ""))
        lid = as_int(snap_data.get("lagId"), 0)
        if dev_mac and lid > 0:
            def _read_lag() -> dict[str, Any] | None:
                return next((row for row in _fetch_switch_lags(client, site, dev_mac) if as_int(row.get("lagId"), -1) == lid), None)

            live_lag = _read_lag()
            lag_obj = as_mapping(snap_data.get("lag"))
            ports_rb = [as_int(port, 0) for port in (lag_obj.get("ports") or [])]
            live_ports = [as_int(port, 0) for port in (as_mapping(live_lag).get("ports") or [])]
            affected_ports = sorted(set(ports_rb + live_ports))

            def _guard_lag_restore() -> None:
                if not affected_ports or any(port < 1 for port in affected_ports):
                    raise OmadaError(f"cannot verify current LAG {lid} member ports for rollback")
                switch = resolve_raw_device(client, site, dev_mac, expected_type="switch")
                ports = collect_switch_ports_data(client, site, switch, include_cable_test=False)
                _assert_ports_safe_for_l2(
                    _normalize_mac(dev_mac), affected_ports, ports,
                    action_label=f"restoring LAG {lid}", allow_uplink=False, warnings=warnings,
                )
                for port in ports_rb:
                    current = _fetch_raw_port(client, site.site_id, dev_mac, port)
                    operation = str(current.get("operation") or "switching")
                    active_lag = as_int(as_mapping(current.get("lagSetting")).get("lagId", current.get("lagId")), 0)
                    if operation == "mirroring" or (operation == "aggregating" and active_lag != lid):
                        raise OmadaError(f"port {port} is now assigned to a different switch operation")

            if snap_data.get("action") == "create":
                if live_lag is None:
                    raise OmadaError(f"LAG {lid} not found on switch {dev_mac} for rollback delete")
                _guard_lag_restore()
                return _run_restore(
                    method="DELETE",
                    endpoint=f"sites/{site.site_id}/switches/{dev_mac}/lags/{lid}",
                    payload=None,
                    live_before=live_lag,
                    restore_preview=None,
                    read_back_fn=_read_lag,
                    verify_fn=lambda _b, a: (a is None, f"LAG {lid} still present"),
                    revalidate=_guard_lag_restore,
                )
            if lag_obj and len(set(ports_rb)) >= 2:
                _guard_lag_restore()
                body = {
                    "name": lag_obj.get("name") or f"LAG {lid}",
                    "profileId": str(lag_obj.get("profileId") or ""),
                    "profileOverrideEnable": bool(lag_obj.get("profileOverrideEnable", False)),
                    "operation": "aggregating",
                    "lagSetting": {"lagId": lid, "lagType": lag_obj.get("lagType", 1), "ports": ports_rb},
                }

                def _verify_lag(_b: Any, after: Any) -> tuple[bool, str | None]:
                    fields = ("name", "profileId", "lagType")
                    observed = as_mapping(after)
                    if sorted(as_int(port, 0) for port in (observed.get("ports") or [])) != sorted(ports_rb):
                        return False, f"LAG {lid} member ports did not restore"
                    return _match_fields(observed, {key: lag_obj[key] for key in fields if key in lag_obj})

                return _run_restore(
                    method="PATCH",
                    endpoint=f"sites/{site.site_id}/switches/{dev_mac}/ports/{ports_rb[0]}",
                    payload=body,
                    live_before=live_lag,
                    restore_preview=lag_obj,
                    read_back_fn=_read_lag,
                    verify_fn=_verify_lag,
                    revalidate=_guard_lag_restore,
                )

    if orig_tool == "run_wlan_optimization" and isinstance(snap_data, Mapping):
        cfg_before = as_mapping(snap_data.get("configBefore"))
        if cfg_before and snap_data.get("action") == "configure":
            if orig_target.endswith(":config"):
                prev_mode = as_int(cfg_before.get("mode"), 0)
                if prev_mode == 1:
                    cfg_payload: dict[str, Any] = {
                        "mode": 1,
                        "customSetting": {
                            "channelDeployEnable": bool(cfg_before.get("channelDeployEnable", True)),
                            "powerAdjustEnable": bool(cfg_before.get("powerAdjustEnable", True)),
                            "channelWidthDeployEnable": bool(cfg_before.get("channelWidthDeployEnable", True)),
                            "bandDeployEnable": bool(cfg_before.get("bandDeployEnable", True)),
                            "channelDeployEnable2g": bool(cfg_before.get("channelDeployEnable2g", True)),
                            "channelDeployEnable5g": bool(cfg_before.get("channelDeployEnable5g", True)),
                            "channelDeployEnable6g": bool(cfg_before.get("channelDeployEnable6g", True)),
                            "powerAdjustEnable2g": bool(cfg_before.get("powerAdjustEnable2g", True)),
                            "powerAdjustEnable5g": bool(cfg_before.get("powerAdjustEnable5g", True)),
                            "powerAdjustEnable6g": bool(cfg_before.get("powerAdjustEnable6g", True)),
                            "chanWidth2g": as_int(cfg_before.get("chanWidth2g"), 0),
                            "chanWidth5g": as_int(cfg_before.get("chanWidth5g"), 0),
                            "chanWidth6g": as_int(cfg_before.get("chanWidth6g"), 0),
                        },
                    }
                else:
                    cfg_payload = {"mode": 0}
                return _run_restore(
                    method="PUT",
                    endpoint=f"sites/{site.site_id}/rfPlanning/config",
                    payload=cfg_payload,
                    live_before=None,
                    restore_preview=cfg_before,
                    read_back_fn=lambda: client.api_result(f"sites/{site.site_id}/rfPlanning"),
                    verify_fn=lambda _b, a: (isinstance(a, Mapping) and as_int(a.get("mode"), -1) == prev_mode, "rfPlanning config rollback failed"),
                )
            return _run_restore(
                method="PUT",
                endpoint=f"sites/{site.site_id}/rfPlanning/schedule",
                payload={
                    "scheduleEnable": bool(cfg_before.get("scheduleEnable", False)),
                    "occurrence": copy.deepcopy(cfg_before.get("occurrence") or {"timingType": 1, "hour": 0, "minute": 0}),
                },
                live_before=None,
                restore_preview=cfg_before,
                read_back_fn=lambda: client.api_result(f"sites/{site.site_id}/rfPlanning"),
                verify_fn=lambda _b, a: (isinstance(a, Mapping), "rfPlanning rollback failed"),
            )

    if orig_tool == "set_vpn_tunnel_status" and isinstance(snap_data, Mapping):
        vpn_obj = as_mapping(snap_data.get("vpn"))
        vid = str(vpn_obj.get("id") or orig_target)
        if vid and "status" in vpn_obj:
            prev_status = bool(vpn_obj["status"])
            live_rows, _ = client.paginate(f"sites/{site.site_id}/setting/vpns")
            live_vpn = next((r for r in live_rows if str(r.get("id")) == vid), None)
            return _run_restore(
                method="POST",
                endpoint=f"sites/{site.site_id}/setting/vpns/{urllib.parse.quote(vid)}/status",
                payload={"status": prev_status},
                live_before=deep_redact(live_vpn) if live_vpn else None,
                restore_preview={"status": prev_status},
                read_back_fn=lambda: next(
                    (dict(r) for r in client.paginate(f"sites/{site.site_id}/setting/vpns")[0] if str(r.get("id")) == vid),
                    {},
                ),
                verify_fn=lambda _b, a: (
                    isinstance(a, Mapping) and bool(a.get("status")) == prev_status,
                    f"VPN {vid} status did not revert to {prev_status}",
                ),
            )

    if orig_tool in _DELETE_ONLY_SECRET_ROLLBACKS and isinstance(snap_data, Mapping) and snap_data.get("created") is True:
            if orig_tool == "upsert_wireguard_tunnel":
                tunnels, _ = client.paginate(f"sites/{site.site_id}/setting/wireguard")
                live_row = next(
                    (r for r in tunnels if str(r.get("id")) == orig_target or str(r.get("name") or "") == orig_target),
                    None,
                )
                if live_row is None:
                    raise OmadaError(f"WireGuard interface {orig_target!r} not found for rollback delete")
                tid = str(live_row["id"])
                return _run_restore(
                    method="DELETE",
                    endpoint=f"sites/{site.site_id}/setting/wireguard/{urllib.parse.quote(tid)}",
                    payload=None,
                    live_before=deep_redact(live_row),
                    restore_preview=None,
                    read_back_fn=lambda: client.paginate(f"sites/{site.site_id}/setting/wireguard")[0],
                    verify_fn=lambda _b, a: (all(str(r.get("id")) != tid for r in a), f"WireGuard interface {tid} still present"),
                )
            if orig_tool == "upsert_wireguard_peer":
                peers, _ = client.paginate(f"sites/{site.site_id}/setting/wireguard/peer")
                live_row = next(
                    (r for r in peers if str(r.get("id")) == orig_target or str(r.get("name") or "") == orig_target),
                    None,
                )
                if live_row is None:
                    raise OmadaError(f"WireGuard peer {orig_target!r} not found for rollback delete")
                pid = str(live_row["id"])
                return _run_restore(
                    method="DELETE",
                    endpoint=f"sites/{site.site_id}/setting/wireguard/peer/{urllib.parse.quote(pid)}",
                    payload=None,
                    live_before=deep_redact(live_row),
                    restore_preview=None,
                    read_back_fn=lambda: client.paginate(f"sites/{site.site_id}/setting/wireguard/peer")[0],
                    verify_fn=lambda _b, a: (all(str(r.get("id")) != pid for r in a), f"WireGuard peer {pid} still present"),
                )
            if orig_tool == "upsert_ddns":
                ddns_rows, _ = client.paginate(f"sites/{site.site_id}/setting/service/ddns")
                live_row = next(
                    (r for r in ddns_rows if str(r.get("id")) == orig_target or str(r.get("domainName") or "") == orig_target),
                    None,
                )
                if live_row is None:
                    raise OmadaError(f"DDNS entry {orig_target!r} not found for rollback delete")
                did = str(live_row["id"])
                return _run_restore(
                    method="DELETE",
                    endpoint=f"sites/{site.site_id}/setting/service/ddns/{urllib.parse.quote(did)}",
                    payload=None,
                    live_before=deep_redact(live_row),
                    restore_preview=None,
                    read_back_fn=lambda: client.paginate(f"sites/{site.site_id}/setting/service/ddns")[0],
                    verify_fn=lambda _b, a: (all(str(r.get("id")) != did for r in a), f"DDNS entry {did} still present"),
                )

    if orig_tool == "upsert_wireguard_peer" and isinstance(snap_data, Mapping) and not snap_data.get("created"):
        peer_obj = as_mapping(snap_data.get("peer"))
        pid = str(peer_obj.get("id") or orig_target)
        if pid and peer_obj.get("interfaceId") and peer_obj.get("publicKey"):
            peer_body: dict[str, Any] = {
                "name": str(peer_obj.get("name") or pid),
                "status": bool(peer_obj.get("status", True)),
                "interfaceId": str(peer_obj["interfaceId"]),
                "publicKey": str(peer_obj["publicKey"]),
                "allowAddress": list(peer_obj.get("allowAddress") or []),
                "keepAlive": as_int(peer_obj.get("keepAlive"), 25),
            }
            if peer_obj.get("endPoint") and peer_obj.get("endPointPort"):
                peer_body["endPoint"] = str(peer_obj["endPoint"])
                peer_body["endPointPort"] = as_int(peer_obj["endPointPort"], 51820)
            return _run_restore(
                method="PUT",
                endpoint=f"sites/{site.site_id}/setting/wireguard/peer/{urllib.parse.quote(pid)}",
                payload=peer_body,
                live_before=None,
                restore_preview=deep_redact(peer_body),
                read_back_fn=lambda: next(
                    (dict(r) for r in client.paginate(f"sites/{site.site_id}/setting/wireguard/peer")[0] if str(r.get("id")) == pid),
                    {},
                ),
                verify_fn=lambda _b, a: (isinstance(a, Mapping) and str(a.get("name") or "") == peer_body["name"], "WireGuard peer rollback failed"),
            )

    if orig_tool in ("delete_wireguard_tunnel", "delete_wireguard_peer", "delete_ddns"):
        raise OmadaError(
            f"cannot automatically rollback {orig_tool}: deleted credential/key secrets were redacted from snapshot {sid!r}",
            hint="re-create the entry manually using upsert_wireguard_tunnel / upsert_wireguard_peer / upsert_ddns with the intended secret/key",
        )

    raise OmadaError(
        f"snapshot {sid!r} from tool {orig_tool!r} does not have an automatic rollback handler for its stored payload shape",
        hint="Inspect the snapshot JSON in OMADA_SNAPSHOT_DIR and apply the recorded before state with the corresponding config tool.",
    )

