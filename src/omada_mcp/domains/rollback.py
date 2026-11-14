"""Write domain module: rollback."""

from __future__ import annotations

import copy
import json
import urllib.parse
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import as_int, as_mapping, deep_redact, resolve_raw_device
from ._write_common import (
    _NON_REVERSIBLE_SNAPSHOT_TOOLS,
    _committed_result,
    _dry_run_result,
    _field_diff,
    _normalize_mac,
    _require_confirm,
    _site,
    _unwrap_rows,
)
from ._write_fetchers import (
    _ensure_lan_patch_body,
    _fetch_dhcp_reservations,
    _fetch_groups,
    _fetch_lan_collection,
    _fetch_lan_dns_rules,
    _fetch_lan_profiles,
    _fetch_mdns_rules,
    _fetch_policy_routes,
    _fetch_port_forwards,
    _fetch_static_routes,
    _fetch_typed_acls,
    _omada_mac,
    _strip_client_volatiles,
)
from .clients_write import _client_lock_wire_aps, _lookup_client_record
from .services_write import _resolve_upnp_targets
from .switch_write import _build_switch_port_patch, _switch_port_summary


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
) -> None:
    """Refuse rolling back a snapshot superseded by a newer write on the same target."""
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
    newer: list[dict[str, Any]] = []
    if sid_idx is not None:
        candidates = entries[sid_idx + 1:]
    else:
        candidates = [row for row in entries if snap_timestamp and str(row.get("timestamp") or "") > snap_timestamp]

    for row in candidates:
        if row.get("result") != "success":
            continue
        if str(row.get("tool") or "") == "rollback_from_snapshot":
            continue
        if str(row.get("target") or "") == orig_target:
            newer.append(row)

    if newer:
        latest = newer[-1]
        raise OmadaError(
            f"stale snapshot {sid!r}: newer committed write {latest.get('snapshot')!r} "
            f"({latest.get('tool')}) modified target {orig_target!r}",
            hint="roll back the newer snapshot first or set force=true to override",
        )


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
    _require_confirm("rollback_from_snapshot", sid, dryRun, confirm)

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

    if orig_tool in _NON_REVERSIBLE_SNAPSHOT_TOOLS:
        raise OmadaError(
            f"snapshot {sid!r} was captured by non-reversible action {orig_tool!r} and cannot be rolled back",
        )

    _check_rollback_not_superseded(client, sid, orig_target, snap_timestamp, force=bool(force))

    site = _site(client)
    warnings: list[str] = [f"Rolling back snapshot {sid} created by {orig_tool} (target={orig_target})."]

    def _run_restore(
        *,
        method: str,
        endpoint: str,
        payload: Any,
        live_before: Any,
        restore_preview: Any,
        read_back_fn: Callable[[], Any],
        verify_fn: Callable[[Any, Any], tuple[bool, str | None]],
    ) -> dict[str, Any]:
        diff = _field_diff(
            live_before if isinstance(live_before, Mapping) else {"state": live_before},
            restore_preview if isinstance(restore_preview, Mapping) else {"state": restore_preview},
            tuple((restore_preview if isinstance(restore_preview, Mapping) else {"state": None}).keys()),
        )
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
            now = read_back_fn()
            ok, _ = verify_fn(live_before, now)
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
        port_num = int(port_str)
        wire_mac = _omada_mac(norm_mac)
        ep = f"sites/{site.site_id}/switches/{wire_mac}/ports/{port_num}"
        live_rows = _unwrap_rows(client.api_result(f"sites/{site.site_id}/switches/{wire_mac}/ports"))
        live_port = next((r for r in live_rows if as_int(r.get("port"), 0) == port_num), {})
        body = _build_switch_port_patch(snap_data)
        return _run_restore(
            method="PATCH",
            endpoint=ep,
            payload=body,
            live_before=_switch_port_summary(live_port),
            restore_preview=_switch_port_summary(snap_data),
            read_back_fn=lambda: _switch_port_summary(
                next(r for r in _unwrap_rows(client.api_result(f"sites/{site.site_id}/switches/{wire_mac}/ports")) if as_int(r.get("port"), 0) == port_num)
            ),
            verify_fn=lambda _b, a: (
                str(a.get("profileId")) == str(snap_data.get("profileId") or "") and str(a.get("name")) == str(snap_data.get("name") or ""),
                "switch port read-back did not match snapshot",
            ),
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

    if orig_tool == "assign_ap_wlan_group" and isinstance(snap_data, Mapping):
        wire_mac = _omada_mac(orig_target)
        ep = f"sites/{site.site_id}/eaps/{wire_mac}/config/wlans"
        body = {"wlanId": str(snap_data.get("wlanId") or ""), "ssidOverrides": list(snap_data.get("ssidOverrides") or [])}
        live_ap = dict(client.api_result(f"sites/{site.site_id}/eaps/{wire_mac}") or {})
        return _run_restore(
            method="PUT",
            endpoint=ep,
            payload=body,
            live_before={"wlanId": live_ap.get("wlanId")},
            restore_preview={"wlanId": body["wlanId"]},
            read_back_fn=lambda: dict(client.api_result(f"sites/{site.site_id}/eaps/{wire_mac}") or {}),
            verify_fn=lambda _b, a: (str(a.get("wlanId") or "") == body["wlanId"], "AP wlanId did not match snapshot"),
        )

    # Collections: LAN networks, ACLs, Port Profiles, Policy Routes, LAN DNS, DHCP, Port Forward, Static Routes, mDNS, IP Groups, Client settings
    if orig_tool in ("update_lan_network", "set_vlan_isolation", "set_vlan_dhcp_pools") and isinstance(snap_data, Mapping):
        lan_obj = as_mapping(snap_data.get("interface")) or snap_data
        nid = str(lan_obj.get("id") or "")
        if nid:
            body, _ = _ensure_lan_patch_body(lan_obj)
            live = next((n for n in _fetch_lan_collection(client, site) if str(n.get("id")) == nid), {})
            if not live:
                raise OmadaError(
                    f"cannot roll back {orig_tool}: LAN network {nid!r} no longer exists on controller",
                    hint="create the network again or inspect current site networks first",
                )
            return _run_restore(
                method="PATCH",
                endpoint=f"sites/{site.site_id}/setting/lan/networks/{nid}",
                payload=body,
                live_before=live,
                restore_preview=lan_obj,
                read_back_fn=lambda: next((n for n in _fetch_lan_collection(client, site) if str(n.get("id")) == nid), {}),
                verify_fn=lambda _b, a: (bool(a) and str(a.get("id")) == nid, f"LAN network {nid} rollback verification failed"),
            )

    if orig_tool == "create_lan_network" and isinstance(snap_data, Mapping):
        existing_ids = {str(r.get("id")) for r in (snap_data.get("existingNetworks") or []) if isinstance(r, Mapping) and r.get("id")}
        rows = _fetch_lan_collection(client, site)
        target = next((r for r in rows if str(r.get("name")) == orig_target and str(r.get("id")) not in existing_ids), None)
        if target is None or not target.get("id"):
            raise OmadaError(f"cannot locate created LAN network {orig_target!r} to delete on rollback")
        nid = str(target["id"])
        return _run_restore(
            method="DELETE",
            endpoint=f"sites/{site.site_id}/setting/lan/networks/{nid}",
            payload=None,
            live_before=target,
            restore_preview=None,
            read_back_fn=lambda: _fetch_lan_collection(client, site),
            verify_fn=lambda _b, a: (all(str(r.get("id")) != nid for r in a), f"LAN network {nid} still present"),
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

    raise OmadaError(
        f"snapshot {sid!r} from tool {orig_tool!r} does not have an automatic rollback handler for its stored payload shape",
        hint="Inspect the snapshot JSON in OMADA_SNAPSHOT_DIR and apply the recorded before state with the corresponding config tool.",
    )

