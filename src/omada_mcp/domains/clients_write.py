"""Write domain module: clients_write."""

from __future__ import annotations

import contextlib
import copy
import ipaddress
import urllib.parse
from collections.abc import Mapping
from typing import Any

from ..client import OmadaClient, OmadaError, SiteInfo, describe_error
from ._common import as_int, as_mapping
from ._write_common import (
    _committed_result,
    _dry_run_result,
    _field_diff,
    _normalize_mac,
    _require_confirm,
    _resolve_by_id_or_name,
    _site,
    _unwrap_rows,
)
from ._write_fetchers import (
    _fetch_clients_filtered,
    _fetch_devices,
    _fetch_dhcp_reservations,
    _fetch_insight_clients,
    _fetch_lan_collection,
    _fetch_rate_limit_profiles,
    _omada_mac,
    _resolve_lan_network,
    _strip_client_volatiles,
)
from ._write_safety import _check_fixed_ip_safety, _management_endpoints


def set_client_fixed_ip(
    client: OmadaClient,
    mac: str,
    ip: str,
    vlan: Any | None = None,
    netId: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Assign a static DHCP reservation to a known client (``PATCH clients/{MAC}``)."""
    site = _site(client)
    try:
        target_ip = ipaddress.IPv4Address(str(ip or "").strip())
    except ValueError as exc:
        raise OmadaError(f"invalid IPv4 address {ip!r}: {exc}") from None

    devices = _fetch_devices(client, site)
    wanted_norm = _normalize_mac(mac)
    for dev in devices:
        if _normalize_mac(dev.get("mac", "")) == wanted_norm:
            raise OmadaError(
                f"{mac!r} is a managed network device ({dev.get('name') or dev.get('type')}), not a client",
                code=-41011,
                hint="clients/{MAC} returns -41011 for switches/APs/gateways; only client MACs can use fixed IP",
            )

    clients = _fetch_insight_clients(client, site)
    client_row = next((c for c in clients if _normalize_mac(c.get("mac", "")) == wanted_norm), None)
    if client_row is None:
        raise OmadaError(
            f"client {mac!r} was not found in insight/clients",
            code=-41011,
            hint="ensure the client MAC is known to this site; list_clients shows valid MACs",
        )
    raw_mac = str(client_row["mac"])
    target_id = _normalize_mac(raw_mac)

    _require_confirm("set_client_fixed_ip", target_id, dryRun, confirm)

    endpoint = f"sites/{site.site_id}/clients/{raw_mac}"
    client_detail = client.api_result(endpoint)
    if not isinstance(client_detail, Mapping):
        raise OmadaError(f"unexpected response from {endpoint}", endpoint=endpoint)
    if "supportFixedIp" in client_detail and not client_detail.get("supportFixedIp"):
        raise OmadaError(
            f"client {target_id} reports supportFixedIp=false and does not support fixed IP reservations",
            endpoint=endpoint,
        )

    networks = _fetch_lan_collection(client, site)
    network = _resolve_lan_network(networks, vlan=vlan, net_id=netId, target_ip=target_ip)
    resolved_net_id = str(network["id"])
    _check_fixed_ip_safety(client, network, target_ip, devices)

    before = copy.deepcopy(client_detail.get("ipSetting") or {})
    desired_ip_setting = {
        "useFixedAddr": True,
        "netId": resolved_net_id,
        "ip": str(target_ip),
    }
    patch_body = _strip_client_volatiles(client_detail)
    patch_body["ipSetting"] = dict(desired_ip_setting)

    warnings = ["effective at next DHCP lease renewal; current client IP does not change immediately"]
    if before.get("useFixedAddr") and before.get("ip") and before.get("netId"):
        rollback: dict[str, Any] = {
            "tool": "set_client_fixed_ip",
            "arguments": {
                "mac": target_id,
                "ip": str(before["ip"]),
                "netId": str(before["netId"]),
                "dryRun": True,
            },
        }
    else:
        rollback = {
            "tool": "release_client_fixed_ip",
            "arguments": {"mac": target_id, "dryRun": True},
        }

    already_converged = (
        bool(before.get("useFixedAddr"))
        and str(before.get("netId") or "") == resolved_net_id
        and str(before.get("ip") or "") == str(target_ip)
    )
    if already_converged:
        warnings.append("no controller write needed: client fixed IP already matches target configuration")
        diff: dict[str, Any] = {}
    else:
        diff = {"ipSetting": {"before": before, "after": desired_ip_setting}}
    if dryRun:
        return _dry_run_result(
            tool_name="set_client_fixed_ip",
            target_id=target_id,
            before=before,
            after=desired_ip_setting,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    if already_converged:
        return _committed_result(
            tool_name="set_client_fixed_ip",
            target_id=target_id,
            before=before,
            after=before,
            diff={},
            snapshot=None,
            warnings=warnings,
            rollback=rollback,
        )

    def _read_back() -> Any:
        return client.api_result(endpoint)

    def _verify(_before: Any, after_obj: Any) -> tuple[bool, str | None]:
        if not isinstance(after_obj, Mapping):
            return False, "clients/{MAC} read-back did not return an object"
        ip_cfg = after_obj.get("ipSetting")
        if not isinstance(ip_cfg, Mapping):
            return False, "ipSetting missing in read-back"
        if not bool(ip_cfg.get("useFixedAddr")):
            return False, f"expected ipSetting.useFixedAddr=true, got {ip_cfg.get('useFixedAddr')!r}"
        if str(ip_cfg.get("netId") or "") != resolved_net_id:
            return False, f"expected ipSetting.netId={resolved_net_id!r}, got {ip_cfg.get('netId')!r}"
        if str(ip_cfg.get("ip") or "") != str(target_ip):
            return False, f"expected ipSetting.ip={str(target_ip)!r}, got {ip_cfg.get('ip')!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        fresh = _read_back()
        ok, _ = _verify(before, fresh)
        if ok:
            return True, None, None
        fresh_patch = _strip_client_volatiles(fresh)
        fresh_patch["ipSetting"] = dict(desired_ip_setting)
        return False, fresh_patch, copy.deepcopy(fresh.get("ipSetting") or {})

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=patch_body,
        tool_name="set_client_fixed_ip",
        target=target_id,
        before=before,
        snapshot_payload=dict(client_detail),
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["ipSetting"],
    )
    after_setting = copy.deepcopy((write_res["after"] or {}).get("ipSetting") or {})
    return _committed_result(
        tool_name="set_client_fixed_ip",
        target_id=target_id,
        before=write_res["before"],
        after=after_setting,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def _release_static_reservation(client: OmadaClient, site: SiteInfo,
                                norm_mac: str) -> tuple[str, str | None]:
    """Delete the static DHCP reservation row that a fixed IP leaves behind.

    ``PATCH clients/{MAC}`` with ``useFixedAddr: false`` disables the address but the
    controller keeps the row in ``setting/service/dhcp`` with ``status: false``, where it
    still shows up in every reservation listing (issue #5). Release therefore removes it.
    """
    try:
        rows = _fetch_dhcp_reservations(client, site)
    except OmadaError as exc:
        return "failed", f"could not read DHCP reservations to clean up the static row: {exc}"
    row = next((r for r in rows if _normalize_mac(r.get("mac", "")) == norm_mac), None)
    if row is None:
        # Nothing to clean up: the client had no static row (or the controller never
        # materialised one). This is NOT a removal, so it must not be reported as one.
        return "absent", None
    path = (f"sites/{site.site_id}/setting/service/dhcp/"
            f"{urllib.parse.quote(str(row.get('mac')), safe='')}")
    response = client.api(path, method="DELETE")
    if response.get("errorCode") not in (0, None):
        return "failed", (f"static reservation row survived release: DELETE returned "
                          f"{response.get('errorCode')} {response.get('msg') or ''}".strip())
    try:
        remaining = _fetch_dhcp_reservations(client, site)
    except OmadaError:
        return "removed", None
    if any(_normalize_mac(r.get("mac", "")) == norm_mac for r in remaining):
        return "failed", "static reservation row still listed after DELETE"
    return "removed", None


def release_client_fixed_ip(
    client: OmadaClient,
    mac: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Release a client's fixed IP: clear ``useFixedAddr`` and delete the static row."""
    site = _site(client)
    devices = _fetch_devices(client, site)
    wanted_norm = _normalize_mac(mac)
    for dev in devices:
        if _normalize_mac(dev.get("mac", "")) == wanted_norm:
            raise OmadaError(
                f"{mac!r} is a managed network device ({dev.get('name') or dev.get('type')}), not a client",
                code=-41011,
            )

    clients = _fetch_insight_clients(client, site)
    client_row = next((c for c in clients if _normalize_mac(c.get("mac", "")) == wanted_norm), None)
    if client_row is None:
        raise OmadaError(f"client {mac!r} was not found in insight/clients", code=-41011)
    raw_mac = str(client_row["mac"])
    target_id = _normalize_mac(raw_mac)

    _require_confirm("release_client_fixed_ip", target_id, dryRun, confirm)

    endpoint = f"sites/{site.site_id}/clients/{raw_mac}"
    client_detail = client.api_result(endpoint)
    if not isinstance(client_detail, Mapping):
        raise OmadaError(f"unexpected response from {endpoint}", endpoint=endpoint)

    before = copy.deepcopy(client_detail.get("ipSetting") or {})
    desired_ip_setting = {"useFixedAddr": False}
    patch_body = _strip_client_volatiles(client_detail)
    patch_body["ipSetting"] = dict(desired_ip_setting)

    diff = {"ipSetting": {"before": before, "after": desired_ip_setting}}
    warnings = ["effective at next DHCP lease renewal",
                "also deletes the static DHCP reservation row when one exists"]
    rollback: dict[str, Any] | None = None
    if before.get("useFixedAddr") and before.get("ip") and before.get("netId"):
        rollback = {
            "tool": "set_client_fixed_ip",
            "arguments": {
                "mac": target_id,
                "ip": str(before["ip"]),
                "netId": str(before["netId"]),
                "dryRun": True,
            },
        }

    if dryRun:
        return _dry_run_result(
            tool_name="release_client_fixed_ip",
            target_id=target_id,
            before=before,
            after=desired_ip_setting,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    def _read_back() -> Any:
        return client.api_result(endpoint)

    def _verify(_before: Any, after_obj: Any) -> tuple[bool, str | None]:
        if not isinstance(after_obj, Mapping):
            return False, "clients/{MAC} read-back did not return an object"
        ip_cfg = after_obj.get("ipSetting") or {}
        if bool(ip_cfg.get("useFixedAddr")):
            return False, "ipSetting.useFixedAddr remained true after release"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        fresh = _read_back()
        ok, _ = _verify(before, fresh)
        if ok:
            return True, None, None
        fresh_patch = _strip_client_volatiles(fresh)
        fresh_patch["ipSetting"] = dict(desired_ip_setting)
        return False, fresh_patch, copy.deepcopy(fresh.get("ipSetting") or {})

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=patch_body,
        tool_name="release_client_fixed_ip",
        target=target_id,
        before=before,
        snapshot_payload=dict(client_detail),
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["ipSetting"],
    )
    after_setting = copy.deepcopy((write_res["after"] or {}).get("ipSetting") or {})
    clean_status, clean_warning = _release_static_reservation(client, site, target_id)
    if clean_status == "removed":
        warnings.append("static DHCP reservation row removed")
    elif clean_warning:
        warnings.append(clean_warning)

    return _committed_result(
        tool_name="release_client_fixed_ip",
        target_id=target_id,
        before=write_res["before"],
        after=after_setting,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def _lookup_client_record(client: OmadaClient, site: SiteInfo, norm_mac: str, omada_mac: str) -> dict[str, Any]:
    res = client.api(f"sites/{site.site_id}/clients/{omada_mac}")
    if res.get("errorCode") == 0 and isinstance(res.get("result"), Mapping):
        return dict(res["result"])
    for c in _fetch_clients_filtered(client, site, active=None):
        if _normalize_mac(c.get("mac", "")) == norm_mac:
            return dict(c)
    for c in _fetch_insight_clients(client, site):
        if _normalize_mac(c.get("mac", "")) == norm_mac:
            return dict(c)
    raise OmadaError(
        f"no client matches MAC {norm_mac!r}",
        code=-41002,
        hint="resolve client MACs via search_clients or list_clients",
    )


def set_client_blocked(
    client: OmadaClient,
    mac: str,
    blocked: bool,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Block or unblock a client by MAC (``POST cmd/clients/{MAC}/block|unblock``)."""
    omada_mac = _omada_mac(mac)
    norm_mac = _normalize_mac(omada_mac)
    _require_confirm("set_client_blocked", norm_mac, dryRun, confirm)

    site = _site(client)
    before_client = _lookup_client_record(client, site, norm_mac, omada_mac)
    desired = bool(blocked)
    if desired:
        client_ip_raw = str(before_client.get("ip") or "").strip()
        if client_ip_raw:
            try:
                c_addr = ipaddress.IPv4Address(client_ip_raw)
                ctrl_ip, mgmt_nets = _management_endpoints(client)
                if ctrl_ip is not None and c_addr == ctrl_ip:
                    raise OmadaError(f"refusing to block client IP {c_addr}: matches Omada controller IP")
                if any(c_addr in m for m in mgmt_nets):
                    raise OmadaError(f"refusing to block client IP {c_addr}: falls inside OMADA_MANAGEMENT_CIDRS")
            except ValueError:
                pass

    before_summary = {
        "mac": before_client.get("mac"),
        "name": before_client.get("name") or before_client.get("hostName"),
        "ip": before_client.get("ip"),
        "blocked": bool(before_client.get("blocked", False)),
    }
    after_preview = {**before_summary, "blocked": desired}
    diff = {"blocked": {"before": before_summary["blocked"], "after": desired}}
    rollback = {
        "tool": "set_client_blocked",
        "arguments": {"mac": norm_mac, "blocked": before_summary["blocked"], "dryRun": True},
    }
    if dryRun:
        return _dry_run_result(
            tool_name="set_client_blocked",
            target_id=norm_mac,
            before=before_summary,
            after=after_preview,
            diff=diff,
            warnings=[],
            rollback=rollback,
        )

    action = "block" if desired else "unblock"
    endpoint = f"sites/{site.site_id}/cmd/clients/{omada_mac}/{action}"

    def _read_back() -> dict[str, Any]:
        return _lookup_client_record(client, site, norm_mac, omada_mac)

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, "client read-back failed"
        if "blocked" in after_now and bool(after_now["blocked"]) != desired:
            return False, f"client blocked expected {desired!r}, got {after_now.get('blocked')!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_summary, live)
        return ok, None, live

    write_res = client.write(
        endpoint,
        method="POST",
        tool_name="set_client_blocked",
        target=norm_mac,
        before=before_summary,
        snapshot_payload=before_client,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["blocked"],
    )
    after_obj = write_res["after"]
    after_summary = {
        "mac": after_obj.get("mac"),
        "name": after_obj.get("name") or after_obj.get("hostName"),
        "ip": after_obj.get("ip"),
        "blocked": bool(after_obj.get("blocked", desired)),
    }
    return _committed_result(
        tool_name="set_client_blocked",
        target_id=norm_mac,
        before=write_res["before"],
        after=after_summary,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


def reconnect_client(
    client: OmadaClient,
    mac: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Force a wireless client to disassociate/reconnect (``POST cmd/clients/{MAC}/reconnect``)."""
    omada_mac = _omada_mac(mac)
    norm_mac = _normalize_mac(omada_mac)
    _require_confirm("reconnect_client", norm_mac, dryRun, confirm)

    site = _site(client)
    before_client = _lookup_client_record(client, site, norm_mac, omada_mac)
    if before_client.get("wireless") is False:
        raise OmadaError(f"client {norm_mac!r} is wired; reconnect is only valid for wireless clients")

    summary = {
        "mac": before_client.get("mac"),
        "name": before_client.get("name") or before_client.get("hostName"),
        "ssid": before_client.get("ssid"),
        "apName": before_client.get("apName"),
    }
    diff = {"action": {"before": "connected", "after": "reconnect_requested"}}
    if dryRun:
        return _dry_run_result(
            tool_name="reconnect_client",
            target_id=norm_mac,
            before=summary,
            after={**summary, "reconnectTriggered": True},
            diff=diff,
            warnings=["client will briefly drop Wi-Fi connectivity during re-association"],
            rollback=None,
        )

    endpoint = f"sites/{site.site_id}/cmd/clients/{omada_mac}/reconnect"
    write_res = client.write(
        endpoint,
        method="POST",
        tool_name="reconnect_client",
        target=norm_mac,
        before=summary,
        snapshot_payload=before_client,
        fields_changed=["reconnect"],
    )
    return _committed_result(
        tool_name="reconnect_client",
        target_id=norm_mac,
        before=write_res["before"],
        after={**summary, "reconnectTriggered": True},
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=None,
    )


def update_client(
    client: OmadaClient,
    mac: str,
    name: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Rename a client record via stripped-object ``PATCH clients/{MAC}``."""
    omada_mac = _omada_mac(mac)
    norm_mac = _normalize_mac(omada_mac)
    new_name = str(name or "").strip()
    if not new_name:
        raise OmadaError("client name must be non-empty")
    _require_confirm("update_client", norm_mac, dryRun, confirm)

    site = _site(client)
    res = client.api(f"sites/{site.site_id}/clients/{omada_mac}")
    if res.get("errorCode") != 0 or not isinstance(res.get("result"), Mapping):
        raise OmadaError(
            describe_error(res.get("errorCode"), str(res.get("msg") or ""),
                           endpoint=f"sites/{site.site_id}/clients/{omada_mac}", method="GET"),
            code=res.get("errorCode"),
            endpoint=f"sites/{site.site_id}/clients/{omada_mac}",
        )
    before_obj = dict(res["result"])
    patch_body = _strip_client_volatiles(before_obj)
    patch_body["name"] = new_name

    before_summary = {"mac": before_obj.get("mac"), "name": before_obj.get("name")}
    after_preview = {"mac": before_obj.get("mac"), "name": new_name}
    diff = {"name": {"before": before_obj.get("name"), "after": new_name}}
    rollback = {
        "tool": "update_client",
        "arguments": {"mac": norm_mac, "name": str(before_obj.get("name") or ""), "dryRun": True},
    } if before_obj.get("name") else None

    if dryRun:
        return _dry_run_result(
            tool_name="update_client",
            target_id=norm_mac,
            before=before_summary,
            after=after_preview,
            diff=diff,
            warnings=[],
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/clients/{omada_mac}"

    def _read_back() -> dict[str, Any]:
        got = client.api_result(endpoint)
        return dict(got) if isinstance(got, Mapping) else {}

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, "client read-back failed"
        if str(after_now.get("name", "")) != new_name:
            return False, f"client name expected {new_name!r}, got {after_now.get('name')!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_summary, live)
        if ok:
            return True, None, None
        fresh_body = _strip_client_volatiles(live)
        fresh_body["name"] = new_name
        return False, fresh_body, {"mac": live.get("mac"), "name": live.get("name")}

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=patch_body,
        tool_name="update_client",
        target=norm_mac,
        before=before_summary,
        snapshot_payload=before_obj,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["name"],
    )
    return _committed_result(
        tool_name="update_client",
        target_id=norm_mac,
        before=write_res["before"],
        after={"mac": write_res["after"].get("mac"), "name": write_res["after"].get("name")},
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


def _client_lock_wire_aps(lock_setting: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for item in lock_setting.get("aps") or []:
        if isinstance(item, Mapping) and item.get("mac"):
            out.append(_omada_mac(str(item["mac"])))
        elif isinstance(item, str) and item.strip():
            out.append(_omada_mac(item))
    return out


def set_client_lock_to_ap(
    client: OmadaClient,
    clientMac: str,
    enabled: bool,
    apMacs: list[str] | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Lock or unlock a wireless client to specific AP(s) via stripped client RMW."""
    norm_mac = _normalize_mac(clientMac)
    if len(norm_mac.replace(":", "")) != 12:
        raise OmadaError(f"invalid clientMac {clientMac!r}")
    _require_confirm("set_client_lock_to_ap", norm_mac, dryRun, confirm)

    site = _site(client)
    wire_client_mac = _omada_mac(norm_mac)
    raw_client = _lookup_client_record(client, site, norm_mac, wire_client_mac)

    warnings: list[str] = []
    if not raw_client.get("wireless", True) and str(raw_client.get("connectType") or "").lower() == "wired":
        warnings.append("Client is currently wired; Lock-to-AP applies only when connecting over Wi-Fi.")

    desired_aps: list[str] = []
    if enabled:
        if not apMacs:
            raise OmadaError("apMacs must be a non-empty list of AP MAC addresses or names when enabled=True")
        ap_candidates: list[dict[str, Any]] = []
        with contextlib.suppress(OmadaError):
            ap_candidates = _unwrap_rows(client.api_result(f"sites/{site.site_id}/lockToAp/aps"))
        if not ap_candidates:
            ap_candidates = [d for d in _fetch_devices(client, site) if str(d.get("type") or "").lower() == "ap"]
        for needle in apMacs:
            n_str = str(needle or "").strip()
            n_mac = _normalize_mac(n_str)
            matched = next(
                (
                    d for d in ap_candidates
                    if _normalize_mac(str(d.get("mac") or "")) == n_mac
                    or str(d.get("name") or "").strip().lower() == n_str.lower()
                ),
                None,
            )
            if matched is None:
                raise OmadaError(f"target AP {needle!r} was not found in site {site.name!r}")
            if matched.get("supportLockToAp") is False:
                raise OmadaError(f"AP {matched.get('name') or matched.get('mac')} does not support Lock-to-AP")
            desired_aps.append(_omada_mac(str(matched.get("mac") or n_mac)))
        lock_payload: dict[str, Any] = {"enable": True, "aps": desired_aps}
    else:
        lock_payload = {"enable": False}

    before_lock = as_mapping(raw_client.get("clientLockToApSetting")) or {"enable": False}
    before_view = {
        "mac": norm_mac,
        "name": raw_client.get("name") or "",
        "enable": bool(before_lock.get("enable", False)),
        "aps": _client_lock_wire_aps(before_lock),
    }
    after_view = {
        "mac": norm_mac,
        "name": raw_client.get("name") or "",
        "enable": bool(enabled),
        "aps": desired_aps,
    }
    diff = _field_diff(before_view, after_view, ("enable", "aps"))

    patch_body = _strip_client_volatiles(raw_client)
    patch_body["clientLockToApSetting"] = lock_payload

    rollback = {
        "tool": "set_client_lock_to_ap",
        "arguments": {
            "clientMac": norm_mac,
            "enabled": before_view["enable"],
            **({"apMacs": before_view["aps"]} if before_view["enable"] and before_view["aps"] else {}),
            "dryRun": True,
        },
    }
    if dryRun:
        return _dry_run_result(
            tool_name="set_client_lock_to_ap",
            target_id=norm_mac,
            before=before_view,
            after=after_view,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/clients/{wire_client_mac}"

    def _read_back() -> dict[str, Any]:
        c_now = _lookup_client_record(client, site, norm_mac, wire_client_mac)
        lk = as_mapping(c_now.get("clientLockToApSetting"))
        return {
            "mac": norm_mac,
            "name": c_now.get("name") or "",
            "enable": bool(lk.get("enable", False)),
            "aps": _client_lock_wire_aps(lk),
        }

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, "client lock-to-AP read-back failed"
        if bool(after_now.get("enable")) != bool(enabled):
            return False, f"clientLockToApSetting.enable expected {enabled!r}, got {after_now.get('enable')!r}"
        if enabled and sorted(after_now.get("aps") or []) != sorted(desired_aps):
            return False, f"locked APs expected {desired_aps!r}, got {after_now.get('aps')!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_view, live)
        return ok, patch_body, live

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=patch_body,
        tool_name="set_client_lock_to_ap",
        target=norm_mac,
        before=before_view,
        snapshot_payload=raw_client,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["clientLockToApSetting"],
    )
    return _committed_result(
        tool_name="set_client_lock_to_ap",
        target_id=norm_mac,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def set_client_rate_limit(
    client: OmadaClient,
    clientMac: str,
    enabled: bool,
    rateLimitProfileId: str | None = None,
    rateLimitProfileName: str | None = None,
    downLimitKbps: int | None = None,
    upLimitKbps: int | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Configure or disable a client rate limit via stripped client RMW."""
    norm_mac = _normalize_mac(clientMac)
    if len(norm_mac.replace(":", "")) != 12:
        raise OmadaError(f"invalid clientMac {clientMac!r}")
    _require_confirm("set_client_rate_limit", norm_mac, dryRun, confirm)

    site = _site(client)
    wire_client_mac = _omada_mac(norm_mac)
    raw_client = _lookup_client_record(client, site, norm_mac, wire_client_mac)

    rate_payload: dict[str, Any]
    if not enabled:
        rate_payload = {"enable": False}
    elif rateLimitProfileId is not None or rateLimitProfileName is not None:
        profiles = _fetch_rate_limit_profiles(client, site)
        if rateLimitProfileId and rateLimitProfileName:
            p_id = _resolve_by_id_or_name(profiles, str(rateLimitProfileId), label="rate limit profile")
            p_name = _resolve_by_id_or_name(profiles, str(rateLimitProfileName), label="rate limit profile")
            if str(p_id.get("id")) != str(p_name.get("id")):
                raise OmadaError(f"conflicting rateLimitProfileId={rateLimitProfileId!r} and rateLimitProfileName={rateLimitProfileName!r}")
            prof = p_id
        else:
            prof = _resolve_by_id_or_name(
                profiles,
                str(rateLimitProfileId if rateLimitProfileId is not None else rateLimitProfileName),
                label="rate limit profile",
            )
        rate_payload = {"enable": True, "rateLimitId": str(prof["id"])}
    else:
        if downLimitKbps is None and upLimitKbps is None:
            raise OmadaError(
                "when enabled=True, provide rateLimitProfileId/Name or at least one of downLimitKbps/upLimitKbps"
            )
        rate_payload = {
            "enable": True,
            "downEnable": downLimitKbps is not None and downLimitKbps > 0,
            "downLimit": int(downLimitKbps) if downLimitKbps else 0,
            "downUnit": 1,
            "upEnable": upLimitKbps is not None and upLimitKbps > 0,
            "upLimit": int(upLimitKbps) if upLimitKbps else 0,
            "upUnit": 1,
        }
        if not rate_payload["downEnable"] and not rate_payload["upEnable"]:
            raise OmadaError("downLimitKbps and/or upLimitKbps must be > 0 when enabling custom rate limits")

    before_rl = dict(raw_client.get("rateLimit") or {"enable": False})
    before_view = {"mac": norm_mac, "rateLimit": before_rl}
    after_view = {"mac": norm_mac, "rateLimit": rate_payload}
    diff = {"rateLimit": {"before": before_rl, "after": rate_payload}}

    patch_body = _strip_client_volatiles(raw_client)
    # Normalize any nested lock setting into clean wire shape if present
    if isinstance(patch_body.get("clientLockToApSetting"), Mapping):
        lk = dict(patch_body["clientLockToApSetting"])
        if lk.get("enable"):
            lk["aps"] = _client_lock_wire_aps(lk)
        patch_body["clientLockToApSetting"] = lk
    patch_body["rateLimit"] = rate_payload

    rollback = {
        "tool": "set_client_rate_limit",
        "arguments": {
            "clientMac": norm_mac,
            "enabled": bool(before_rl.get("enable", False)),
            **({"rateLimitProfileId": str(before_rl["rateLimitId"])} if before_rl.get("rateLimitId") else {}),
            **({"downLimitKbps": int(before_rl["downLimit"])} if before_rl.get("downEnable") and before_rl.get("downLimit") else {}),
            **({"upLimitKbps": int(before_rl["upLimit"])} if before_rl.get("upEnable") and before_rl.get("upLimit") else {}),
            "dryRun": True,
        },
    }
    if dryRun:
        return _dry_run_result(
            tool_name="set_client_rate_limit",
            target_id=norm_mac,
            before=before_view,
            after=after_view,
            diff=diff,
            warnings=[],
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/clients/{wire_client_mac}"

    def _read_back() -> dict[str, Any]:
        c_now = _lookup_client_record(client, site, norm_mac, wire_client_mac)
        return {"mac": norm_mac, "rateLimit": dict(c_now.get("rateLimit") or {"enable": False})}

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, "client rate-limit read-back failed"
        rl = after_now.get("rateLimit") or {}
        if bool(rl.get("enable")) != bool(enabled):
            return False, f"rateLimit.enable expected {enabled!r}, got {rl.get('enable')!r}"
        if enabled:
            if "rateLimitId" in rate_payload and str(rl.get("rateLimitId") or "") != rate_payload["rateLimitId"]:
                return False, f"rateLimitId expected {rate_payload['rateLimitId']!r}"
            if downLimitKbps is not None and as_int(rl.get("downLimit"), -1) != int(downLimitKbps):
                return False, f"downLimit expected {downLimitKbps}, got {rl.get('downLimit')}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_view, live)
        return ok, patch_body, live

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=patch_body,
        tool_name="set_client_rate_limit",
        target=norm_mac,
        before=before_view,
        snapshot_payload=raw_client,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["rateLimit"],
    )
    return _committed_result(
        tool_name="set_client_rate_limit",
        target_id=norm_mac,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=rollback,
    )

