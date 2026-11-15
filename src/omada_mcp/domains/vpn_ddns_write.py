"""Write domain module: VPN status, WireGuard CRUD, and DDNS CRUD."""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import as_int, deep_redact
from ._write_common import (
    _committed_result,
    _dry_run_result,
    _field_diff,
    _require_confirm,
    _site,
)
from ._write_fetchers import _fetch_wan_networks

_WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")

_DDNS_SERVICES: dict[str, int] = {
    "0": 0,
    "dyndns": 0,
    "dyn": 0,
    "1": 1,
    "noip": 1,
    "no-ip": 1,
    "no_ip": 1,
    "2": 2,
    "peanuthull": 2,
    "oray": 2,
    "3": 3,
    "comexe": 3,
}

_VALID_DDNS_INTERVALS = frozenset({0, 1, 6, 12, 24, 48, 72})


def _validate_wg_key(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _WG_KEY_RE.fullmatch(text):
        raise OmadaError(
            f"invalid WireGuard {field_name}: must be a 44-character base64 key ending in '='",
            hint=f"provide a valid WireGuard curve25519 {field_name} (44 chars base64)",
        )
    return text


def _validate_wg_local_ip(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise OmadaError("localIp must be non-empty")
    try:
        if "/" in text:
            return str(ipaddress.ip_interface(text).ip)
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise OmadaError(f"invalid localIp {value!r}: {exc}") from None


def _validate_cidr(value: str, field_name: str, *, interface: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        raise OmadaError(f"{field_name} must be non-empty")
    try:
        if interface:
            ipaddress.ip_interface(text)
        else:
            ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise OmadaError(f"invalid {field_name} {value!r}: {exc}") from None
    return text


def _fetch_vpns(client: OmadaClient, site_id: str) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site_id}/setting/vpns")
    return rows


def _fetch_wireguard_tunnels(client: OmadaClient, site_id: str) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site_id}/setting/wireguard")
    return rows


def _fetch_wireguard_peers(client: OmadaClient, site_id: str) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site_id}/setting/wireguard/peer")
    return rows


def _fetch_ddns_rows(client: OmadaClient, site_id: str) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site_id}/setting/service/ddns")
    return rows


def _resolve_by_id_or_name(
    rows: list[dict[str, Any]],
    needle: str,
    *,
    kind: str,
    name_key: str = "name",
) -> dict[str, Any]:
    wanted = str(needle or "").strip()
    if not wanted:
        raise OmadaError(f"{kind} identifier or name is required")
    by_id = [dict(r) for r in rows if str(r.get("id") or "") == wanted]
    if by_id:
        return by_id[0]
    low = wanted.lower()
    by_name = [dict(r) for r in rows if str(r.get(name_key) or "").strip().lower() == low]
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        raise OmadaError(
            f"multiple {kind} entries match {wanted!r}; pass exact id instead",
            hint=f"matching ids: {', '.join(str(r.get('id')) for r in by_name)}",
        )
    raise OmadaError(f"{kind} {wanted!r} not found")


def _strip_secret_keys(obj: dict[str, Any]) -> dict[str, Any]:
    out = dict(deep_redact(obj))
    return out


# -- VPN status toggle -------------------------------------------------------


def set_vpn_tunnel_status(
    client: OmadaClient,
    vpn: str,
    enabled: bool,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Enable or disable a configured IPsec/OpenVPN/L2TP/PPTP entry."""
    site = _site(client)
    existing = _resolve_by_id_or_name(
        _fetch_vpns(client, site.site_id),
        vpn,
        kind="VPN tunnel",
    )
    vpn_id = str(existing["id"])
    target_id = vpn_id
    desired = bool(enabled)
    _require_confirm("set_vpn_tunnel_status", target_id, dryRun, confirm)

    before_safe = _strip_secret_keys(existing)
    after_preview = dict(before_safe)
    after_preview["status"] = desired
    diff = _field_diff(before_safe, after_preview)
    rollback = {
        "tool": "set_vpn_tunnel_status",
        "arguments": {"vpn": vpn_id, "enabled": bool(existing.get("status", False))},
    }
    if dryRun:
        return _dry_run_result(
            tool_name="set_vpn_tunnel_status",
            target_id=target_id,
            before=before_safe,
            after=after_preview,
            diff=diff,
            warnings=[],
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/setting/vpns/{urllib.parse.quote(vpn_id)}/status"
    res = client.write(
        endpoint,
        "POST",
        data={"status": desired},
        expect_keys={"status": desired},
        tool_name="set_vpn_tunnel_status",
        target=target_id,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "vpn": before_safe},
        read_back=lambda: next(
            (dict(r) for r in _fetch_vpns(client, site.site_id) if str(r.get("id")) == vpn_id),
            {},
        ),
        fields_changed=["status"],
    )
    return _committed_result(
        tool_name="set_vpn_tunnel_status",
        target_id=target_id,
        before=before_safe,
        after=_strip_secret_keys(res["after"]),
        diff=diff,
        snapshot=res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


# -- WireGuard interfaces ----------------------------------------------------


def upsert_wireguard_tunnel(
    client: OmadaClient,
    name: str,
    localIp: str,
    privateKey: str | None = None,
    mtu: int = 1420,
    listenPort: int = 51820,
    status: bool = True,
    tunnelId: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a WireGuard VPN interface without exposing private keys."""
    site = _site(client)
    clean_name = str(name or "").strip()
    if not (1 <= len(clean_name) <= 64):
        raise OmadaError("WireGuard interface name must be 1..64 characters")
    local_ip = _validate_wg_local_ip(localIp)
    mtu_val = as_int(mtu, -1)
    if not (576 <= mtu_val <= 1440):
        raise OmadaError(f"mtu={mtu} out of valid WireGuard range (576..1440)")
    port_val = as_int(listenPort, -1)
    if not (1 <= port_val <= 65535):
        raise OmadaError(f"listenPort={listenPort} out of valid TCP/UDP port range (1..65535)")
    if privateKey is not None:
        validated_key: str | None = _validate_wg_key(privateKey, "privateKey")
    else:
        validated_key = None

    existing_rows = _fetch_wireguard_tunnels(client, site.site_id)
    existing: dict[str, Any] | None = None
    if tunnelId:
        existing = _resolve_by_id_or_name(existing_rows, tunnelId, kind="WireGuard interface")
    else:
        for row in existing_rows:
            if str(row.get("name") or "").strip().lower() == clean_name.lower():
                existing = dict(row)
                break

    is_create = existing is None
    target_id = str(existing["id"]) if existing else clean_name
    _require_confirm("upsert_wireguard_tunnel", target_id, dryRun, confirm)

    before_safe = _strip_secret_keys(existing) if existing else {}
    preview_after: dict[str, Any] = {
        **(before_safe if existing else {}),
        "name": clean_name,
        "status": bool(status),
        "mtu": mtu_val,
        "listenPort": port_val,
        "localIp": local_ip,
        "hasPrivateKey": bool(validated_key or existing),
    }
    diff = _field_diff(before_safe, preview_after)
    rollback = (
        {"tool": "delete_wireguard_tunnel", "arguments": {"tunnel": clean_name}}
        if is_create
        else {
            "tool": "upsert_wireguard_tunnel",
            "arguments": {
                "tunnelId": target_id,
                "name": str(before_safe.get("name") or clean_name),
                "localIp": str(before_safe.get("localIp") or local_ip),
                "mtu": as_int(before_safe.get("mtu"), mtu_val),
                "listenPort": as_int(before_safe.get("listenPort"), port_val),
                "status": bool(before_safe.get("status", True)),
            },
        }
    )
    warnings: list[str] = []
    if is_create and validated_key is None:
        warnings.append("privateKey omitted: controller will generate an ephemeral WireGuard keypair on apply")

    if dryRun:
        return _dry_run_result(
            tool_name="upsert_wireguard_tunnel",
            target_id=target_id,
            before=before_safe,
            after=preview_after,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    effective_key = validated_key
    if effective_key is None:
        if existing and isinstance(existing.get("privateKey"), str) and _WG_KEY_RE.fullmatch(existing["privateKey"]):
            effective_key = existing["privateKey"]
        else:
            keypair = client.api_result(f"sites/{site.site_id}/setting/wireguard/key") or {}
            effective_key = _validate_wg_key(str(keypair.get("privateKey") or ""), "generated privateKey")

    payload: dict[str, Any] = {
        "name": clean_name,
        "status": bool(status),
        "mtu": mtu_val,
        "listenPort": port_val,
        "localIp": local_ip,
        "privateKey": effective_key,
    }
    if existing:
        endpoint = f"sites/{site.site_id}/setting/wireguard/{urllib.parse.quote(str(existing['id']))}"
        method = "PUT"
    else:
        endpoint = f"sites/{site.site_id}/setting/wireguard"
        method = "POST"

    res = client.write(
        endpoint,
        method,
        data=payload,
        expect_keys={
            "name": clean_name,
            "status": bool(status),
            "mtu": mtu_val,
            "listenPort": port_val,
            "localIp": local_ip,
        },
        tool_name="upsert_wireguard_tunnel",
        target=target_id,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "created": is_create, "tunnel": before_safe},
        read_back=lambda: next(
            (
                dict(r)
                for r in _fetch_wireguard_tunnels(client, site.site_id)
                if (existing and str(r.get("id")) == str(existing["id"]))
                or str(r.get("name") or "").strip().lower() == clean_name.lower()
            ),
            {},
        ),
        fields_changed=sorted(k for k in payload if k != "privateKey"),
    )
    after_safe = _strip_secret_keys(res["after"])
    if is_create and after_safe.get("id"):
        rollback = {"tool": "delete_wireguard_tunnel", "arguments": {"tunnel": str(after_safe["id"])}}
    return _committed_result(
        tool_name="upsert_wireguard_tunnel",
        target_id=str(after_safe.get("id") or target_id),
        before=before_safe,
        after=after_safe,
        diff=diff,
        snapshot=res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def delete_wireguard_tunnel(
    client: OmadaClient,
    tunnel: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a WireGuard interface after verifying zero dependent peers exist."""
    site = _site(client)
    existing = _resolve_by_id_or_name(
        _fetch_wireguard_tunnels(client, site.site_id),
        tunnel,
        kind="WireGuard interface",
    )
    tid = str(existing["id"])
    peers = [
        p for p in _fetch_wireguard_peers(client, site.site_id)
        if str(p.get("interfaceId") or "") == tid
    ]
    if peers:
        names = ", ".join(str(p.get("name") or p.get("id")) for p in peers[:5])
        raise OmadaError(
            f"cannot delete WireGuard interface {existing.get('name')!r} ({tid}): {len(peers)} peer(s) still attached ({names})",
            hint="remove attached peers with delete_wireguard_peer first",
        )
    _require_confirm("delete_wireguard_tunnel", tid, dryRun, confirm)
    before_safe = _strip_secret_keys(existing)
    diff = _field_diff(before_safe, {})
    warnings = ["WireGuard privateKey was redacted from snapshot; auto-recreate requires supplying a new privateKey or regenerating one"]
    if dryRun:
        return _dry_run_result(
            tool_name="delete_wireguard_tunnel",
            target_id=tid,
            before=before_safe,
            after={},
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    res = client.write(
        f"sites/{site.site_id}/setting/wireguard/{urllib.parse.quote(tid)}",
        "DELETE",
        tool_name="delete_wireguard_tunnel",
        target=tid,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "tunnel": before_safe},
        read_back=lambda: next(
            (dict(r) for r in _fetch_wireguard_tunnels(client, site.site_id) if str(r.get("id")) == tid),
            {},
        ),
        verify_fn=lambda _req, after: (
            (False, f"WireGuard interface {tid} still present after DELETE") if after else (True, None)
        ),
        fields_changed=["deleted"],
    )
    return _committed_result(
        tool_name="delete_wireguard_tunnel",
        target_id=tid,
        before=before_safe,
        after={},
        diff=diff,
        snapshot=res["snapshot"],
        warnings=warnings,
        rollback=None,
    )


# -- WireGuard peers ---------------------------------------------------------


def upsert_wireguard_peer(
    client: OmadaClient,
    name: str,
    interface: str,
    publicKey: str,
    allowAddress: list[str],
    peerId: str | None = None,
    endPoint: str | None = None,
    endPointPort: int | None = None,
    presharedKey: str | None = None,
    keepAlive: int = 25,
    comment: str | None = None,
    status: bool = True,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a WireGuard peer bound to an existing interface."""
    site = _site(client)
    clean_name = str(name or "").strip()
    if not (1 <= len(clean_name) <= 64):
        raise OmadaError("WireGuard peer name must be 1..64 characters")
    pub = _validate_wg_key(publicKey, "publicKey")
    psk = _validate_wg_key(presharedKey, "presharedKey") if presharedKey else None
    if not allowAddress:
        raise OmadaError("allowAddress must contain at least one CIDR range")
    cidrs = [_validate_cidr(c, "allowAddress") for c in allowAddress]
    keep_val = as_int(keepAlive, -1)
    if not (0 <= keep_val <= 65535):
        raise OmadaError(f"keepAlive={keepAlive} must be in 0..65535")

    ep_clean = str(endPoint).strip() if endPoint is not None and str(endPoint).strip() else None
    port_clean: int | None = None
    if endPointPort is not None:
        port_clean = as_int(endPointPort, -1)
        if not (1 <= port_clean <= 65535):
            raise OmadaError(f"endPointPort={endPointPort} must be in 1..65535")
    if (ep_clean is None) != (port_clean is None):
        raise OmadaError("endPoint and endPointPort must either both be set or both omitted")
    if comment is not None and len(str(comment)) > 128:
        raise OmadaError("comment must be at most 128 characters")

    tunnels = _fetch_wireguard_tunnels(client, site.site_id)
    iface_row = _resolve_by_id_or_name(tunnels, interface, kind="WireGuard interface")
    iface_id = str(iface_row["id"])

    peers = _fetch_wireguard_peers(client, site.site_id)
    existing: dict[str, Any] | None = None
    if peerId:
        existing = _resolve_by_id_or_name(peers, peerId, kind="WireGuard peer")
    else:
        for row in peers:
            if (
                str(row.get("name") or "").strip().lower() == clean_name.lower()
                and str(row.get("interfaceId") or "") == iface_id
            ):
                existing = dict(row)
                break

    is_create = existing is None
    target_id = str(existing["id"]) if existing else clean_name
    _require_confirm("upsert_wireguard_peer", target_id, dryRun, confirm)

    before_safe = _strip_secret_keys(existing) if existing else {}
    payload: dict[str, Any] = {
        "name": clean_name,
        "status": bool(status),
        "interfaceId": iface_id,
        "publicKey": pub,
        "allowAddress": cidrs,
        "keepAlive": keep_val,
    }
    if ep_clean is not None and port_clean is not None:
        payload["endPoint"] = ep_clean
        payload["endPointPort"] = port_clean
    if psk is not None:
        payload["presharedKey"] = psk
    if comment is not None and str(comment).strip():
        payload["comment"] = str(comment).strip()

    preview_after = _strip_secret_keys({**before_safe, **payload})
    diff = _field_diff(before_safe, preview_after)
    rollback = (
        {"tool": "delete_wireguard_peer", "arguments": {"peer": clean_name}}
        if is_create
        else {
            "tool": "upsert_wireguard_peer",
            "arguments": {
                "peerId": target_id,
                "name": str(before_safe.get("name") or clean_name),
                "interface": str(before_safe.get("interfaceId") or iface_id),
                "publicKey": str(before_safe.get("publicKey") or pub),
                "allowAddress": list(before_safe.get("allowAddress") or cidrs),
                "keepAlive": as_int(before_safe.get("keepAlive"), keep_val),
                "status": bool(before_safe.get("status", True)),
            },
        }
    )

    if dryRun:
        return _dry_run_result(
            tool_name="upsert_wireguard_peer",
            target_id=target_id,
            before=before_safe,
            after=preview_after,
            diff=diff,
            warnings=[],
            rollback=rollback,
        )

    endpoint = (
        f"sites/{site.site_id}/setting/wireguard/peer/{urllib.parse.quote(str(existing['id']))}"
        if existing
        else f"sites/{site.site_id}/setting/wireguard/peer"
    )
    res = client.write(
        endpoint,
        "PUT" if existing else "POST",
        data=payload,
        expect_keys={
            "name": clean_name,
            "status": bool(status),
            "interfaceId": iface_id,
            "publicKey": pub,
        },
        tool_name="upsert_wireguard_peer",
        target=target_id,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "created": is_create, "peer": before_safe},
        read_back=lambda: next(
            (
                dict(r)
                for r in _fetch_wireguard_peers(client, site.site_id)
                if (existing and str(r.get("id")) == str(existing["id"]))
                or (
                    str(r.get("name") or "").strip().lower() == clean_name.lower()
                    and str(r.get("interfaceId") or "") == iface_id
                )
            ),
            {},
        ),
        fields_changed=sorted(k for k in payload if k != "presharedKey"),
    )
    after_safe = _strip_secret_keys(res["after"])
    if is_create and after_safe.get("id"):
        rollback = {"tool": "delete_wireguard_peer", "arguments": {"peer": str(after_safe["id"])}}
    return _committed_result(
        tool_name="upsert_wireguard_peer",
        target_id=str(after_safe.get("id") or target_id),
        before=before_safe,
        after=after_safe,
        diff=diff,
        snapshot=res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


def delete_wireguard_peer(
    client: OmadaClient,
    peer: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a WireGuard peer by ID or exact name."""
    site = _site(client)
    existing = _resolve_by_id_or_name(
        _fetch_wireguard_peers(client, site.site_id),
        peer,
        kind="WireGuard peer",
    )
    pid = str(existing["id"])
    _require_confirm("delete_wireguard_peer", pid, dryRun, confirm)
    before_safe = _strip_secret_keys(existing)
    diff = _field_diff(before_safe, {})
    if dryRun:
        return _dry_run_result(
            tool_name="delete_wireguard_peer",
            target_id=pid,
            before=before_safe,
            after={},
            diff=diff,
            warnings=[],
            rollback=None,
        )

    res = client.write(
        f"sites/{site.site_id}/setting/wireguard/peer/{urllib.parse.quote(pid)}",
        "DELETE",
        tool_name="delete_wireguard_peer",
        target=pid,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "peer": before_safe},
        read_back=lambda: next(
            (dict(r) for r in _fetch_wireguard_peers(client, site.site_id) if str(r.get("id")) == pid),
            {},
        ),
        verify_fn=lambda _req, after: (
            (False, f"WireGuard peer {pid} still present after DELETE") if after else (True, None)
        ),
        fields_changed=["deleted"],
    )
    return _committed_result(
        tool_name="delete_wireguard_peer",
        target_id=pid,
        before=before_safe,
        after={},
        diff=diff,
        snapshot=res["snapshot"],
        warnings=[],
        rollback=None,
    )


# -- DDNS CRUD ---------------------------------------------------------------


def _resolve_wan_port_uuid(client: OmadaClient, site: Any, interface: str | None) -> str:
    wan_raw = _fetch_wan_networks(client, site)
    ports = ((wan_raw or {}).get("osgPortInfo") or {}).get("wanLanPortSettings") or []
    if not isinstance(ports, list) or not ports:
        raise OmadaError(
            "no WAN ports reported by controller for DDNS binding",
            hint="ensure a gateway is adopted and at least one WAN port is enabled",
        )
    if not interface:
        for p in ports:
            if isinstance(p, dict) and p.get("portUuid"):
                return str(p["portUuid"])
    wanted = str(interface or "").strip().lower()
    for p in ports:
        if not isinstance(p, dict):
            continue
        uuid_val = str(p.get("portUuid") or "")
        name_val = str(p.get("portName") or p.get("name") or "")
        if uuid_val.lower() == wanted or name_val.lower() == wanted:
            return uuid_val
    raise OmadaError(f"WAN interface {interface!r} not found")


def upsert_ddns(
    client: OmadaClient,
    domainName: str,
    service: str | int = "dyndns",
    username: str | None = None,
    password: str | None = None,
    ddnsId: str | None = None,
    interface: str | None = None,
    updateInterval: int = 12,
    status: bool = True,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a DDNS entry (passwords redacted in outputs and snapshots)."""
    site = _site(client)
    clean_domain = str(domainName or "").strip()
    if not clean_domain:
        raise OmadaError("domainName is required")
    svc_key = str(service if service is not None else "dyndns").strip().lower()
    if svc_key not in _DDNS_SERVICES:
        raise OmadaError(
            f"unsupported DDNS service {service!r}",
            hint="supported services: dyndns (0), noip (1), peanuthull (2), comexe (3)",
        )
    svc_code = _DDNS_SERVICES[svc_key]
    interval_val = as_int(updateInterval, -1)
    if interval_val not in _VALID_DDNS_INTERVALS:
        raise OmadaError(
            f"updateInterval={updateInterval} must be one of {sorted(_VALID_DDNS_INTERVALS)}"
        )

    rows = _fetch_ddns_rows(client, site.site_id)
    existing: dict[str, Any] | None = None
    if ddnsId:
        existing = _resolve_by_id_or_name(rows, ddnsId, kind="DDNS entry", name_key="domainName")
    else:
        for r in rows:
            if str(r.get("domainName") or "").strip().lower() == clean_domain.lower():
                existing = dict(r)
                break

    if existing and not interface:
        port_uuid = str(existing.get("interfacePortId") or "")
    else:
        port_uuid = _resolve_wan_port_uuid(client, site, interface)

    eff_user = str(username if username is not None else (existing.get("username") if existing else "") or "").strip()
    if not existing and not eff_user:
        raise OmadaError("username is required when creating a DDNS entry")
    if not existing and not password:
        raise OmadaError("password is required when creating a DDNS entry")

    is_create = existing is None
    target_id = str(existing["id"]) if existing else clean_domain
    _require_confirm("upsert_ddns", target_id, dryRun, confirm)

    before_safe = _strip_secret_keys(existing) if existing else {}
    payload: dict[str, Any] = {
        "service": svc_code,
        "interfacePortId": port_uuid,
        "username": eff_user,
        "domainName": clean_domain,
        "updateInterval": interval_val,
        "status": bool(status),
    }
    if password is not None:
        payload["password"] = str(password)

    preview_after = _strip_secret_keys({**before_safe, **payload})
    diff = _field_diff(before_safe, preview_after)
    rollback = (
        {"tool": "delete_ddns", "arguments": {"ddns": clean_domain}}
        if is_create
        else None
    )
    if dryRun:
        return _dry_run_result(
            tool_name="upsert_ddns",
            target_id=target_id,
            before=before_safe,
            after=preview_after,
            diff=diff,
            warnings=[],
            rollback=rollback,
        )

    endpoint = (
        f"sites/{site.site_id}/setting/service/ddns/{urllib.parse.quote(str(existing['id']))}"
        if existing
        else f"sites/{site.site_id}/setting/service/ddns"
    )
    res = client.write(
        endpoint,
        "PUT" if existing else "POST",
        data=payload,
        expect_keys={
            "service": svc_code,
            "domainName": clean_domain,
            "updateInterval": interval_val,
            "status": bool(status),
        },
        tool_name="upsert_ddns",
        target=target_id,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "created": is_create, "ddns": before_safe},
        read_back=lambda: next(
            (
                dict(r)
                for r in _fetch_ddns_rows(client, site.site_id)
                if (existing and str(r.get("id")) == str(existing["id"]))
                or str(r.get("domainName") or "").strip().lower() == clean_domain.lower()
            ),
            {},
        ),
        fields_changed=sorted(k for k in payload if k != "password"),
    )
    after_safe = _strip_secret_keys(res["after"])
    if is_create and after_safe.get("id"):
        rollback = {"tool": "delete_ddns", "arguments": {"ddns": str(after_safe["id"])}}
    return _committed_result(
        tool_name="upsert_ddns",
        target_id=str(after_safe.get("id") or target_id),
        before=before_safe,
        after=after_safe,
        diff=diff,
        snapshot=res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


def delete_ddns(
    client: OmadaClient,
    ddns: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a DDNS entry by ID or domainName."""
    site = _site(client)
    existing = _resolve_by_id_or_name(
        _fetch_ddns_rows(client, site.site_id),
        ddns,
        kind="DDNS entry",
        name_key="domainName",
    )
    did = str(existing["id"])
    _require_confirm("delete_ddns", did, dryRun, confirm)
    before_safe = _strip_secret_keys(existing)
    diff = _field_diff(before_safe, {})
    warnings = ["DDNS password was redacted; rollback cannot restore credentials automatically"]
    if dryRun:
        return _dry_run_result(
            tool_name="delete_ddns",
            target_id=did,
            before=before_safe,
            after={},
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    res = client.write(
        f"sites/{site.site_id}/setting/service/ddns/{urllib.parse.quote(did)}",
        "DELETE",
        tool_name="delete_ddns",
        target=did,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "ddns": before_safe},
        read_back=lambda: next(
            (dict(r) for r in _fetch_ddns_rows(client, site.site_id) if str(r.get("id")) == did),
            {},
        ),
        verify_fn=lambda _req, after: (
            (False, f"DDNS entry {did} still present after DELETE") if after else (True, None)
        ),
        fields_changed=["deleted"],
    )
    return _committed_result(
        tool_name="delete_ddns",
        target_id=did,
        before=before_safe,
        after={},
        diff=diff,
        snapshot=res["snapshot"],
        warnings=warnings,
        rollback=None,
    )
