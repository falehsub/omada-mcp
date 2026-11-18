"""Write domain module: VPN status, WireGuard CRUD, and DDNS CRUD."""

from __future__ import annotations

import contextlib
import ipaddress
import re
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from typing import Any

from .._projections import project_controller_row
from ..client import OmadaClient, OmadaError
from ._common import as_int, require_complete_collection
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
_MANUAL_RECOVERY_WARNING = (
    "Credential values are excluded from verification and snapshots. Use your credential store for recovery."
)


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


@contextlib.contextmanager
def _credential_safe_errors() -> Iterator[None]:
    """Keep upstream messages from echoing submitted or stored credentials."""
    try:
        yield
    except OmadaError as exc:
        code = exc.code if type(exc.code) is int else None
        suffix = f" (controller code {code})" if code is not None else ""
        error = OmadaError(
            f"could not confirm VPN or DDNS state{suffix}", code=code,
            hint="re-read controller state and inspect any recorded snapshot before retrying",
        )
        error.write_status = exc.write_status
        raise error from None


def _fetch_rows(client: OmadaClient, endpoint: str) -> list[dict[str, Any]]:
    with _credential_safe_errors():
        rows, _ = require_complete_collection(client, endpoint)
    return rows


def _fetch_vpns(client: OmadaClient, site_id: str) -> list[dict[str, Any]]:
    return _fetch_rows(client, f"sites/{site_id}/setting/vpns")


def _fetch_wireguard_tunnels(client: OmadaClient, site_id: str) -> list[dict[str, Any]]:
    return _fetch_rows(client, f"sites/{site_id}/setting/wireguard")


def _fetch_wireguard_peers(client: OmadaClient, site_id: str) -> list[dict[str, Any]]:
    return _fetch_rows(client, f"sites/{site_id}/setting/wireguard/peer")


def _fetch_ddns_rows(client: OmadaClient, site_id: str) -> list[dict[str, Any]]:
    return _fetch_rows(client, f"sites/{site_id}/setting/service/ddns")


def _find_unique(
    rows: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool],
) -> dict[str, Any] | None:
    matches = [row for row in rows if predicate(row)]
    if len(matches) > 1:
        raise OmadaError("multiple controller records match", hint="use a unique record ID")
    return matches[0] if matches else None


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
    match = _find_unique(rows, lambda row: str(row.get("id", "")) == wanted)
    if match is None:
        match = _find_unique(rows, lambda row: str(row.get(name_key) or "").strip().casefold() == wanted.casefold())
    if match is None:
        raise OmadaError(f"{kind} not found")
    if not match.get("id"):
        raise OmadaError(f"{kind} has no usable ID")
    return match


def _public_row(shape: str, row: Mapping[str, Any]) -> dict[str, Any]:
    public = project_controller_row(shape, row)
    if shape == "wireguard" and row:
        public["hasPrivateKey"] = bool(row.get("privateKey") or row.get("hasPrivateKey"))
    if shape == "ddnsEntry" and isinstance(row.get("username"), str):
        public["username"] = row["username"]
    return public


def _upsert_target(existing: dict[str, Any] | None, new_name: str) -> str:
    if existing is None:
        return new_name
    if not existing.get("id"):
        raise OmadaError("existing controller record has no usable ID")
    return str(existing["id"])


def _write_with_safe_errors(client: OmadaClient, endpoint: str, method: str, **kwargs: Any) -> dict[str, Any]:
    with _credential_safe_errors():
        return client.write(endpoint, method, **kwargs)


def _write_readback(
    rows: list[dict[str, Any]], existing: dict[str, Any] | None, *,
    name: str, name_key: str = "name", interface_id: str | None = None,
) -> dict[str, Any]:
    match = _find_unique(
        rows,
        lambda row: str(row.get("id")) == str(existing["id"]) if existing else (
            str(row.get(name_key) or "").strip().casefold() == name.casefold()
            and (interface_id is None or str(row.get("interfaceId")) == interface_id)
        ),
    )
    return match if match and match.get("id") else {}


def _write_result(result: dict[str, Any], *, manual_recovery: bool, verified: bool | None = None) -> dict[str, Any]:
    if manual_recovery:
        result["manualRecoveryRequired"] = True
        result["warnings"].append(_MANUAL_RECOVERY_WARNING)
    if verified is not None:
        result["verified"] = verified
    return result


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

    before_safe = _public_row("vpns", existing)
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

    endpoint = f"sites/{site.site_id}/setting/vpns/{urllib.parse.quote(vpn_id, safe='')}/status"
    expected = {key: value for key, value in after_preview.items() if key != "enabled"}
    res = _write_with_safe_errors(
        client, endpoint,
        "POST",
        data={"status": desired},
        expect_keys=expected,
        tool_name="set_vpn_tunnel_status",
        target=target_id,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "vpn": before_safe},
        read_back=lambda: _public_row("vpns", _write_readback(
            _fetch_vpns(client, site.site_id), existing, name="",
        )
        ),
        fields_changed=["status"],
    )
    return _committed_result(
        tool_name="set_vpn_tunnel_status",
        target_id=target_id,
        before=before_safe,
        after=res["after"],
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
    existing: dict[str, Any] | None
    if tunnelId:
        existing = _resolve_by_id_or_name(existing_rows, tunnelId, kind="WireGuard interface")
    else:
        existing = _find_unique(existing_rows, lambda row: str(row.get("name") or "").strip().casefold() == clean_name.casefold())

    is_create = existing is None
    existing_key = existing.get("privateKey") if existing else None
    if existing is not None and validated_key is None:
        if not isinstance(existing_key, str) or not _WG_KEY_RE.fullmatch(existing_key):
            raise OmadaError(
                "the controller did not return a reusable WireGuard private key",
                hint="supply the existing privateKey explicitly to preserve it, or choose a new key for intentional rotation",
            )
        validated_key = existing_key
    target_id = _upsert_target(existing, clean_name)
    _require_confirm("upsert_wireguard_tunnel", target_id, dryRun, confirm)

    before_safe = _public_row("wireguard", existing) if existing else {}
    preview_after: dict[str, Any] = {
        **(before_safe if existing else {}),
        "name": clean_name,
        "status": bool(status),
        "mtu": mtu_val,
        "listenPort": port_val,
        "localIp": local_ip,
        "hasPrivateKey": True,
    }
    diff = _field_diff(before_safe, preview_after)
    rollback: dict[str, Any] | None = (
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
    if not is_create and privateKey is not None:
        rollback = None
    warnings: list[str] = []
    if is_create and validated_key is None:
        warnings.append("privateKey omitted: controller will generate an ephemeral WireGuard keypair on apply")

    if dryRun:
        return _write_result(_dry_run_result(
            tool_name="upsert_wireguard_tunnel",
            target_id=target_id,
            before=before_safe,
            after=preview_after,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        ), manual_recovery=True)

    effective_key = validated_key
    if effective_key is None:
        with _credential_safe_errors():
            keypair = client.api_result(f"sites/{site.site_id}/setting/wireguard/key") or {}
        raw_key = keypair.get("privateKey") if isinstance(keypair, Mapping) else None
        effective_key = _validate_wg_key(str(raw_key or ""), "generated privateKey")

    payload: dict[str, Any] = {
        "name": clean_name,
        "status": bool(status),
        "mtu": mtu_val,
        "listenPort": port_val,
        "localIp": local_ip,
        "privateKey": effective_key,
    }
    if existing:
        endpoint = f"sites/{site.site_id}/setting/wireguard/{urllib.parse.quote(str(existing['id']), safe='')}"
        method = "PUT"
    else:
        endpoint = f"sites/{site.site_id}/setting/wireguard"
        method = "POST"

    expected = {key: value for key, value in payload.items() if key != "privateKey"}
    if privateKey is None and "publicKey" in before_safe:
        expected["publicKey"] = before_safe["publicKey"]
    res = _write_with_safe_errors(
        client, endpoint,
        method,
        data=payload,
        expect_keys=expected,
        tool_name="upsert_wireguard_tunnel",
        target=target_id,
        before=before_safe,
        snapshot_payload={
            "siteId": site.site_id, "created": is_create, "tunnel": before_safe,
            "manualRecoveryRequired": True,
        },
        read_back=lambda: _write_readback(
            _fetch_wireguard_tunnels(client, site.site_id), existing, name=clean_name,
        ),
        fields_changed=sorted(expected),
        verification_complete=False,
    )
    after_safe = _public_row("wireguard", res["after"])
    if is_create and after_safe.get("id"):
        rollback = {"tool": "delete_wireguard_tunnel", "arguments": {"tunnel": str(after_safe["id"])}}
    return _write_result(_committed_result(
        tool_name="upsert_wireguard_tunnel",
        target_id=str(after_safe.get("id") or target_id),
        before=before_safe,
        after=after_safe,
        diff=diff,
        snapshot=res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    ), manual_recovery=True, verified=res["verified"])


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
    before_safe = _public_row("wireguard", existing)
    diff = _field_diff(before_safe, {})
    warnings = ["Recreating the WireGuard tunnel requires a private key."]
    if dryRun:
        return _write_result(_dry_run_result(
            tool_name="delete_wireguard_tunnel",
            target_id=tid,
            before=before_safe,
            after={},
            diff=diff,
            warnings=warnings,
            rollback=None,
        ), manual_recovery=True)

    res = _write_with_safe_errors(
        client, f"sites/{site.site_id}/setting/wireguard/{urllib.parse.quote(tid, safe='')}",
        "DELETE",
        tool_name="delete_wireguard_tunnel",
        target=tid,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "tunnel": before_safe, "manualRecoveryRequired": True},
        read_back=lambda: next(
            (dict(r) for r in _fetch_wireguard_tunnels(client, site.site_id) if str(r.get("id")) == tid),
            {},
        ),
        verify_fn=lambda _req, after: (
            (False, f"WireGuard interface {tid} still present after DELETE") if after else (True, None)
        ),
        fields_changed=["deleted"],
    )
    return _write_result(_committed_result(
        tool_name="delete_wireguard_tunnel",
        target_id=tid,
        before=before_safe,
        after={},
        diff=diff,
        snapshot=res["snapshot"],
        warnings=warnings,
        rollback=None,
    ), manual_recovery=True, verified=res["verified"])


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
    existing: dict[str, Any] | None
    if peerId:
        existing = _resolve_by_id_or_name(peers, peerId, kind="WireGuard peer")
    else:
        existing = _find_unique(peers, lambda row: (
            str(row.get("name") or "").strip().casefold() == clean_name.casefold()
            and str(row.get("interfaceId") or "") == iface_id
        ))

    is_create = existing is None
    target_id = _upsert_target(existing, clean_name)
    _require_confirm("upsert_wireguard_peer", target_id, dryRun, confirm)

    before_safe = _public_row("wireguardPeers", existing) if existing else {}
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

    preview_after = _public_row("wireguardPeers", {**before_safe, **payload})
    diff = _field_diff(before_safe, preview_after)
    rollback: dict[str, Any] | None = (
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
    if not is_create and psk is not None:
        rollback = None

    if dryRun:
        return _write_result(_dry_run_result(
            tool_name="upsert_wireguard_peer",
            target_id=target_id,
            before=before_safe,
            after=preview_after,
            diff=diff,
            warnings=[],
            rollback=rollback,
        ), manual_recovery=psk is not None)

    endpoint = (
        f"sites/{site.site_id}/setting/wireguard/peer/{urllib.parse.quote(str(existing['id']), safe='')}"
        if existing
        else f"sites/{site.site_id}/setting/wireguard/peer"
    )
    expected = {
        key: preview_after[key] for key in (*payload, "endPoint", "endPointPort", "comment")
        if key in preview_after
    }
    res = _write_with_safe_errors(
        client, endpoint,
        "PUT" if existing else "POST",
        data=payload,
        expect_keys=expected,
        tool_name="upsert_wireguard_peer",
        target=target_id,
        before=before_safe,
        snapshot_payload={
            "siteId": site.site_id, "created": is_create, "peer": before_safe,
            "manualRecoveryRequired": psk is not None,
        },
        read_back=lambda: _write_readback(
            _fetch_wireguard_peers(client, site.site_id), existing, name=clean_name, interface_id=iface_id,
        ),
        fields_changed=sorted(key for key in payload if key != "presharedKey"),
        verification_complete=psk is None,
    )
    after_safe = _public_row("wireguardPeers", res["after"])
    if is_create and after_safe.get("id"):
        rollback = {"tool": "delete_wireguard_peer", "arguments": {"peer": str(after_safe["id"])}}
    return _write_result(_committed_result(
        tool_name="upsert_wireguard_peer",
        target_id=str(after_safe.get("id") or target_id),
        before=before_safe,
        after=after_safe,
        diff=diff,
        snapshot=res["snapshot"],
        warnings=[],
        rollback=rollback,
    ), manual_recovery=psk is not None, verified=res["verified"])


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
    before_safe = _public_row("wireguardPeers", existing)
    diff = _field_diff(before_safe, {})
    if dryRun:
        return _write_result(_dry_run_result(
            tool_name="delete_wireguard_peer",
            target_id=pid,
            before=before_safe,
            after={},
            diff=diff,
            warnings=[],
            rollback=None,
        ), manual_recovery=True)

    res = _write_with_safe_errors(
        client, f"sites/{site.site_id}/setting/wireguard/peer/{urllib.parse.quote(pid, safe='')}",
        "DELETE",
        tool_name="delete_wireguard_peer",
        target=pid,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "peer": before_safe, "manualRecoveryRequired": True},
        read_back=lambda: next(
            (dict(r) for r in _fetch_wireguard_peers(client, site.site_id) if str(r.get("id")) == pid),
            {},
        ),
        verify_fn=lambda _req, after: (
            (False, f"WireGuard peer {pid} still present after DELETE") if after else (True, None)
        ),
        fields_changed=["deleted"],
    )
    return _write_result(_committed_result(
        tool_name="delete_wireguard_peer",
        target_id=pid,
        before=before_safe,
        after={},
        diff=diff,
        snapshot=res["snapshot"],
        warnings=[],
        rollback=None,
    ), manual_recovery=True, verified=res["verified"])


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
    existing: dict[str, Any] | None
    if ddnsId:
        existing = _resolve_by_id_or_name(rows, ddnsId, kind="DDNS entry", name_key="domainName")
    else:
        existing = _find_unique(rows, lambda row: (
            str(row.get("domainName") or "").strip().casefold() == clean_domain.casefold()
        ))

    if existing and not interface:
        port_uuid = str(existing.get("interfacePortId") or "")
    else:
        with _credential_safe_errors():
            port_uuid = _resolve_wan_port_uuid(client, site, interface)
    if not port_uuid:
        raise OmadaError("the DDNS entry lacks a WAN interface", hint="specify an adopted WAN interface")

    eff_user = str(username if username is not None else (existing.get("username") if existing else "") or "").strip()
    if not existing and not eff_user:
        raise OmadaError("username is required when creating a DDNS entry")
    if not existing and not password:
        raise OmadaError("password is required when creating a DDNS entry")

    is_create = existing is None
    target_id = _upsert_target(existing, clean_domain)
    _require_confirm("upsert_ddns", target_id, dryRun, confirm)

    before_safe = _public_row("ddnsEntry", existing) if existing else {}
    payload: dict[str, Any] = {
        "service": svc_code,
        "interfacePortId": port_uuid,
        "username": eff_user,
        "domainName": clean_domain,
        "updateInterval": interval_val,
        "status": bool(status),
    }
    password_changed = password is not None
    if password_changed:
        payload["password"] = str(password)

    preview_after = _public_row("ddnsEntry", {**before_safe, **payload})
    diff = _field_diff(before_safe, preview_after)
    rollback = (
        {"tool": "delete_ddns", "arguments": {"ddns": clean_domain}}
        if is_create
        else None
    )
    if dryRun:
        return _write_result(_dry_run_result(
            tool_name="upsert_ddns",
            target_id=target_id,
            before=before_safe,
            after=preview_after,
            diff=diff,
            warnings=[],
            rollback=rollback,
        ), manual_recovery=password_changed)

    endpoint = (
        f"sites/{site.site_id}/setting/service/ddns/{urllib.parse.quote(str(existing['id']), safe='')}"
        if existing
        else f"sites/{site.site_id}/setting/service/ddns"
    )
    expected = {key: value for key, value in payload.items() if key != "password"}
    res = _write_with_safe_errors(
        client, endpoint,
        "PUT" if existing else "POST",
        data=payload,
        expect_keys=expected,
        tool_name="upsert_ddns",
        target=target_id,
        before=before_safe,
        snapshot_payload={
            "siteId": site.site_id, "created": is_create, "ddns": before_safe,
            "manualRecoveryRequired": password_changed,
        },
        read_back=lambda: _write_readback(
            _fetch_ddns_rows(client, site.site_id), existing, name=clean_domain, name_key="domainName",
        ),
        fields_changed=sorted(expected),
        verification_complete=not password_changed,
    )
    after_safe = _public_row("ddnsEntry", res["after"])
    if is_create and after_safe.get("id"):
        rollback = {"tool": "delete_ddns", "arguments": {"ddns": str(after_safe["id"])}}
    return _write_result(_committed_result(
        tool_name="upsert_ddns",
        target_id=str(after_safe.get("id") or target_id),
        before=before_safe,
        after=after_safe,
        diff=diff,
        snapshot=res["snapshot"],
        warnings=[],
        rollback=rollback,
    ), manual_recovery=password_changed, verified=res["verified"])


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
    before_safe = _public_row("ddnsEntry", existing)
    diff = _field_diff(before_safe, {})
    warnings = ["Recreating the DDNS entry requires its password."]
    if dryRun:
        return _write_result(_dry_run_result(
            tool_name="delete_ddns",
            target_id=did,
            before=before_safe,
            after={},
            diff=diff,
            warnings=warnings,
            rollback=None,
        ), manual_recovery=True)

    res = _write_with_safe_errors(
        client, f"sites/{site.site_id}/setting/service/ddns/{urllib.parse.quote(did, safe='')}",
        "DELETE",
        tool_name="delete_ddns",
        target=did,
        before=before_safe,
        snapshot_payload={"siteId": site.site_id, "ddns": before_safe, "manualRecoveryRequired": True},
        read_back=lambda: next(
            (dict(r) for r in _fetch_ddns_rows(client, site.site_id) if str(r.get("id")) == did),
            {},
        ),
        verify_fn=lambda _req, after: (
            (False, f"DDNS entry {did} still present after DELETE") if after else (True, None)
        ),
        fields_changed=["deleted"],
    )
    return _write_result(_committed_result(
        tool_name="delete_ddns",
        target_id=did,
        before=before_safe,
        after={},
        diff=diff,
        snapshot=res["snapshot"],
        warnings=warnings,
        rollback=None,
    ), manual_recovery=True, verified=res["verified"])
