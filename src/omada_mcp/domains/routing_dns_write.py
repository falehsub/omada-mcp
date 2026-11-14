"""Write domain module: routing_dns_write."""

from __future__ import annotations

import copy
import ipaddress
from collections.abc import Mapping
from typing import Any

from ..client import OmadaClient, OmadaError
from ._write_common import (
    _LAN_DNS_TYPE_MAP,
    _committed_result,
    _delete_entity,
    _dry_run_result,
    _field_diff,
    _match_fields,
    _parse_code_map,
    _parse_ipv4,
    _port_range_valid,
    _require_confirm,
    _resolve_by_id_or_name,
    _site,
    _unwrap_rows,
)
from ._write_fetchers import (
    _fetch_lan_dns_rules,
    _fetch_lan_interfaces,
    _fetch_policy_routes,
    _fetch_port_forwards,
    _fetch_static_routes,
    _fetch_wan_networks,
    _require_gateway,
)


def upsert_port_forward(
    client: OmadaClient,
    name: str,
    externalPort: str,
    forwardIp: str,
    forwardPort: str,
    id: str | None = None,
    protocol: Any = "all",
    status: bool = True,
    fromIp: str | None = None,
    interfaceWanPortIds: list[str] | None = None,
    dmz: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a gateway port forwarding rule (``setting/transmission/portForwardings``)."""
    rule_name = str(name or "").strip()
    if not rule_name:
        raise OmadaError("port forward rule name must be non-empty")
    ext_port = _port_range_valid(externalPort, "externalPort")
    int_port = _port_range_valid(forwardPort, "forwardPort")
    fwd_addr = _parse_ipv4(forwardIp, "forwardIp")
    proto_map = {"0": 0, "all": 0, "tcp_udp": 0, "tcp/udp": 0, "1": 1, "tcp": 1, "2": 2, "udp": 2}
    proto_key = str(protocol).strip().lower()
    if proto_key not in proto_map:
        raise OmadaError(f"invalid protocol {protocol!r}; expected 'all' (0), 'tcp' (1), or 'udp' (2)")
    proto_val = proto_map[proto_key]

    site = _site(client)
    existing = _fetch_port_forwards(client, site)
    before_row: dict[str, Any] | None = None
    if id and str(id).strip():
        before_row = _resolve_by_id_or_name(existing, str(id), label="port forward rule")
    else:
        before_row = next((dict(r) for r in existing if str(r.get("name", "")).strip() == rule_name), None)

    target_id = str(before_row["id"]) if before_row is not None else rule_name
    _require_confirm("upsert_port_forward", target_id, dryRun, confirm)

    if interfaceWanPortIds is not None:
        wan_ids = [str(x).strip() for x in interfaceWanPortIds if str(x).strip()]
    elif before_row is not None and before_row.get("interfaceWanPortId"):
        wan_ids = list(before_row["interfaceWanPortId"])
    else:
        wan = _fetch_wan_networks(client, site)
        ports = ((wan.get("osgPortInfo") or {}).get("wanLanPortSettings") or [])
        wan_ids = [str(p["portUuid"]) for p in ports if isinstance(p, Mapping) and p.get("portUuid") and p.get("mode") == 0]
    if not wan_ids:
        raise OmadaError("no WAN portUuid available; pass interfaceWanPortIds explicitly")

    body: dict[str, Any] = {
        "name": rule_name,
        "status": bool(status),
        "from": 1 if fromIp and str(fromIp).strip() else 0,
        "interfaceWanPortId": wan_ids,
        "externalPort": ext_port,
        "forwardIp": str(fwd_addr),
        "forwardPort": int_port,
        "protocol": proto_val,
        "dMZ": bool(dmz),
    }
    if body["from"] == 1:
        body["limitedAddresses"] = str(ipaddress.IPv4Network(str(fromIp).strip(), strict=False))

    expected = {
        "name": rule_name,
        "status": bool(status),
        "externalPort": ext_port,
        "forwardIp": str(fwd_addr),
        "forwardPort": int_port,
        "protocol": proto_val,
    }
    diff = {"portForward": {"before": before_row, "after": body}}
    if dryRun:
        return _dry_run_result(
            tool_name="upsert_port_forward",
            target_id=target_id,
            before=before_row,
            after=body,
            diff=diff,
            warnings=[],
            rollback=None,
        )

    is_update = before_row is not None
    endpoint = (
        f"sites/{site.site_id}/setting/transmission/portForwardings/{target_id}"
        if is_update
        else f"sites/{site.site_id}/setting/transmission/portForwardings"
    )
    method = "PUT" if is_update else "POST"

    def _read_back() -> dict[str, Any] | None:
        rows_now = _fetch_port_forwards(client, site)
        if is_update:
            return next((dict(r) for r in rows_now if str(r.get("id")) == target_id), None)
        return next((dict(r) for r in rows_now if str(r.get("name")) == rule_name), None)

    def _verify(_before: Any, after_row: Any) -> tuple[bool, str | None]:
        if not isinstance(after_row, Mapping):
            return False, f"port forward rule {target_id!r} missing on read-back"
        return _match_fields(after_row, expected)

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        if live is not None:
            ok, _ = _match_fields(live, expected)
            if ok:
                return True, None, None
        return False, body, live

    write_res = client.write(
        endpoint,
        method=method,
        data=body,
        tool_name="upsert_port_forward",
        target=target_id,
        before=before_row,
        snapshot_payload=before_row if before_row is not None else {"existingPortForwards": existing},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(expected.keys()),
    )
    created = write_res["after"]
    rollback = {
        "tool": "delete_port_forward",
        "arguments": {"rule": str((created or {}).get("id") or rule_name), "dryRun": True},
    } if not is_update and created else None
    return _committed_result(
        tool_name="upsert_port_forward",
        target_id=target_id,
        before=write_res["before"],
        after=created,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


def delete_port_forward(
    client: OmadaClient,
    rule: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a port forwarding rule (``DELETE setting/transmission/portForwardings/{id}``)."""
    site = _site(client)
    rows = _fetch_port_forwards(client, site)
    target = _resolve_by_id_or_name(rows, rule, label="port forward rule")
    target_id = str(target["id"])
    return _delete_entity(
        client,
        tool_name="delete_port_forward",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/transmission/portForwardings/{target_id}",
        before=target,
        snapshot_payload=target,
        fetch_all=lambda: _fetch_port_forwards(client, site),
        match_fn=lambda row: str(row.get("id")) == target_id,
        rollback=None,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="portForward",
    )


def upsert_static_route(
    client: OmadaClient,
    name: str,
    destination: str,
    nextHop: str,
    id: str | None = None,
    interfaceId: str | None = None,
    routeType: int = 0,
    metric: int = 1,
    status: bool = True,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a static route (``setting/transmission/staticRoutings``)."""
    route_name = str(name or "").strip()
    if not route_name:
        raise OmadaError("static route name must be non-empty")
    try:
        dest_net = ipaddress.IPv4Network(str(destination or "").strip(), strict=False)
    except ValueError as exc:
        raise OmadaError(f"invalid destination CIDR {destination!r}: {exc}") from None
    hop_ip = _parse_ipv4(nextHop, "nextHop")
    if isinstance(metric, bool) or not 0 <= int(metric) <= 255:
        raise OmadaError("metric must be an integer between 0 and 255")

    site = _site(client)
    existing = _fetch_static_routes(client, site)
    before_row: dict[str, Any] | None = None
    if id and str(id).strip():
        before_row = _resolve_by_id_or_name(existing, str(id), label="static route")
    else:
        before_row = next((dict(r) for r in existing if str(r.get("name", "")).strip() == route_name), None)

    target_id = str(before_row["id"]) if before_row is not None else route_name
    _require_confirm("upsert_static_route", target_id, dryRun, confirm)

    resolved_iface = str(interfaceId).strip() if interfaceId and str(interfaceId).strip() else None
    if not resolved_iface and before_row is not None:
        resolved_iface = str(before_row.get("interfaceId") or "").strip() or None
    if not resolved_iface:
        wan = _fetch_wan_networks(client, site)
        ports = ((wan.get("osgPortInfo") or {}).get("wanLanPortSettings") or [])
        resolved_iface = next((str(p["portUuid"]) for p in ports if isinstance(p, Mapping) and p.get("portUuid")), None)
    if not resolved_iface:
        ifaces = _fetch_lan_interfaces(client, site)
        resolved_iface = str(ifaces[0]["id"]) if ifaces else None
    if not resolved_iface:
        raise OmadaError("could not resolve an interfaceId for the static route; pass interfaceId explicitly")

    body: dict[str, Any] = {
        "name": route_name,
        "status": bool(status),
        "routeType": int(routeType),
        "destinations": str(dest_net),
        "nextHopIp": str(hop_ip),
        "interfaceId": resolved_iface,
        "metric": int(metric),
    }
    expected = {
        "name": route_name,
        "status": bool(status),
        "nextHopIp": str(hop_ip),
        "metric": int(metric),
    }
    diff = {"staticRoute": {"before": before_row, "after": body}}
    if dryRun:
        return _dry_run_result(
            tool_name="upsert_static_route",
            target_id=target_id,
            before=before_row,
            after=body,
            diff=diff,
            warnings=[],
            rollback=None,
        )

    is_update = before_row is not None
    endpoint = (
        f"sites/{site.site_id}/setting/transmission/staticRoutings/{target_id}"
        if is_update
        else f"sites/{site.site_id}/setting/transmission/staticRoutings"
    )
    method = "PUT" if is_update else "POST"

    def _read_back() -> dict[str, Any] | None:
        rows_now = _fetch_static_routes(client, site)
        if is_update:
            return next((dict(r) for r in rows_now if str(r.get("id")) == target_id), None)
        return next((dict(r) for r in rows_now if str(r.get("name")) == route_name), None)

    def _verify(_before: Any, after_row: Any) -> tuple[bool, str | None]:
        if not isinstance(after_row, Mapping):
            return False, f"static route {target_id!r} missing on read-back"
        ok, reason = _match_fields(after_row, expected)
        if not ok:
            return False, reason
        got_dest = after_row.get("destinations")
        if isinstance(got_dest, list):
            if str(dest_net) not in [str(x) for x in got_dest]:
                return False, f"destinations expected {str(dest_net)!r}, got {got_dest!r}"
        elif str(got_dest) != str(dest_net):
            return False, f"destinations expected {str(dest_net)!r}, got {got_dest!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        if live is not None:
            ok, _ = _verify(before_row, live)
            if ok:
                return True, None, None
        return False, body, live

    write_res = client.write(
        endpoint,
        method=method,
        data=body,
        tool_name="upsert_static_route",
        target=target_id,
        before=before_row,
        snapshot_payload=before_row if before_row is not None else {"existingStaticRoutes": existing},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(expected.keys()) + ["destinations"],
    )
    created = write_res["after"]
    rollback = {
        "tool": "delete_static_route",
        "arguments": {"rule": str((created or {}).get("id") or route_name), "dryRun": True},
    } if not is_update and created else None
    return _committed_result(
        tool_name="upsert_static_route",
        target_id=target_id,
        before=write_res["before"],
        after=created,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


def delete_static_route(
    client: OmadaClient,
    rule: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a static route (``DELETE setting/transmission/staticRoutings/{id}``)."""
    site = _site(client)
    rows = _fetch_static_routes(client, site)
    target = _resolve_by_id_or_name(rows, rule, label="static route")
    target_id = str(target["id"])
    return _delete_entity(
        client,
        tool_name="delete_static_route",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/transmission/staticRoutings/{target_id}",
        before=target,
        snapshot_payload=target,
        fetch_all=lambda: _fetch_static_routes(client, site),
        match_fn=lambda row: str(row.get("id")) == target_id,
        rollback=None,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="staticRoute",
    )


def upsert_policy_route(
    client: OmadaClient,
    name: str,
    routeId: str | None = None,
    status: bool = True,
    protocols: list[int] | None = None,
    sourceType: int = 0,
    sourceIds: list[str] | None = None,
    destinationType: int = 1,
    destinationIds: list[str] | None = None,
    interfaceIds: list[str] | None = None,
    backupInterface: bool = True,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a gateway policy-based route (``setting/transmission/policyRoutings``)."""
    rule_name = str(name or "").strip()
    if not rule_name:
        raise OmadaError("policy route name must be non-empty")
    site = _site(client)
    _require_gateway(client, site, "Policy routing")

    existing_rules = _fetch_policy_routes(client, site)
    existing: dict[str, Any] | None = None
    if routeId:
        existing = _resolve_by_id_or_name(existing_rules, str(routeId), label="policy route")
    else:
        matches = [dict(r) for r in existing_rules if str(r.get("name") or "").strip() == rule_name]
        if matches:
            existing = matches[0]
    target_id = str(existing["id"]) if existing is not None and existing.get("id") else rule_name
    _require_confirm("upsert_policy_route", target_id, dryRun, confirm)

    resolved_src = [str(x) for x in (sourceIds if sourceIds is not None else (existing.get("sourceIds") or [] if existing else []))]
    resolved_dst = [str(x) for x in (destinationIds if destinationIds is not None else (existing.get("destinationIds") or [] if existing else []))]
    if not resolved_src:
        raise OmadaError("sourceIds must contain at least one source network or group ID")
    if not resolved_dst:
        raise OmadaError("destinationIds must contain at least one destination group or network ID")

    # Resolve WAN port names or UUIDs against wan/networks
    wan_info = _fetch_wan_networks(client, site)
    wan_ports = _unwrap_rows(wan_info.get("wanPortSettings") or wan_info.get("wanPorts") or wan_info.get("portList") or [])
    wan_by_name = {
        str(w.get("portName") or w.get("name") or "").strip().lower(): str(w.get("portUuid") or w.get("id") or "")
        for w in wan_ports if (w.get("portUuid") or w.get("id"))
    }
    raw_ifaces: list[str] = []
    if interfaceIds is not None:
        raw_ifaces = [wan_by_name.get(str(x).strip().lower(), str(x).strip()) for x in interfaceIds if str(x).strip()]
    elif existing:
        if existing.get("interfaceId"):
            raw_ifaces = [str(existing["interfaceId"])]
        else:
            raw_ifaces = [str(x) for x in (existing.get("wanPortIds") or [])]
    if not raw_ifaces:
        raise OmadaError("interfaceIds must specify at least one WAN port UUID or name")

    body: dict[str, Any] = {
        "name": rule_name,
        "status": bool(status),
        "protocols": [int(p) for p in (protocols if protocols is not None else (existing.get("protocols") or [256] if existing else [256]))],
        "sourceType": int(sourceType),
        "sourceIds": resolved_src,
        "destinationType": int(destinationType),
        "destinationIds": resolved_dst,
        "backupInterface": bool(backupInterface),
    }
    if len(raw_ifaces) > 1:
        body["interfaceType"] = 4
        body["wanPortIds"] = raw_ifaces
    else:
        body["interfaceType"] = 0
        body["interfaceId"] = raw_ifaces[0]

    before_summary = copy.deepcopy(existing) if existing else None
    diff = (
        _field_diff(before_summary, body, tuple(body.keys()))
        if before_summary
        else {"route": {"before": None, "after": body}}
    )
    if dryRun:
        return _dry_run_result(
            tool_name="upsert_policy_route",
            target_id=target_id,
            before=before_summary,
            after=body,
            diff=diff,
            warnings=[],
            rollback=None,
        )

    method = "PUT" if existing is not None else "POST"
    endpoint = f"sites/{site.site_id}/setting/transmission/policyRoutings/{existing['id']}" if existing is not None else f"sites/{site.site_id}/setting/transmission/policyRoutings"

    def _read_back() -> dict[str, Any] | None:
        rows = _fetch_policy_routes(client, site)
        if existing is not None:
            found = next((r for r in rows if str(r.get("id")) == str(existing["id"])), None)
            if found:
                return found
        return next((r for r in rows if str(r.get("name")) == rule_name), None)

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, f"policy route {rule_name!r} missing on read-back"
        if str(after_now.get("name")) != rule_name:
            return False, f"policy route name expected {rule_name!r}, got {after_now.get('name')!r}"
        if bool(after_now.get("status")) != bool(status):
            return False, f"policy route status expected {status!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_summary, live)
        return ok, (body if existing is not None else None), live

    snap = (
        {"action": "update", "rule": existing}
        if existing is not None
        else {"action": "create", "name": rule_name, "existingIds": [str(r.get("id")) for r in existing_rules if r.get("id")]}
    )
    write_res = client.write(
        endpoint,
        method=method,
        data=body,
        tool_name="upsert_policy_route",
        target=target_id,
        before=before_summary,
        snapshot_payload=snap,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()),
    )
    return _committed_result(
        tool_name="upsert_policy_route",
        target_id=target_id,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=None,
    )


def delete_policy_route(
    client: OmadaClient,
    routeId: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a gateway policy route by ID or unique name."""
    site = _site(client)
    _require_gateway(client, site, "Policy routing")
    rules = _fetch_policy_routes(client, site)
    target = _resolve_by_id_or_name(rules, str(routeId), label="policy route")
    rid = str(target["id"])
    return _delete_entity(
        client,
        tool_name="delete_policy_route",
        target_id=rid,
        endpoint=f"sites/{site.site_id}/setting/transmission/policyRoutings/{rid}",
        before=target,
        snapshot_payload=target,
        fetch_all=lambda: _fetch_policy_routes(client, site),
        match_fn=lambda row: str(row.get("id")) == rid,
        rollback=None,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="policyRoute",
    )


def upsert_lan_dns_rule(
    client: OmadaClient,
    name: str,
    domain: str,
    ruleType: Any = "ip",
    ruleId: str | None = None,
    enable: bool = True,
    ipAddresses: list[str] | None = None,
    ipv6Addresses: list[str] | None = None,
    cname: str | None = None,
    dnsServers: list[str] | None = None,
    lanNetworkIds: list[str] | None = None,
    aliases: list[str] | None = None,
    customTtl: bool = False,
    ttl: int = 3600,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a Local LAN DNS rule (``POST/PATCH setting/lan/dns``)."""
    rule_name = str(name or "").strip()
    dom = str(domain or "").strip()
    if not rule_name:
        raise OmadaError("LAN DNS rule name must be non-empty")
    if not dom:
        raise OmadaError("LAN DNS domain must be non-empty")
    type_code = _parse_code_map(ruleType, _LAN_DNS_TYPE_MAP, label="ruleType")

    site = _site(client)
    existing_rules = _fetch_lan_dns_rules(client, site)
    existing: dict[str, Any] | None = None
    if ruleId:
        existing = _resolve_by_id_or_name(existing_rules, str(ruleId), label="LAN DNS rule")
    else:
        matches = [dict(r) for r in existing_rules if str(r.get("name") or "").strip() == rule_name]
        if matches:
            existing = matches[0]
    target_id = str(existing["id"]) if existing is not None and existing.get("id") else rule_name
    _require_confirm("upsert_lan_dns_rule", target_id, dryRun, confirm)

    warnings: list[str] = []
    if type_code in (0, 1):
        if lanNetworkIds is not None:
            resolved_nets = [str(x) for x in lanNetworkIds if str(x).strip()]
        elif existing and existing.get("lanNetworkIds"):
            resolved_nets = [str(x) for x in existing["lanNetworkIds"]]
        else:
            resolved_nets = [str(n["id"]) for n in _fetch_lan_interfaces(client, site) if n.get("id")]
            if resolved_nets:
                warnings.append(f"lanNetworkIds omitted; defaulting to all {len(resolved_nets)} site LAN interface(s).")
        if not resolved_nets:
            raise OmadaError("lanNetworkIds must be non-empty for LAN DNS IP/CNAME rules")
    else:
        resolved_nets = []

    body: dict[str, Any] = {
        "name": rule_name,
        "enable": bool(enable),
        "domain": dom,
        "aliases": [str(a).strip() for a in (aliases if aliases is not None else (existing.get("aliases") or [] if existing else [])) if str(a).strip()],
        "type": type_code,
        "customTtl": bool(customTtl),
    }
    if customTtl:
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1 or ttl > 86400:
            raise OmadaError("ttl must be an integer between 1 and 86400 seconds")
        body["ttl"] = ttl

    if type_code == 0:
        v4 = [str(_parse_ipv4(ip, "ipAddress")) for ip in (ipAddresses if ipAddresses is not None else (existing.get("ipAddresses") or [] if existing else []))]
        v6 = [str(ipaddress.IPv6Address(str(x).strip())) for x in (ipv6Addresses if ipv6Addresses is not None else (existing.get("ipv6Addresses") or [] if existing else []))]
        if not v4 and not v6:
            raise OmadaError("type='ip' requires at least one valid IPv4 (ipAddresses) or IPv6 (ipv6Addresses) address")
        if v4:
            body["ipAddresses"] = v4
        if v6:
            body["ipv6Addresses"] = v6
        body["lanNetworkIds"] = resolved_nets
    elif type_code == 1:
        cn = str(cname if cname is not None else (existing.get("cname") or "" if existing else "")).strip()
        if not cn:
            raise OmadaError("type='cname' requires a non-empty cname target")
        body["cname"] = cn
        body["lanNetworkIds"] = resolved_nets
    else:
        servers = [str(_parse_ipv4(s, "dnsServer")) for s in (dnsServers if dnsServers is not None else (existing.get("dnsServers") or [] if existing else []))]
        if not servers:
            raise OmadaError("type='forward' requires at least one dnsServer IPv4 address")
        body["dnsServers"] = servers

    before_summary = copy.deepcopy(existing) if existing else None
    diff = (
        _field_diff(before_summary, body, tuple(body.keys()))
        if before_summary
        else {"rule": {"before": None, "after": body}}
    )
    if dryRun:
        return _dry_run_result(
            tool_name="upsert_lan_dns_rule",
            target_id=target_id,
            before=before_summary,
            after=body,
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    method = "PATCH" if existing is not None else "POST"
    endpoint = f"sites/{site.site_id}/setting/lan/dns/{existing['id']}" if existing is not None else f"sites/{site.site_id}/setting/lan/dns"

    def _read_back() -> dict[str, Any] | None:
        rows = _fetch_lan_dns_rules(client, site)
        if existing is not None:
            found = next((r for r in rows if str(r.get("id")) == str(existing["id"])), None)
            if found:
                return found
        return next((r for r in rows if str(r.get("name")) == rule_name), None)

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, f"LAN DNS rule {rule_name!r} missing on read-back"
        if str(after_now.get("name")) != rule_name or str(after_now.get("domain")) != dom:
            return False, f"LAN DNS rule {rule_name!r} fields did not match intent on read-back"
        if bool(after_now.get("enable")) != bool(enable):
            return False, f"LAN DNS enable expected {enable!r}, got {after_now.get('enable')!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_summary, live)
        return ok, (body if existing is not None else None), live

    snap = (
        {"action": "update", "rule": existing}
        if existing is not None
        else {"action": "create", "name": rule_name, "existingIds": [str(r.get("id")) for r in existing_rules if r.get("id")]}
    )
    write_res = client.write(
        endpoint,
        method=method,
        data=body,
        tool_name="upsert_lan_dns_rule",
        target=target_id,
        before=before_summary,
        snapshot_payload=snap,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()),
    )
    return _committed_result(
        tool_name="upsert_lan_dns_rule",
        target_id=target_id,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )


def delete_lan_dns_rule(
    client: OmadaClient,
    ruleId: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a Local LAN DNS rule by ID or unique name."""
    site = _site(client)
    rules = _fetch_lan_dns_rules(client, site)
    target = _resolve_by_id_or_name(rules, str(ruleId), label="LAN DNS rule")
    rid = str(target["id"])
    return _delete_entity(
        client,
        tool_name="delete_lan_dns_rule",
        target_id=rid,
        endpoint=f"sites/{site.site_id}/setting/lan/dns/{rid}",
        before=target,
        snapshot_payload=target,
        fetch_all=lambda: _fetch_lan_dns_rules(client, site),
        match_fn=lambda row: str(row.get("id")) == rid,
        rollback=None,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="lanDnsRule",
    )

