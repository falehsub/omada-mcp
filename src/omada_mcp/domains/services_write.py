"""Write domain module: services_write."""

from __future__ import annotations

import urllib.parse
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError, SiteInfo
from ._write_common import (
    _committed_result,
    _delete_entity,
    _dry_run_result,
    _match_fields,
    _normalize_mac,
    _parse_ipv4,
    _require_confirm,
    _resolve_by_id_or_name,
    _site,
)
from ._write_fetchers import (
    _fetch_devices,
    _fetch_dhcp_reservations,
    _fetch_lan_collection,
    _fetch_lan_interfaces,
    _fetch_mdns_profiles,
    _fetch_mdns_rules,
    _fetch_wan_networks,
    _omada_mac,
    _resolve_lan_network,
)
from ._write_safety import _management_endpoints, _network_dhcp_ranges, _network_subnet_and_gw


def upsert_dhcp_reservation(
    client: OmadaClient,
    mac: str,
    ip: str,
    vlan: Any | None = None,
    netId: str | None = None,
    description: str | None = None,
    status: bool = True,
    exportToIpMacBinding: bool | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a static DHCP reservation via ``setting/service/dhcp`` (works offline)."""
    omada_mac = _omada_mac(mac)
    norm_mac = _normalize_mac(omada_mac)
    target_addr = _parse_ipv4(ip, "DHCP reservation IP")
    _require_confirm("upsert_dhcp_reservation", norm_mac, dryRun, confirm)

    site = _site(client)
    interfaces = _fetch_lan_interfaces(client, site)
    target_net = _resolve_lan_network(interfaces, vlan=vlan, net_id=netId, target_ip=target_addr)
    devices = _fetch_devices(client, site)
    subnet, gw_ip = _network_subnet_and_gw(target_net)
    if subnet is not None:
        if target_addr not in subnet:
            raise OmadaError(f"IP {target_addr} falls outside network subnet {subnet}")
        if subnet.prefixlen < 31 and target_addr in (subnet.network_address, subnet.broadcast_address):
            raise OmadaError(f"IP {target_addr} cannot be network or broadcast address of {subnet}")
    if gw_ip is not None and target_addr == gw_ip:
        raise OmadaError(f"IP {target_addr} conflicts with the VLAN gateway IP")
    controller_ip, _ = _management_endpoints(client)
    if controller_ip is not None and target_addr == controller_ip:
        raise OmadaError(f"refusing reservation IP {target_addr}: matches Omada controller IP")
    for dev in devices:
        if str(dev.get("ip") or "").strip() == str(target_addr):
            raise OmadaError(
                f"refusing reservation IP {target_addr}: already assigned to device "
                f"{dev.get('name') or dev.get('mac')}",
            )

    existing_rows = _fetch_dhcp_reservations(client, site)
    for row in existing_rows:
        if _normalize_mac(row.get("mac", "")) != norm_mac and str(row.get("ip") or "").strip() == str(target_addr):
            raise OmadaError(
                f"IP {target_addr} is already reserved for MAC {_normalize_mac(row.get('mac', ''))}",
                code=-34522,
                hint="pick a free IP or delete/update the conflicting DHCP reservation",
            )

    before_row = next((dict(r) for r in existing_rows if _normalize_mac(r.get("mac", "")) == norm_mac), None)
    net_hex = str(target_net["id"])
    desired_desc = (
        str(description)
        if description is not None
        else str(before_row.get("description", "")) if before_row is not None else ""
    )
    desired_export = (
        bool(exportToIpMacBinding)
        if exportToIpMacBinding is not None
        else bool(before_row.get("exportToIpMacBinding", False)) if before_row is not None else False
    )

    body: dict[str, Any] = {
        "netId": net_hex,
        "mac": before_row["mac"] if before_row is not None else omada_mac,
        "ip": str(target_addr),
        "status": bool(status),
        "description": desired_desc,
        "exportToIpMacBinding": desired_export,
    }

    expected = {"netId": net_hex, "ip": str(target_addr), "status": bool(status)}
    if description is not None:
        expected["description"] = desired_desc

    before_summary = (
        {
            "mac": before_row.get("mac"),
            "ip": before_row.get("ip"),
            "netId": before_row.get("netId"),
            "status": bool(before_row.get("status", True)),
            "description": before_row.get("description", ""),
        }
        if before_row is not None
        else None
    )
    after_preview = {
        "mac": body["mac"],
        "ip": str(target_addr),
        "netId": net_hex,
        "status": bool(status),
        "description": desired_desc,
    }
    diff = {"reservation": {"before": before_summary, "after": after_preview}}
    warnings: list[str] = []
    for s_ip, e_ip in _network_dhcp_ranges(target_net):
        if s_ip <= target_addr <= e_ip:
            warnings.append(
                f"IP {target_addr} falls inside dynamic DHCP pool {s_ip}-{e_ip}; ensure no active "
                "client holds a conflicting dynamic lease"
            )
    rollback = (
        {
            "tool": "upsert_dhcp_reservation",
            "arguments": {
                "mac": norm_mac,
                "ip": before_row["ip"],
                "netId": before_row["netId"],
                "status": bool(before_row.get("status", True)),
                "description": before_row.get("description", ""),
                "dryRun": True,
            },
        }
        if before_row is not None
        else {
            "tool": "delete_dhcp_reservation",
            "arguments": {"mac": norm_mac, "dryRun": True},
        }
    )

    if dryRun:
        return _dry_run_result(
            tool_name="upsert_dhcp_reservation",
            target_id=norm_mac,
            before=before_summary,
            after=after_preview,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    endpoint = (
        f"sites/{site.site_id}/setting/service/dhcp/{urllib.parse.quote(str(before_row['mac']), safe='')}"
        if before_row is not None
        else f"sites/{site.site_id}/setting/service/dhcp"
    )
    method = "PUT" if before_row is not None else "POST"

    def _read_back() -> dict[str, Any] | None:
        rows_now = _fetch_dhcp_reservations(client, site)
        return next((dict(r) for r in rows_now if _normalize_mac(r.get("mac", "")) == norm_mac), None)

    def _verify(_before: Any, after_row: Any) -> tuple[bool, str | None]:
        if not isinstance(after_row, Mapping):
            return False, f"DHCP reservation for {norm_mac} missing on read-back"
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
        tool_name="upsert_dhcp_reservation",
        target=norm_mac,
        before=before_summary,
        snapshot_payload=before_row if before_row is not None else {"existingReservations": existing_rows},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(expected.keys()),
    )
    return _committed_result(
        tool_name="upsert_dhcp_reservation",
        target_id=norm_mac,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def delete_dhcp_reservation(
    client: OmadaClient,
    mac: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a static DHCP reservation by MAC (``DELETE setting/service/dhcp/{mac}``)."""
    omada_mac = _omada_mac(mac)
    norm_mac = _normalize_mac(omada_mac)
    site = _site(client)
    rows = _fetch_dhcp_reservations(client, site)
    target_row = next((dict(r) for r in rows if _normalize_mac(r.get("mac", "")) == norm_mac), None)
    if target_row is None:
        raise OmadaError(f"no static DHCP reservation exists for MAC {norm_mac!r}")

    controller_ip, _ = _management_endpoints(client)
    if controller_ip is not None and str(target_row.get("ip") or "").strip() == str(controller_ip):
        raise OmadaError(f"refusing to delete reservation for controller IP {controller_ip}")

    rollback = {
        "tool": "upsert_dhcp_reservation",
        "arguments": {
            "mac": norm_mac,
            "ip": target_row["ip"],
            "netId": target_row["netId"],
            "status": bool(target_row.get("status", True)),
            "description": target_row.get("description", ""),
            "dryRun": True,
        },
    }
    return _delete_entity(
        client,
        tool_name="delete_dhcp_reservation",
        target_id=norm_mac,
        endpoint=f"sites/{site.site_id}/setting/service/dhcp/{urllib.parse.quote(str(target_row['mac']), safe='')}",
        before=target_row,
        snapshot_payload=target_row,
        fetch_all=lambda: _fetch_dhcp_reservations(client, site),
        match_fn=lambda r: _normalize_mac(r.get("mac", "")) == norm_mac,
        rollback=rollback,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="dhcpReservation",
    )


def upsert_mdns_rule(
    client: OmadaClient,
    name: str,
    profiles: list[str],
    serviceNetworks: list[str],
    clientNetworks: list[str],
    id: str | None = None,
    ruleType: str = "gateway",
    status: bool = True,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update an mDNS reflector/repeater rule (``setting/service/mdns``)."""
    rule_name = str(name or "").strip()
    if not rule_name:
        raise OmadaError("mDNS rule name must be non-empty")
    if not profiles or not serviceNetworks or not clientNetworks:
        raise OmadaError("profiles, serviceNetworks, and clientNetworks must all be non-empty arrays")

    rtype_str = str(ruleType or "gateway").strip().lower()
    if rtype_str in ("gateway", "osg", "1"):
        rtype = 1
    elif rtype_str in ("ap", "0"):
        rtype = 0
    else:
        raise OmadaError(f"invalid ruleType {ruleType!r}; expected 'gateway' or 'ap'")

    site = _site(client)
    existing = _fetch_mdns_rules(client, site)
    before_row: dict[str, Any] | None = None
    if id and str(id).strip():
        before_row = _resolve_by_id_or_name(existing, str(id), label="mDNS rule")
    else:
        before_row = next((dict(r) for r in existing if str(r.get("name", "")).strip() == rule_name), None)
    target_id = str(before_row["id"]) if before_row is not None else rule_name
    _require_confirm("upsert_mdns_rule", target_id, dryRun, confirm)

    avail_profiles = _fetch_mdns_profiles(client, site)
    resolved_profiles = [
        str(_resolve_by_id_or_name(avail_profiles, str(p), label="mDNS profile")["id"])
        for p in profiles
    ]
    networks = _fetch_lan_collection(client, site)
    svc_nets = [_resolve_lan_network(networks, vlan=str(n)) for n in serviceNetworks]
    cli_nets = [_resolve_lan_network(networks, vlan=str(n)) for n in clientNetworks]

    body: dict[str, Any] = {"name": rule_name, "status": bool(status), "type": rtype}
    if rtype == 1:
        body["osg"] = {
            "profileIds": resolved_profiles,
            "serviceNetworks": [str(n["id"]) for n in svc_nets],
            "clientNetworks": [str(n["id"]) for n in cli_nets],
        }
    else:
        body["ap"] = {
            "profileIds": resolved_profiles,
            "serviceVlan": int(svc_nets[0]["vlan"]),
            "clientVlan": [int(n["vlan"]) for n in cli_nets],
        }

    expected: dict[str, Any] = {"name": rule_name, "status": bool(status), "type": rtype}
    diff = {"mdnsRule": {"before": before_row, "after": body}}
    if dryRun:
        return _dry_run_result(
            tool_name="upsert_mdns_rule",
            target_id=target_id,
            before=before_row,
            after=body,
            diff=diff,
            warnings=[],
            rollback=None,
        )

    is_update = before_row is not None
    endpoint = (
        f"sites/{site.site_id}/setting/service/mdns/{target_id}"
        if is_update
        else f"sites/{site.site_id}/setting/service/mdns"
    )
    method = "PUT" if is_update else "POST"

    def _read_back() -> dict[str, Any] | None:
        rows_now = _fetch_mdns_rules(client, site)
        if is_update:
            return next((dict(r) for r in rows_now if str(r.get("id")) == target_id), None)
        return next((dict(r) for r in rows_now if str(r.get("name")) == rule_name), None)

    def _verify(_before: Any, after_row: Any) -> tuple[bool, str | None]:
        if not isinstance(after_row, Mapping):
            return False, f"mDNS rule {target_id!r} missing on read-back"
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
        tool_name="upsert_mdns_rule",
        target=target_id,
        before=before_row,
        snapshot_payload=before_row if before_row is not None else {"existingMdnsRules": existing},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["name", "status", "type"],
    )
    created = write_res["after"]
    rollback = {
        "tool": "delete_mdns_rule",
        "arguments": {"rule": str((created or {}).get("id") or rule_name), "dryRun": True},
    } if not is_update and created else None
    return _committed_result(
        tool_name="upsert_mdns_rule",
        target_id=target_id,
        before=write_res["before"],
        after=created,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


def delete_mdns_rule(
    client: OmadaClient,
    rule: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete an mDNS reflector rule (``DELETE setting/service/mdns/{id}``)."""
    site = _site(client)
    rows = _fetch_mdns_rules(client, site)
    target = _resolve_by_id_or_name(rows, rule, label="mDNS rule")
    target_id = str(target["id"])
    return _delete_entity(
        client,
        tool_name="delete_mdns_rule",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/service/mdns/{target_id}",
        before=target,
        snapshot_payload=target,
        fetch_all=lambda: _fetch_mdns_rules(client, site),
        match_fn=lambda row: str(row.get("id")) == target_id,
        rollback=None,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="mdnsRule",
    )


def _resolve_upnp_targets(
    client: OmadaClient,
    site: SiteInfo,
    before_obj: Mapping[str, Any],
    *,
    wan_port_ids: Sequence[str] | None = None,
    network_ids: Sequence[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Resolve non-empty ``wanPortIds`` and ``networkIds`` required when UPnP is enabled on v6.2+."""
    if wan_port_ids is not None:
        resolved_wan = [str(p).strip() for p in wan_port_ids if str(p).strip()]
    else:
        existing_wan = before_obj.get("wanPortIds")
        if isinstance(existing_wan, Sequence) and not isinstance(existing_wan, (str, bytes)) and existing_wan:
            resolved_wan = [str(p).strip() for p in existing_wan if str(p).strip()]
        else:
            wan = _fetch_wan_networks(client, site)
            raw_uuids = wan.get("portUuids")
            if isinstance(raw_uuids, Sequence) and not isinstance(raw_uuids, (str, bytes)) and raw_uuids:
                resolved_wan = [str(p).strip() for p in raw_uuids if str(p).strip()]
            else:
                port_settings = (wan.get("osgPortInfo") or {}).get("wanLanPortSettings") or []
                resolved_wan = [
                    str(p["portUuid"]).strip()
                    for p in port_settings
                    if isinstance(p, Mapping) and p.get("portUuid") and p.get("mode") == 0
                ]
    if not resolved_wan:
        raise OmadaError(
            "enabling UPnP requires at least one WAN port ID (wanPortIds)",
            code=-1001,
            hint="Ensure a WAN interface is configured or pass wanPortIds explicitly.",
        )

    if network_ids is not None:
        ifaces = _fetch_lan_interfaces(client, site)
        resolved_nets: list[str] = []
        for item in network_ids:
            matched = _resolve_lan_network(ifaces, vlan=item)
            nid = str(matched.get("id") or "").strip()
            if nid and nid not in resolved_nets:
                resolved_nets.append(nid)
    else:
        existing_nets = before_obj.get("networkIds")
        if isinstance(existing_nets, Sequence) and not isinstance(existing_nets, (str, bytes)) and existing_nets:
            resolved_nets = [str(n).strip() for n in existing_nets if str(n).strip()]
        else:
            ifaces = _fetch_lan_interfaces(client, site)
            resolved_nets = [str(n["id"]).strip() for n in ifaces if n.get("id")]
    if not resolved_nets:
        raise OmadaError(
            "enabling UPnP requires at least one LAN interface ID (networkIds)",
            code=-1001,
            hint="Create a routed LAN interface or pass networkIds explicitly.",
        )
    return resolved_wan, resolved_nets


def set_upnp(
    client: OmadaClient,
    enable: bool,
    wanPortIds: list[str] | None = None,
    networkIds: list[str] | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Enable or disable UPnP on the site gateway (``PUT setting/upnp``)."""
    site = _site(client)
    target_id = site.site_id
    _require_confirm("set_upnp", target_id, dryRun, confirm)
    before_raw = client.api_result(f"sites/{site.site_id}/setting/upnp")
    before_obj = dict(before_raw) if isinstance(before_raw, Mapping) else {"enable": False}
    desired = bool(enable)
    warnings: list[str] = []
    if desired:
        resolved_wan, resolved_nets = _resolve_upnp_targets(
            client, site, before_obj, wan_port_ids=wanPortIds, network_ids=networkIds,
        )
        put_payload: dict[str, Any] = {
            "enable": True,
            "wanPortIds": resolved_wan,
            "networkIds": resolved_nets,
        }
        devices = _fetch_devices(client, site)
        if not any(str(d.get("type") or "").lower() == "gateway" for d in devices):
            warnings.append("no adopted gateway device found in site; live activation returns -33001")
        diff: dict[str, Any] = {
            "enable": {"before": bool(before_obj.get("enable", False)), "after": True},
            "wanPortIds": {"before": before_obj.get("wanPortIds") or [], "after": resolved_wan},
            "networkIds": {"before": before_obj.get("networkIds") or [], "after": resolved_nets},
        }
    else:
        put_payload = {"enable": False}
        diff = {"enable": {"before": bool(before_obj.get("enable", False)), "after": False}}

    after_preview = {**before_obj, **put_payload}
    rb_args: dict[str, Any] = {"enable": bool(before_obj.get("enable", False)), "dryRun": True}
    if before_obj.get("enable"):
        wan_port_ids = before_obj.get("wanPortIds")
        if isinstance(wan_port_ids, list) and wan_port_ids:
            rb_args["wanPortIds"] = list(wan_port_ids)
        network_ids = before_obj.get("networkIds")
        if isinstance(network_ids, list) and network_ids:
            rb_args["networkIds"] = list(network_ids)
    rollback = {
        "tool": "set_upnp",
        "arguments": rb_args,
    }
    if dryRun:
        return _dry_run_result(
            tool_name="set_upnp",
            target_id=target_id,
            before=before_obj,
            after=after_preview,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/setting/upnp"

    def _read_back() -> dict[str, Any]:
        raw = client.api_result(endpoint)
        return dict(raw) if isinstance(raw, Mapping) else {}

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, "UPnP read-back failed"
        if bool(after_now.get("enable")) != desired:
            return False, f"UPnP enable expected {desired!r}, got {after_now.get('enable')!r}"
        if desired:
            if isinstance(after_now.get("wanPortIds"), list) and set(map(str, after_now["wanPortIds"])) != set(put_payload["wanPortIds"]):
                return False, f"UPnP wanPortIds mismatch on read-back: {after_now.get('wanPortIds')!r}"
            if isinstance(after_now.get("networkIds"), list) and set(map(str, after_now["networkIds"])) != set(put_payload["networkIds"]):
                return False, f"UPnP networkIds mismatch on read-back: {after_now.get('networkIds')!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_obj, live)
        return ok, dict(put_payload), live

    write_res = client.write(
        endpoint,
        method="PUT",
        data=put_payload,
        tool_name="set_upnp",
        target=target_id,
        before=before_obj,
        snapshot_payload=before_obj,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(put_payload.keys()),
    )
    return _committed_result(
        tool_name="set_upnp",
        target_id=target_id,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )

