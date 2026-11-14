"""Write domain module: networks_write."""

from __future__ import annotations

import copy
import ipaddress
from collections.abc import Mapping
from typing import Any

from ..client import OmadaClient, OmadaError
from ._write_common import (
    _committed_result,
    _delete_entity,
    _diff_mappings,
    _dry_run_result,
    _parse_ipv4,
    _require_confirm,
    _site,
    _validate_vlan_id,
)
from ._write_fetchers import (
    _ensure_lan_patch_body,
    _fetch_devices,
    _fetch_dhcp_reservations,
    _fetch_lan_collection,
    _fetch_lan_interfaces,
    _fetch_lan_pair,
    _fetch_wan_networks,
    _lan_drift_ignore_keys,
    _resolve_lan_network,
)
from ._write_safety import (
    _check_dhcp_pools_safety,
    _check_vlan_isolation_safety,
    _management_endpoints,
    _network_subnet_and_gw,
)


def set_vlan_isolation(
    client: OmadaClient,
    isolation: bool,
    vlan: Any | None = None,
    netId: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Set client isolation on a LAN/VLAN via the two-endpoint read-modify-write flow."""
    site = _site(client)
    col_before, iface_before = _fetch_lan_pair(client, site, vlan=vlan, net_id=netId)
    target_id = str(iface_before["id"])
    _require_confirm("set_vlan_isolation", target_id, dryRun, confirm)

    desired = bool(isolation)
    _check_vlan_isolation_safety(client, iface_before, desired)

    patch_body, defaulted_ipv6 = _ensure_lan_patch_body(iface_before)
    patch_body["isolation"] = desired

    before_summary = {
        "id": target_id,
        "name": iface_before.get("name") or col_before.get("name"),
        "vlan": iface_before.get("vlan") or col_before.get("vlan"),
        "isolation": bool(iface_before.get("isolation")),
        "collectionIsolation": bool(col_before.get("isolation")),
        "accessControlRule": col_before.get("accessControlRule"),
        "existNetworkIsolation": col_before.get("existNetworkIsolation"),
    }
    proposed_after = dict(before_summary)
    proposed_after["isolation"] = desired
    proposed_after["collectionIsolation"] = desired

    diff = {
        "isolation": {
            "before": bool(iface_before.get("isolation")),
            "after": desired,
        },
    }
    warnings: list[str] = []
    if desired:
        warnings.append("enabling VLAN isolation cuts client-to-client traffic within this VLAN")
    warnings.append(
        f"observed collection accessControlRule={col_before.get('accessControlRule')!r} separately; "
        "isolation and accessControlRule are independent fields on this controller"
    )
    rollback = {
        "tool": "set_vlan_isolation",
        "arguments": {"netId": target_id, "isolation": bool(iface_before.get("isolation")), "dryRun": True},
    }

    if dryRun:
        return _dry_run_result(
            tool_name="set_vlan_isolation",
            target_id=target_id,
            before=before_summary,
            after=proposed_after,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/setting/lan/networks/{target_id}"

    def _read_back() -> dict[str, Any]:
        col_after, iface_after = _fetch_lan_pair(client, site, net_id=target_id)
        return {"collection": col_after, "interface": iface_after}

    def _verify(_before: Any, after_pair: Any) -> tuple[bool, str | None]:
        if not isinstance(after_pair, Mapping):
            return False, "read-back did not return collection/interface pair"
        col_after = after_pair["collection"]
        iface_after = after_pair["interface"]
        if bool(iface_after.get("isolation")) != desired:
            return False, (f"interface isolation expected {desired}, "
                           f"got {iface_after.get('isolation')!r}")
        if "isolation" in col_after and bool(col_after.get("isolation")) != desired:
            return False, (f"collection isolation expected {desired}, "
                           f"got {col_after.get('isolation')!r}")
        ignore_keys = _lan_drift_ignore_keys(
            iface_before,
            iface_after,
            ["isolation"],
            defaulted_ipv6=defaulted_ipv6,
        )
        drifts = _diff_mappings(iface_before, iface_after, ignore_keys=ignore_keys)
        if drifts:
            return False, "unexpected field drift on LAN interface after PATCH: " + ", ".join(drifts)
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        pair = _read_back()
        ok, _ = _verify(before_summary, pair)
        if ok:
            return True, None, None
        fresh_iface = pair["interface"]
        fresh_col = pair["collection"]
        fresh_patch, _ = _ensure_lan_patch_body(fresh_iface)
        fresh_patch["isolation"] = desired
        fresh_before = {
            "id": target_id,
            "name": fresh_iface.get("name") or fresh_col.get("name"),
            "vlan": fresh_iface.get("vlan") or fresh_col.get("vlan"),
            "isolation": bool(fresh_iface.get("isolation")),
            "collectionIsolation": bool(fresh_col.get("isolation")),
            "accessControlRule": fresh_col.get("accessControlRule"),
            "existNetworkIsolation": fresh_col.get("existNetworkIsolation"),
        }
        return False, fresh_patch, fresh_before

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=patch_body,
        tool_name="set_vlan_isolation",
        target=target_id,
        before=before_summary,
        snapshot_payload={"collection": col_before, "interface": iface_before},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["isolation"],
    )
    after_pair = write_res["after"]
    col_after = after_pair["collection"]
    iface_after = after_pair["interface"]
    after_summary = {
        "id": target_id,
        "name": iface_after.get("name") or col_after.get("name"),
        "vlan": iface_after.get("vlan") or col_after.get("vlan"),
        "isolation": bool(iface_after.get("isolation")),
        "collectionIsolation": bool(col_after.get("isolation")),
        "accessControlRule": col_after.get("accessControlRule"),
        "existNetworkIsolation": col_after.get("existNetworkIsolation"),
    }
    return _committed_result(
        tool_name="set_vlan_isolation",
        target_id=target_id,
        before=write_res["before"],
        after=after_summary,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def set_vlan_dhcp_pools(
    client: OmadaClient,
    pools: list[dict[str, Any]],
    vlan: Any | None = None,
    netId: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Update ``dhcpSettings.ipRangePool`` on a LAN/VLAN with full-object PATCH."""
    site = _site(client)
    col_before, iface_before = _fetch_lan_pair(client, site, vlan=vlan, net_id=netId)
    target_id = str(iface_before["id"])
    _require_confirm("set_vlan_dhcp_pools", target_id, dryRun, confirm)

    devices = _fetch_devices(client, site)
    normalized_pools = _check_dhcp_pools_safety(client, iface_before, pools, devices)
    outer_start = str(min(ipaddress.IPv4Address(p["ipaddrStart"]) for p in normalized_pools))
    outer_end = str(max(ipaddress.IPv4Address(p["ipaddrEnd"]) for p in normalized_pools))

    patch_body, defaulted_ipv6 = _ensure_lan_patch_body(iface_before)
    dhcp_before = copy.deepcopy(iface_before.get("dhcpSettings") or {})
    if not isinstance(patch_body.get("dhcpSettings"), dict):
        patch_body["dhcpSettings"] = {}
    patch_body["dhcpSettings"]["ipRangePool"] = copy.deepcopy(normalized_pools)
    patch_body["dhcpSettings"]["ipaddrStart"] = outer_start
    patch_body["dhcpSettings"]["ipaddrEnd"] = outer_end

    before_pools = copy.deepcopy(dhcp_before.get("ipRangePool") or [])
    before_summary = {
        "id": target_id,
        "name": iface_before.get("name") or col_before.get("name"),
        "vlan": iface_before.get("vlan") or col_before.get("vlan"),
        "enable": bool(dhcp_before.get("enable")),
        "ipRangePool": before_pools,
        "ipaddrStart": dhcp_before.get("ipaddrStart"),
        "ipaddrEnd": dhcp_before.get("ipaddrEnd"),
    }
    proposed_after = {
        "id": target_id,
        "name": before_summary["name"],
        "vlan": before_summary["vlan"],
        "enable": before_summary["enable"],
        "ipRangePool": copy.deepcopy(normalized_pools),
        "ipaddrStart": outer_start,
        "ipaddrEnd": outer_end,
    }
    diff = {"dhcpSettings.ipRangePool": {"before": before_pools, "after": normalized_pools}}
    warnings: list[str] = []
    if not dhcp_before.get("enable"):
        warnings.append("dhcpSettings.enable is currently false on this network; leases will not be served until enabled")
    rollback: dict[str, Any] | None = None
    if before_pools:
        try:
            _check_dhcp_pools_safety(client, iface_before, before_pools, devices)
        except OmadaError:
            warnings.append(
                "previous controller dhcpSettings.ipRangePool overlapped the gateway or controller IP; "
                "automatic rollback via set_vlan_dhcp_pools was omitted"
            )
        else:
            rollback = {
                "tool": "set_vlan_dhcp_pools",
                "arguments": {"netId": target_id, "pools": before_pools, "dryRun": True},
            }

    if dryRun:
        return _dry_run_result(
            tool_name="set_vlan_dhcp_pools",
            target_id=target_id,
            before=before_summary,
            after=proposed_after,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/setting/lan/networks/{target_id}"
    dhcp_ignore_base = [
        "dhcpSettings.ipRangePool",
        "dhcpSettings.ipaddrStart",
        "dhcpSettings.ipaddrEnd",
        "dhcpSettings.ipRangeStart",
        "dhcpSettings.ipRangeEnd",
    ]

    def _read_back() -> dict[str, Any]:
        col_after, iface_after = _fetch_lan_pair(client, site, net_id=target_id)
        return {"collection": col_after, "interface": iface_after}

    def _verify(_before: Any, after_pair: Any) -> tuple[bool, str | None]:
        if not isinstance(after_pair, Mapping):
            return False, "read-back did not return collection/interface pair"
        col_after = after_pair["collection"]
        iface_after = after_pair["interface"]
        after_dhcp = iface_after.get("dhcpSettings") or {}
        if after_dhcp.get("ipRangePool") != normalized_pools:
            return False, (f"interface dhcpSettings.ipRangePool expected {normalized_pools!r}, "
                           f"got {after_dhcp.get('ipRangePool')!r}")
        col_dhcp = col_after.get("dhcpSettings") or {}
        if isinstance(col_dhcp, Mapping) and "ipRangePool" in col_dhcp and col_dhcp.get("ipRangePool") != normalized_pools:
            return False, (f"collection dhcpSettings.ipRangePool expected {normalized_pools!r}, "
                           f"got {col_dhcp.get('ipRangePool')!r}")
        ignore_keys = _lan_drift_ignore_keys(
            iface_before,
            iface_after,
            dhcp_ignore_base,
            defaulted_ipv6=defaulted_ipv6,
        )
        drifts = _diff_mappings(iface_before, iface_after, ignore_keys=ignore_keys)
        if drifts:
            return False, "unexpected field drift on LAN interface after PATCH: " + ", ".join(drifts)
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        pair = _read_back()
        ok, _ = _verify(before_summary, pair)
        if ok:
            return True, None, None
        fresh_iface = pair["interface"]
        fresh_col = pair["collection"]
        fresh_patch, _ = _ensure_lan_patch_body(fresh_iface)
        if not isinstance(fresh_patch.get("dhcpSettings"), dict):
            fresh_patch["dhcpSettings"] = {}
        fresh_patch["dhcpSettings"]["ipRangePool"] = copy.deepcopy(normalized_pools)
        fresh_patch["dhcpSettings"]["ipaddrStart"] = outer_start
        fresh_patch["dhcpSettings"]["ipaddrEnd"] = outer_end
        fresh_dhcp = fresh_iface.get("dhcpSettings") or {}
        fresh_before = {
            "id": target_id,
            "name": fresh_iface.get("name") or fresh_col.get("name"),
            "vlan": fresh_iface.get("vlan") or fresh_col.get("vlan"),
            "enable": bool(fresh_dhcp.get("enable")),
            "ipRangePool": copy.deepcopy(fresh_dhcp.get("ipRangePool") or []),
            "ipaddrStart": fresh_dhcp.get("ipaddrStart"),
            "ipaddrEnd": fresh_dhcp.get("ipaddrEnd"),
        }
        return False, fresh_patch, fresh_before

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=patch_body,
        tool_name="set_vlan_dhcp_pools",
        target=target_id,
        before=before_summary,
        snapshot_payload={"collection": col_before, "interface": iface_before},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["dhcpSettings.ipRangePool"],
    )
    after_iface = write_res["after"]["interface"]
    after_dhcp = after_iface.get("dhcpSettings") or {}
    after_summary = {
        "id": target_id,
        "name": after_iface.get("name"),
        "vlan": after_iface.get("vlan"),
        "enable": bool(after_dhcp.get("enable")),
        "ipRangePool": copy.deepcopy(after_dhcp.get("ipRangePool") or []),
        "ipaddrStart": after_dhcp.get("ipaddrStart"),
        "ipaddrEnd": after_dhcp.get("ipaddrEnd"),
    }
    return _committed_result(
        tool_name="set_vlan_dhcp_pools",
        target_id=target_id,
        before=write_res["before"],
        after=after_summary,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def _default_dhcp_pool_for_subnet(subnet: ipaddress.IPv4Network, gw_ip: ipaddress.IPv4Address) -> dict[str, str]:
    hosts = list(subnet.hosts())
    usable = [ip for ip in hosts if ip != gw_ip]
    if not usable:
        raise OmadaError(f"subnet {subnet} has no usable host IPv4 addresses for DHCP pool")
    start_ip = usable[min(9, len(usable) - 1)] if len(usable) > 20 else usable[0]
    end_ip = usable[-1]
    if int(start_ip) > int(end_ip):
        start_ip = usable[0]
    return {"ipaddrStart": str(start_ip), "ipaddrEnd": str(end_ip)}


def create_lan_network(
    client: OmadaClient,
    name: str,
    vlan: int,
    purpose: str = "interface",
    gatewaySubnet: str | None = None,
    dhcpEnable: bool = True,
    pools: list[dict[str, str]] | None = None,
    leaseTime: int = 120,
    domain: str | None = None,
    isolation: bool = False,
    igmpSnoopEnable: bool = False,
    icmpPingEnable: bool = True,
    interfaceIds: list[str] | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create a LAN interface or pure VLAN network (``POST setting/lan/networks``)."""
    net_name = str(name or "").strip()
    if not net_name:
        raise OmadaError("LAN network name must be non-empty")
    vid = _validate_vlan_id(vlan)
    norm_purpose = str(purpose or "interface").strip().lower()
    if norm_purpose not in ("interface", "vlan"):
        raise OmadaError(f"invalid purpose {purpose!r}; expected 'interface' or 'vlan'")

    _require_confirm("create_lan_network", net_name, dryRun, confirm)

    site = _site(client)
    existing_col = _fetch_lan_collection(client, site)
    existing_ifaces = _fetch_lan_interfaces(client, site)
    for item in existing_col:
        if str(item.get("name", "")).strip().lower() == net_name.lower():
            raise OmadaError(f"LAN network {net_name!r} already exists")
        if item.get("vlan") == vid:
            raise OmadaError(f"VLAN {vid} is already used by network {item.get('name') or item.get('id')!r}")

    body: dict[str, Any] = {
        "name": net_name,
        "purpose": norm_purpose,
        "vlanType": 0,
        "vlan": vid,
        "igmpSnoopEnable": bool(igmpSnoopEnable),
    }

    if norm_purpose == "interface":
        if not gatewaySubnet or not str(gatewaySubnet).strip():
            raise OmadaError("gatewaySubnet (e.g. '192.168.40.1/24') is required when purpose='interface'")
        try:
            iface_cidr = ipaddress.IPv4Interface(str(gatewaySubnet).strip())
        except ValueError as exc:
            raise OmadaError(f"invalid gatewaySubnet {gatewaySubnet!r}: {exc}") from None
        if iface_cidr.network.prefixlen > 30:
            raise OmadaError(f"gatewaySubnet {gatewaySubnet!r} must be /30 or larger")
        if iface_cidr.ip in (iface_cidr.network.network_address, iface_cidr.network.broadcast_address):
            raise OmadaError(f"gateway IP {iface_cidr.ip} cannot be network or broadcast address")

        for existing in existing_ifaces:
            ex_sub, _ = _network_subnet_and_gw(existing)
            if ex_sub is not None and ex_sub.overlaps(iface_cidr.network):
                raise OmadaError(
                    f"subnet {iface_cidr.network} overlaps existing LAN network "
                    f"{existing.get('name') or existing.get('id')!r} ({ex_sub})",
                )
        devices = _fetch_devices(client, site)
        synth_net = {"name": net_name, "gatewaySubnet": str(iface_cidr)}
        _check_vlan_isolation_safety(client, synth_net, bool(isolation))

        resolved_if_ids: list[str]
        if interfaceIds is not None:
            resolved_if_ids = [str(x).strip() for x in interfaceIds if str(x).strip()]
        else:
            wan = _fetch_wan_networks(client, site)
            port_settings = ((wan.get("osgPortInfo") or {}).get("wanLanPortSettings") or [])
            resolved_if_ids = [
                str(p["portUuid"])
                for p in port_settings
                if isinstance(p, Mapping) and p.get("portUuid") and p.get("mode") == 1
            ]

        lease_val = int(leaseTime)
        if lease_val < 1:
            raise OmadaError("leaseTime must be at least 1 minute")

        dhcp_block: dict[str, Any] = {
            "enable": bool(dhcpEnable),
            "leasetime": lease_val,
            "dhcpns": "auto",
        }
        if dhcpEnable:
            raw_pools = pools if pools is not None else [_default_dhcp_pool_for_subnet(iface_cidr.network, iface_cidr.ip)]
            validated_pools = _check_dhcp_pools_safety(client, synth_net, raw_pools, devices)
            dhcp_block["ipRangePool"] = validated_pools

        body.update({
            "interfaceIds": resolved_if_ids,
            "gatewaySubnet": str(iface_cidr),
            "isolation": bool(isolation),
            "portal": False,
            "arpDetectionEnable": False,
            "dhcpL2RelayEnable": False,
            "dhcpSettings": dhcp_block,
            "lanNetworkIpv6Config": {"proto": "none", "enable": 0},
            "mtu": 1500,
            "icmpPingEnable": bool(icmpPingEnable),
        })
        if domain and str(domain).strip():
            body["domain"] = str(domain).strip()

    diff = {"network": {"before": None, "after": body}}
    warnings: list[str] = []
    if norm_purpose == "interface" and not body.get("interfaceIds"):
        warnings.append(
            "no gateway LAN ports (mode=1) resolved; sites without an adopted gateway LAN port "
            "may reject purpose='interface' with -33515 (use purpose='vlan' for switch-only VLANs)"
        )

    if dryRun:
        return _dry_run_result(
            tool_name="create_lan_network",
            target_id=net_name,
            before=None,
            after=body,
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    endpoint = f"sites/{site.site_id}/setting/lan/networks"

    def _read_back() -> dict[str, Any]:
        return {
            "collection": _fetch_lan_collection(client, site),
            "interfaces": _fetch_lan_interfaces(client, site),
        }

    def _find_created(state: Mapping[str, Any]) -> dict[str, Any] | None:
        for row in state.get("collection") or []:
            if str(row.get("name", "")).strip() == net_name and row.get("vlan") == vid:
                return dict(row)
        return None

    def _verify(_before: Any, after_state: Any) -> tuple[bool, str | None]:
        if not isinstance(after_state, Mapping):
            return False, "LAN read-back failed"
        found = _find_created(after_state)
        if found is None:
            return False, f"created LAN network {net_name!r} (vlan={vid}) missing on read-back"
        if norm_purpose == "interface":
            iface_match = next(
                (dict(i) for i in (after_state.get("interfaces") or []) if str(i.get("id")) == str(found.get("id"))),
                None,
            )
            if iface_match is None:
                return False, f"created interface network {net_name!r} missing from /setting/lan/networks/interface"
            if bool(iface_match.get("isolation")) != bool(isolation):
                return False, f"isolation mismatch on created network: expected {isolation!r}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        state_now = _read_back()
        ok, _ = _verify(None, state_now)
        return ok, None, None

    write_res = client.write(
        endpoint,
        method="POST",
        data=body,
        tool_name="create_lan_network",
        target=net_name,
        before=None,
        snapshot_payload={"existingNetworks": existing_col},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(body.keys()),
    )
    created = _find_created(write_res["after"]) or body
    rollback = {
        "tool": "delete_lan_network",
        "arguments": {"netId": str(created.get("id") or ""), "dryRun": True},
    } if created.get("id") else None
    return _committed_result(
        tool_name="create_lan_network",
        target_id=net_name,
        before=None,
        after=created,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def update_lan_network(
    client: OmadaClient,
    vlan: Any | None = None,
    netId: str | None = None,
    name: str | None = None,
    dhcpEnable: bool | None = None,
    leaseTime: int | None = None,
    dnsMode: str | None = None,
    dnsServers: list[str] | None = None,
    domain: str | None = None,
    igmpSnoopEnable: bool | None = None,
    icmpPingEnable: bool | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Update LAN/VLAN settings via ``/interface`` with full read-back verification."""
    if all(
        v is None
        for v in (name, dhcpEnable, leaseTime, dnsMode, dnsServers, domain, igmpSnoopEnable, icmpPingEnable)
    ):
        raise OmadaError("specify at least one field to update on the LAN network")

    site = _site(client)
    col_before, iface_before = _fetch_lan_pair(client, site, vlan=vlan, net_id=netId)
    target_id = str(iface_before["id"])
    _require_confirm("update_lan_network", target_id, dryRun, confirm)

    patch_body, defaulted_ipv6 = _ensure_lan_patch_body(iface_before)
    diff: dict[str, Any] = {}
    ignored_extra: list[str] = []

    if name is not None:
        clean_name = str(name).strip()
        if not clean_name:
            raise OmadaError("LAN network name must be non-empty")
        diff["name"] = {"before": iface_before.get("name"), "after": clean_name}
        patch_body["name"] = clean_name
        ignored_extra.extend(["name", "origName"])

    if igmpSnoopEnable is not None:
        diff["igmpSnoopEnable"] = {"before": iface_before.get("igmpSnoopEnable"), "after": bool(igmpSnoopEnable)}
        patch_body["igmpSnoopEnable"] = bool(igmpSnoopEnable)
        ignored_extra.append("igmpSnoopEnable")

    if icmpPingEnable is not None:
        diff["icmpPingEnable"] = {"before": iface_before.get("icmpPingEnable"), "after": bool(icmpPingEnable)}
        patch_body["icmpPingEnable"] = bool(icmpPingEnable)
        ignored_extra.append("icmpPingEnable")

    if domain is not None:
        clean_dom = str(domain).strip()
        if not clean_dom:
            raise OmadaError("domain cannot be empty string (-1001 validation error); omit or pass a valid hostname")
        diff["domain"] = {"before": iface_before.get("domain"), "after": clean_dom}
        patch_body["domain"] = clean_dom
        ignored_extra.append("domain")

    if any(v is not None for v in (dhcpEnable, leaseTime, dnsMode, dnsServers)):
        dhcp_after = copy.deepcopy(patch_body.get("dhcpSettings") or {})
        dhcp_before_snap = copy.deepcopy(iface_before.get("dhcpSettings") or {})
        if dhcpEnable is not None:
            dhcp_after["enable"] = bool(dhcpEnable)
        if leaseTime is not None:
            if int(leaseTime) < 1:
                raise OmadaError("leaseTime must be at least 1 minute")
            dhcp_after["leasetime"] = int(leaseTime)
        if dnsMode is not None:
            mode_norm = str(dnsMode).strip().lower()
            if mode_norm not in ("auto", "manual"):
                raise OmadaError("dnsMode must be 'auto' or 'manual'")
            dhcp_after["dhcpns"] = mode_norm
            if "dnsEnable" in dhcp_before_snap:
                dhcp_after["dnsEnable"] = mode_norm == "manual"
            if mode_norm == "auto" and dnsServers is None:
                for dk in ("priDns", "sndDns", "dns1", "dns2"):
                    dhcp_after.pop(dk, None)
        if dnsServers is not None:
            if not (1 <= len(dnsServers) <= 2):
                raise OmadaError("dnsServers must contain 1 or 2 IPv4 addresses")
            addrs = [str(_parse_ipv4(s, f"dnsServers[{i}]")) for i, s in enumerate(dnsServers)]
            dhcp_after["dhcpns"] = "manual"
            if "dnsEnable" in dhcp_before_snap:
                dhcp_after["dnsEnable"] = True
            dhcp_after["priDns"] = addrs[0]
            if "dns1" in dhcp_before_snap:
                dhcp_after["dns1"] = addrs[0]
            if len(addrs) > 1:
                dhcp_after["sndDns"] = addrs[1]
                if "dns2" in dhcp_before_snap:
                    dhcp_after["dns2"] = addrs[1]
            else:
                dhcp_after.pop("sndDns", None)
                dhcp_after.pop("dns2", None)
        patch_body["dhcpSettings"] = dhcp_after
        diff["dhcpSettings"] = {"before": dhcp_before_snap, "after": dhcp_after}
        ignored_extra.append("dhcpSettings")

    rollback_args: dict[str, Any] = {"netId": target_id, "dryRun": True}
    if name is not None:
        rollback_args["name"] = iface_before.get("name")
    if igmpSnoopEnable is not None:
        rollback_args["igmpSnoopEnable"] = iface_before.get("igmpSnoopEnable")
    if icmpPingEnable is not None:
        rollback_args["icmpPingEnable"] = iface_before.get("icmpPingEnable")
    if dhcpEnable is not None:
        rollback_args["dhcpEnable"] = bool((iface_before.get("dhcpSettings") or {}).get("enable"))
    if leaseTime is not None and (iface_before.get("dhcpSettings") or {}).get("leasetime") is not None:
        rollback_args["leaseTime"] = int(iface_before["dhcpSettings"]["leasetime"])
    rollback = {"tool": "update_lan_network", "arguments": rollback_args}

    if dryRun:
        return _dry_run_result(
            tool_name="update_lan_network",
            target_id=target_id,
            before=iface_before,
            after=patch_body,
            diff=diff,
            warnings=[],
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/setting/lan/networks/{target_id}"

    def _read_back() -> dict[str, Any]:
        col_after, iface_after = _fetch_lan_pair(client, site, net_id=target_id)
        return {"collection": col_after, "interface": iface_after}

    def _verify(_before: Any, after_pair: Any) -> tuple[bool, str | None]:
        if not isinstance(after_pair, Mapping):
            return False, "LAN read-back failed"
        ia = after_pair.get("interface") or {}
        for k, entry in diff.items():
            expected_val = entry["after"]
            if k == "dhcpSettings":
                da = ia.get("dhcpSettings") or {}
                for dk in ("enable", "leasetime", "leaseTime", "dhcpns", "dnsMode", "dnsEnable"):
                    if dk in expected_val and da.get(dk) != expected_val[dk]:
                        return False, f"dhcpSettings.{dk} expected {expected_val[dk]!r}, got {da.get(dk)!r}"
                if "priDns" in expected_val and (da.get("priDns") or da.get("dns1")) != expected_val["priDns"]:
                    return False, (
                        f"dhcpSettings.priDns expected {expected_val['priDns']!r}, "
                        f"got {(da.get('priDns') or da.get('dns1'))!r}"
                    )
                if "sndDns" in expected_val and (da.get("sndDns") or da.get("dns2")) != expected_val["sndDns"]:
                    return False, (
                        f"dhcpSettings.sndDns expected {expected_val['sndDns']!r}, "
                        f"got {(da.get('sndDns') or da.get('dns2'))!r}"
                    )
            elif ia.get(k) != expected_val:
                return False, f"{k} expected {expected_val!r}, got {ia.get(k)!r}"
        ignored = _lan_drift_ignore_keys(
            iface_before,
            ia,
            ignored_extra,
            defaulted_ipv6=defaulted_ipv6,
        )
        drifts = _diff_mappings(iface_before, ia, ignore_keys=ignored)
        if drifts:
            return False, "unexpected field drift after LAN PATCH: " + ", ".join(drifts)
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        fresh_pair = _read_back()
        ok, _ = _verify({"collection": col_before, "interface": iface_before}, fresh_pair)
        if ok:
            return True, None, None
        fresh_patch, _ = _ensure_lan_patch_body(fresh_pair["interface"])
        for k, entry in diff.items():
            fresh_patch[k] = copy.deepcopy(entry["after"])
        return False, fresh_patch, fresh_pair["interface"]

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=patch_body,
        tool_name="update_lan_network",
        target=target_id,
        before=iface_before,
        snapshot_payload={"collection": col_before, "interface": iface_before},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()),
    )
    return _committed_result(
        tool_name="update_lan_network",
        target_id=target_id,
        before=write_res["before"],
        after=write_res["after"]["interface"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


def delete_lan_network(
    client: OmadaClient,
    vlan: Any | None = None,
    netId: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a non-primary LAN/VLAN network (``DELETE setting/lan/networks/{id}``)."""
    site = _site(client)
    col = _fetch_lan_collection(client, site)
    target = _resolve_lan_network(col, vlan=vlan, net_id=netId)
    target_id = str(target["id"])

    if bool(target.get("primary")) or target.get("vlan") == 1:
        raise OmadaError(
            f"refusing to delete primary/default LAN network {target.get('name') or target_id!r}",
            hint="the primary Default network (VLAN 1) cannot be deleted",
        )
    subnet, _ = _network_subnet_and_gw(target)
    controller_ip, mgmt_nets = _management_endpoints(client)
    if subnet is not None:
        if controller_ip is not None and controller_ip in subnet:
            raise OmadaError(
                f"refusing to delete network {target.get('name') or target_id!r}: controller IP {controller_ip} is inside {subnet}",
            )
        for mgmt in mgmt_nets:
            if mgmt.overlaps(subnet):
                raise OmadaError(
                    f"refusing to delete network {target.get('name') or target_id!r}: overlaps management range {mgmt}",
                )

    warnings: list[str] = []
    reservations = _fetch_dhcp_reservations(client, site)
    linked_res = [r for r in reservations if str(r.get("netId")) == target_id]
    if linked_res:
        warnings.append(f"{len(linked_res)} static DHCP reservation(s) reference this network")

    return _delete_entity(
        client,
        tool_name="delete_lan_network",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/lan/networks/{target_id}",
        before=target,
        snapshot_payload=target,
        fetch_all=lambda: _fetch_lan_collection(client, site),
        match_fn=lambda row: str(row.get("id")) == target_id,
        rollback=None,
        warnings=warnings,
        dry_run=dryRun,
        confirm=confirm,
        label="lanNetwork",
    )

