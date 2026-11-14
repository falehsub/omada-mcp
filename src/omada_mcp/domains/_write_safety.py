"""Write domain module: _write_safety."""

from __future__ import annotations

import ipaddress
import urllib.parse
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError
from ._write_common import MAX_IP_GROUP_ENTRIES


def _parse_range_token(token: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    left, right = token.split("-", 1)
    start_s = left.strip()
    end_s = right.strip()
    try:
        start_ip = ipaddress.IPv4Address(start_s)
    except ValueError as exc:
        raise OmadaError(f"invalid IPv4 range start {start_s!r}: {exc}") from None

    if "." not in end_s:
        try:
            last_octet = int(end_s)
        except ValueError:
            raise OmadaError(f"invalid IPv4 range end {end_s!r} in {token!r}") from None
        if not 0 <= last_octet <= 255:
            raise OmadaError(f"invalid last octet {end_s!r} in {token!r}")
        prefix = ".".join(start_s.split(".")[:3])
        end_ip = ipaddress.IPv4Address(f"{prefix}.{last_octet}")
    else:
        try:
            end_ip = ipaddress.IPv4Address(end_s)
        except ValueError as exc:
            raise OmadaError(f"invalid IPv4 range end {end_s!r}: {exc}") from None

    if int(end_ip) < int(start_ip):
        raise OmadaError(f"IPv4 range end {end_ip} precedes start {start_ip}")
    return start_ip, end_ip


def _parse_ip_item(item: Any) -> list[ipaddress.IPv4Network]:
    if isinstance(item, Mapping):
        ip_raw = str(item.get("ip") or "").strip()
        mask_raw = item.get("mask", 32)
        if not ip_raw:
            raise OmadaError("IP entry object is missing 'ip'")
        try:
            mask = int(mask_raw)
        except (TypeError, ValueError):
            raise OmadaError(f"invalid CIDR mask {mask_raw!r}") from None
        try:
            return [ipaddress.IPv4Network(f"{ip_raw}/{mask}", strict=False)]
        except ValueError as exc:
            raise OmadaError(f"invalid IPv4 entry {ip_raw}/{mask}: {exc}") from None

    token = str(item or "").strip()
    if not token:
        raise OmadaError("empty IP/CIDR entry")
    if "-" in token:
        start_ip, end_ip = _parse_range_token(token)
        return list(ipaddress.summarize_address_range(start_ip, end_ip))
    try:
        return [ipaddress.IPv4Network(token, strict=False)]
    except ValueError as exc:
        raise OmadaError(f"invalid IPv4 address or CIDR {token!r}: {exc}") from None


def pack_ip_entries(
    cidrs: Sequence[Any] | None = None,
    ip_range: str | None = None,
) -> list[dict[str, Any]]:
    """Pack CIDRs, single IPs, or ranges into <=16 network-aligned Omada ``ipList`` items."""
    networks: list[ipaddress.IPv4Network] = []
    for entry in (cidrs or []):
        networks.extend(_parse_ip_item(entry))
    if ip_range is not None and str(ip_range).strip():
        for part in str(ip_range).split(","):
            part_s = part.strip()
            if part_s:
                networks.extend(_parse_ip_item(part_s))

    if not networks:
        raise OmadaError(
            "at least one IP, CIDR, or ipRange entry is required",
            hint="provide cidrs=[...] (e.g. ['192.168.20.180/30']) or ipRange='192.168.20.180-199'",
        )

    collapsed = list(ipaddress.collapse_addresses(networks))
    if len(collapsed) > MAX_IP_GROUP_ENTRIES:
        raise OmadaError(
            f"packed CIDR count ({len(collapsed)}) exceeds Omada's {MAX_IP_GROUP_ENTRIES}-entry "
            "IP group limit (-33726)",
            code=-33726,
            hint=(f"merge contiguous hosts/ranges or split across multiple IP groups of at most "
                  f"{MAX_IP_GROUP_ENTRIES} aligned CIDRs each"),
        )
    return [
        {"ip": str(net.network_address), "mask": int(net.prefixlen), "description": ""}
        for net in collapsed
    ]


def _ip_list_canonical(ip_list: Sequence[Mapping[str, Any]]) -> list[tuple[str, int]]:
    pairs: list[tuple[str, int]] = []
    for item in ip_list:
        ip_val = str(item.get("ip") or "").strip()
        mask_val = int(item.get("mask", 32))
        try:
            net = ipaddress.IPv4Network(f"{ip_val}/{mask_val}", strict=False)
            pairs.append((str(net.network_address), int(net.prefixlen)))
        except ValueError:
            pairs.append((ip_val, mask_val))
    pairs.sort()
    return pairs


def _group_ip_networks(group: Mapping[str, Any]) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for item in (group.get("ipList") or []):
        try:
            nets.append(ipaddress.IPv4Network(f"{item.get('ip')}/{item.get('mask', 32)}", strict=False))
        except ValueError:
            continue
    return nets


def _management_endpoints(client: OmadaClient) -> tuple[ipaddress.IPv4Address | None, list[ipaddress.IPv4Network]]:
    controller_ip: ipaddress.IPv4Address | None = None
    host = urllib.parse.urlsplit(client.config.base_url).hostname or ""
    try:
        controller_ip = ipaddress.IPv4Address(host)
    except ValueError:
        controller_ip = None

    mgmt_nets: list[ipaddress.IPv4Network] = []
    for raw in (getattr(client.config, "management_cidrs", ()) or ()):
        try:
            mgmt_nets.append(ipaddress.IPv4Network(raw, strict=False))
        except ValueError:
            continue
    return controller_ip, mgmt_nets


def _network_subnet_and_gw(network: Mapping[str, Any]) -> tuple[ipaddress.IPv4Network | None, ipaddress.IPv4Address | None]:
    raw = str(network.get("gatewaySubnet") or "").strip()
    if not raw:
        return None, None
    try:
        iface = ipaddress.IPv4Interface(raw)
        return iface.network, iface.ip
    except ValueError:
        return None, None


def _network_dhcp_ranges(network: Mapping[str, Any]) -> list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]:
    dhcp = network.get("dhcpSettings") or {}
    if not isinstance(dhcp, Mapping):
        return []
    pools = dhcp.get("ipRangePool") or []
    if not pools and dhcp.get("enable") and dhcp.get("ipaddrStart") and dhcp.get("ipaddrEnd"):
        pools = [{"ipaddrStart": dhcp.get("ipaddrStart"), "ipaddrEnd": dhcp.get("ipaddrEnd")}]
    ranges: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]] = []
    for pool in pools:
        if not isinstance(pool, Mapping):
            continue
        s_raw = pool.get("ipaddrStart")
        e_raw = pool.get("ipaddrEnd")
        if not s_raw or not e_raw:
            continue
        try:
            s_ip = ipaddress.IPv4Address(str(s_raw).strip())
            e_ip = ipaddress.IPv4Address(str(e_raw).strip())
        except ValueError:
            continue
        if e_ip >= s_ip:
            ranges.append((s_ip, e_ip))
    return ranges


def _check_vlan_isolation_safety(
    client: OmadaClient,
    network: Mapping[str, Any],
    isolation: bool,
) -> None:
    if not isolation:
        return
    subnet, _ = _network_subnet_and_gw(network)
    if subnet is None:
        return
    controller_ip, mgmt_nets = _management_endpoints(client)
    if controller_ip is not None and controller_ip in subnet:
        raise OmadaError(
            f"refusing to enable isolation on network {network.get('name') or network.get('id')}: "
            f"controller IP {controller_ip} is inside {subnet}",
            hint="do not isolate the management subnet hosting the Omada controller",
        )
    for mgmt in mgmt_nets:
        if mgmt.overlaps(subnet):
            raise OmadaError(
                f"refusing to enable isolation on network {network.get('name') or network.get('id')}: "
                f"management range {mgmt} overlaps {subnet}",
                hint="do not isolate a subnet containing configured OMADA_MANAGEMENT_CIDRS",
            )


def _check_dhcp_pools_safety(
    client: OmadaClient,
    network: Mapping[str, Any],
    pools: Sequence[Mapping[str, Any]],
    devices: Sequence[Mapping[str, Any]],
) -> list[dict[str, str]]:
    if not isinstance(pools, list) or not pools:
        raise OmadaError("pools must be a non-empty array of {ipaddrStart, ipaddrEnd} objects")
    subnet, gw_ip = _network_subnet_and_gw(network)
    if subnet is None:
        raise OmadaError(
            f"target network {network.get('name') or network.get('id')} has no valid IPv4 gatewaySubnet",
        )
    controller_ip, mgmt_nets = _management_endpoints(client)

    parsed: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]] = []
    for idx, entry in enumerate(pools):
        if not isinstance(entry, Mapping):
            raise OmadaError(f"pools[{idx}] must be an object with ipaddrStart and ipaddrEnd")
        s_raw = str(entry.get("ipaddrStart") or entry.get("start") or "").strip()
        e_raw = str(entry.get("ipaddrEnd") or entry.get("end") or "").strip()
        if not s_raw or not e_raw:
            raise OmadaError(f"pools[{idx}] must include both ipaddrStart and ipaddrEnd (or start/end)")
        try:
            s_ip = ipaddress.IPv4Address(s_raw)
            e_ip = ipaddress.IPv4Address(e_raw)
        except ValueError as exc:
            raise OmadaError(f"pools[{idx}] has invalid IPv4 address: {exc}") from None
        if e_ip < s_ip:
            raise OmadaError(f"pools[{idx}] ipaddrEnd ({e_ip}) precedes ipaddrStart ({s_ip})")
        if s_ip not in subnet or e_ip not in subnet:
            raise OmadaError(
                f"pools[{idx}] ({s_ip}-{e_ip}) falls outside subnet {subnet}",
            )
        if subnet.prefixlen < 31 and (s_ip == subnet.network_address or e_ip == subnet.broadcast_address):
            raise OmadaError(
                f"pools[{idx}] ({s_ip}-{e_ip}) includes the network or broadcast address of {subnet}",
            )
        if gw_ip is not None and s_ip <= gw_ip <= e_ip:
            raise OmadaError(
                f"pools[{idx}] ({s_ip}-{e_ip}) includes the gateway IP {gw_ip}",
            )
        if controller_ip is not None and s_ip <= controller_ip <= e_ip:
            raise OmadaError(
                f"refusing DHCP pool ({s_ip}-{e_ip}): includes controller IP {controller_ip}",
                hint="exclude the controller IP from dynamic DHCP pools to prevent address conflicts",
            )
        for mgmt in mgmt_nets:
            if any(s_ip <= ip <= e_ip for ip in (mgmt.network_address, mgmt.broadcast_address)):
                raise OmadaError(
                    f"refusing DHCP pool ({s_ip}-{e_ip}): overlaps management host/range {mgmt}",
                )
        for dev in devices:
            dev_ip_raw = str(dev.get("ip") or "").strip()
            if not dev_ip_raw:
                continue
            try:
                dev_ip = ipaddress.IPv4Address(dev_ip_raw)
            except ValueError:
                continue
            if s_ip <= dev_ip <= e_ip:
                raise OmadaError(
                    f"refusing DHCP pool ({s_ip}-{e_ip}): includes managed device "
                    f"{dev.get('name') or dev.get('mac')} IP {dev_ip}",
                    hint="carve managed device static IPs out of ipRangePool",
                )
        parsed.append((s_ip, e_ip))

    ordered = sorted(parsed, key=lambda pair: (int(pair[0]), int(pair[1])))
    for i in range(1, len(ordered)):
        if ordered[i][0] <= ordered[i - 1][1]:
            raise OmadaError(
                f"DHCP pools overlap: {ordered[i - 1][0]}-{ordered[i - 1][1]} and "
                f"{ordered[i][0]}-{ordered[i][1]}",
            )
    return [{"ipaddrStart": str(s), "ipaddrEnd": str(e)} for s, e in parsed]


def _check_fixed_ip_safety(
    client: OmadaClient,
    network: Mapping[str, Any],
    target_ip: ipaddress.IPv4Address,
    devices: Sequence[Mapping[str, Any]],
) -> None:
    subnet, gw_ip = _network_subnet_and_gw(network)
    if subnet is None:
        raise OmadaError(
            f"network {network.get('name') or network.get('id')} has no valid IPv4 gatewaySubnet",
        )
    if target_ip not in subnet:
        raise OmadaError(
            f"target IP {target_ip} is outside network {network.get('name') or network.get('id')} "
            f"subnet {subnet}",
        )
    if subnet.prefixlen < 31 and target_ip in (subnet.network_address, subnet.broadcast_address):
        raise OmadaError(
            f"target IP {target_ip} cannot be the network or broadcast address of {subnet}",
        )
    if gw_ip is not None and target_ip == gw_ip:
        raise OmadaError(f"target IP {target_ip} conflicts with the VLAN gateway IP")

    for s_ip, e_ip in _network_dhcp_ranges(network):
        if s_ip <= target_ip <= e_ip:
            raise OmadaError(
                f"target IP {target_ip} lies inside dynamic DHCP pool {s_ip}-{e_ip}",
                hint=("choose a static IP outside ipRangePool, or carve a static block out of "
                      "ipRangePool first with set_vlan_dhcp_pools"),
            )

    controller_ip, _ = _management_endpoints(client)
    if controller_ip is not None and target_ip == controller_ip:
        raise OmadaError(
            f"refusing fixed IP {target_ip}: matches the Omada controller IP",
        )
    for dev in devices:
        dev_ip_raw = str(dev.get("ip") or "").strip()
        if not dev_ip_raw:
            continue
        try:
            if ipaddress.IPv4Address(dev_ip_raw) == target_ip:
                raise OmadaError(
                    f"refusing fixed IP {target_ip}: already used by managed device "
                    f"{dev.get('name') or dev.get('mac')}",
                )
        except ValueError:
            continue


def _endpoint_covers_ip(
    target_type: int,
    target_ids: Sequence[str],
    networks_by_id: Mapping[str, Mapping[str, Any]],
    groups_by_id: Mapping[str, Mapping[str, Any]],
    probe_net: ipaddress.IPv4Network,
) -> tuple[bool, bool]:
    """Return ``(covers_probe, is_any_catchall)`` for an ACL source/destination."""
    covers = False
    is_any = False
    for tid in target_ids:
        if target_type == 0:
            net_obj = networks_by_id.get(tid)
            if net_obj:
                subnet, _ = _network_subnet_and_gw(net_obj)
                if subnet is not None and subnet.overlaps(probe_net):
                    covers = True
        elif target_type == 1:
            grp = groups_by_id.get(tid)
            if grp:
                for gnet in _group_ip_networks(grp):
                    if gnet.prefixlen == 0:
                        is_any = True
                    if gnet.overlaps(probe_net):
                        covers = True
    return covers, is_any


def _group_id(group: Mapping[str, Any]) -> str:
    """Return a group ID across real Omada (``groupId``) and legacy/mock (``id``) shapes."""
    return str(group.get("groupId") or group.get("id") or "").strip()


def _normalize_group_output(group_obj: Mapping[str, Any]) -> dict[str, Any]:
    """Ensure tool output exposes both ``groupId`` and ``id`` without altering snapshots."""
    out = dict(group_obj)
    gid = _group_id(out)
    if gid:
        out.setdefault("groupId", gid)
        out.setdefault("id", gid)
    return out


def _check_acl_safety(
    client: OmadaClient,
    *,
    policy: int,
    status: bool,
    source_type: int,
    source_ids: Sequence[str],
    dest_type: int,
    dest_ids: Sequence[str],
    direction: Mapping[str, Any],
    networks: Sequence[Mapping[str, Any]],
    groups: Sequence[Mapping[str, Any]],
) -> None:
    if policy != 0 or not status:
        return
    controller_ip, mgmt_nets = _management_endpoints(client)
    protected: list[tuple[str, ipaddress.IPv4Network]] = []
    if controller_ip is not None:
        protected.append((f"controller {controller_ip}", ipaddress.IPv4Network(f"{controller_ip}/32")))
    for mgmt in mgmt_nets:
        protected.append((f"management {mgmt}", mgmt))
    if not protected:
        return

    networks_by_id = {str(n.get("id")): n for n in networks if n.get("id")}
    groups_by_id = {_group_id(g): g for g in groups if _group_id(g)}
    lan_to_lan = bool(direction.get("lanToLan"))
    lan_to_wan = bool(direction.get("lanToWan"))

    for label, probe in protected:
        src_cov, src_any = _endpoint_covers_ip(source_type, source_ids, networks_by_id, groups_by_id, probe)
        dst_cov, dst_any = _endpoint_covers_ip(dest_type, dest_ids, networks_by_id, groups_by_id, probe)
        if src_any and (dst_cov or lan_to_wan):
            raise OmadaError(
                f"refusing deny ACL rule: wildcard source would block {label}",
                hint="narrow the ACL source to a specific isolated VLAN or IP group",
            )
        if src_cov and lan_to_lan and (dst_cov or dst_any):
            raise OmadaError(
                f"refusing deny ACL rule: would block LAN-to-LAN reachability involving {label}",
                hint="do not create or enable a deny rule whose source and destination both match "
                     "controller/management subnets",
            )
        if src_cov and lan_to_wan and dst_any:
            raise OmadaError(
                f"refusing deny ACL rule: would block {label} outbound LAN-to-WAN traffic",
                hint="do not include the controller or management host in a LAN->WAN deny source",
            )

