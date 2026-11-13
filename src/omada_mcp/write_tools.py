"""Write-support helpers and handlers for omada-mcp (Web API v2).

Every write path enforces the safety contract in ``docs/write-support.md``:

1. Fail-closed gate: ``OMADA_READ_ONLY=true`` or missing from ``OMADA_WRITE_TOOLS``
   refuses before reaching the transport.
2. Two-phase apply: ``dryRun`` defaults to ``True``; ``dryRun=False`` requires
   ``confirm == "<tool>:<target-id>"``.
3. Anti-stranding: refuses operations that would isolate, conflict with, or block
   the controller or management hosts.
4. Snapshot before, re-read after, whole-object integrity checks, JSONL audit log.
"""

from __future__ import annotations

import copy
import ipaddress
import urllib.parse
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .client import OmadaClient, OmadaError, SiteInfo

__all__ = [
    "CLIENT_VOLATILE_KEYS",
    "WRITE_ENVELOPE_SCHEMA",
    "create_gateway_acl",
    "create_ip_group",
    "pack_ip_entries",
    "release_client_fixed_ip",
    "replace_ip_group",
    "set_acl_rule_status",
    "set_client_fixed_ip",
    "set_vlan_dhcp_pools",
    "set_vlan_isolation",
]

MAX_IP_GROUP_ENTRIES = 16

#: Volatile runtime keys stripped before PATCHing ``sites/{siteId}/clients/{MAC}``.
CLIENT_VOLATILE_KEYS = frozenset({
    "trafficDown",
    "trafficUp",
    "downPacket",
    "upPacket",
    "uptime",
    "lastSeen",
    "activity",
    "uploadActivity",
    "rxRate",
    "txRate",
    "rssi",
    "snr",
    "signalLevel",
    "signalRank",
    "dpiStat",
    "authInfo",
    "channel",
    "active",
    "rateLimit",
    "authStatus",
})

WRITE_ENVELOPE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "applied": {"type": "boolean"},
        "dryRun": {"type": "boolean"},
        "verified": {"type": "boolean"},
        "target": {"type": "string"},
        "confirmToken": {"type": "string"},
        "before": {},
        "after": {},
        "diff": {"type": "object"},
        "snapshot": {"type": ["string", "null"]},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "rollback": {"type": ["object", "null"]},
        "steps": {"type": "array", "items": {"type": "object"}},
    },
    "required": [
        "applied",
        "dryRun",
        "verified",
        "target",
        "before",
        "after",
        "diff",
        "snapshot",
        "warnings",
        "rollback",
    ],
}

_SOURCE_DEST_TYPES: Dict[str, int] = {
    "0": 0,
    "network": 0,
    "lan": 0,
    "1": 1,
    "ip_group": 1,
    "ipgroup": 1,
    "group": 1,
    "2": 2,
    "port_group": 2,
    "portgroup": 2,
}

_ACL_DISPATCH_NOTES = (
    "aclDisable on the controller list envelope is not a reliable enforcement indicator; "
    "verify enforcement behaviourally on affected clients after re-association"
)


# -- generic helpers ---------------------------------------------------------

def _normalize_mac(value: str) -> str:
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).lower()
    if len(cleaned) == 12 and all(ch in "0123456789abcdef" for ch in cleaned):
        return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    return str(value or "").strip().lower()


def _site(client: OmadaClient) -> SiteInfo:
    client.authenticate()
    site = client.site
    if site is None:  # pragma: no cover - authenticate() guarantees a site
        raise OmadaError("site resolution failed", hint="run `omada-mcp --doctor`")
    return site


def _unwrap_rows(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        rows = payload.get("data")
        return list(rows) if isinstance(rows, list) else []
    if isinstance(payload, list):
        return list(payload)
    return []


def _require_confirm(tool_name: str, target_id: str, dry_run: bool, confirm: Optional[str]) -> str:
    expected = f"{tool_name}:{target_id}"
    if dry_run:
        return expected
    supplied = str(confirm or "").strip()
    if supplied != expected:
        raise OmadaError(
            f"confirmation mismatch for {tool_name}: dryRun=false requires confirm='{tool_name}:<target-id>'",
            hint="run this tool with dryRun=true first to inspect the diff and obtain confirmToken",
        )
    return expected


def _dry_run_result(
    *,
    tool_name: str,
    target_id: str,
    before: Any,
    after: Any,
    diff: Dict[str, Any],
    warnings: List[str],
    rollback: Optional[Dict[str, Any]],
    steps: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "applied": False,
        "dryRun": True,
        "verified": False,
        "target": target_id,
        "confirmToken": f"{tool_name}:{target_id}",
        "before": before,
        "after": after,
        "diff": diff,
        "snapshot": None,
        "warnings": warnings,
        "rollback": rollback,
    }
    if steps is not None:
        out["steps"] = steps
    return out


def _committed_result(
    *,
    tool_name: str,
    target_id: str,
    before: Any,
    after: Any,
    diff: Dict[str, Any],
    snapshot: Optional[str],
    warnings: List[str],
    rollback: Optional[Dict[str, Any]],
    steps: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "applied": True,
        "dryRun": False,
        "verified": True,
        "target": target_id,
        "confirmToken": f"{tool_name}:{target_id}",
        "before": before,
        "after": after,
        "diff": diff,
        "snapshot": snapshot,
        "warnings": warnings,
        "rollback": rollback,
    }
    if steps is not None:
        out["steps"] = steps
    return out


# -- CIDR packing ------------------------------------------------------------

def _parse_range_token(token: str) -> Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
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


def _parse_ip_item(item: Any) -> List[ipaddress.IPv4Network]:
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
    cidrs: Optional[Sequence[Any]] = None,
    ip_range: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Pack CIDRs, single IPs, or ranges into <=16 network-aligned Omada ``ipList`` items."""
    networks: List[ipaddress.IPv4Network] = []
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


def _ip_list_canonical(ip_list: Sequence[Mapping[str, Any]]) -> List[Tuple[str, int]]:
    pairs: List[Tuple[str, int]] = []
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


def _group_ip_networks(group: Mapping[str, Any]) -> List[ipaddress.IPv4Network]:
    nets: List[ipaddress.IPv4Network] = []
    for item in (group.get("ipList") or []):
        try:
            nets.append(ipaddress.IPv4Network(f"{item.get('ip')}/{item.get('mask', 32)}", strict=False))
        except ValueError:
            continue
    return nets


# -- anti-stranding & network helpers ----------------------------------------

def _management_endpoints(client: OmadaClient) -> Tuple[Optional[ipaddress.IPv4Address], List[ipaddress.IPv4Network]]:
    controller_ip: Optional[ipaddress.IPv4Address] = None
    host = urllib.parse.urlsplit(client.config.base_url).hostname or ""
    try:
        controller_ip = ipaddress.IPv4Address(host)
    except ValueError:
        controller_ip = None

    mgmt_nets: List[ipaddress.IPv4Network] = []
    for raw in (getattr(client.config, "management_cidrs", ()) or ()):
        try:
            mgmt_nets.append(ipaddress.IPv4Network(raw, strict=False))
        except ValueError:
            continue
    return controller_ip, mgmt_nets


def _network_subnet_and_gw(network: Mapping[str, Any]) -> Tuple[Optional[ipaddress.IPv4Network], Optional[ipaddress.IPv4Address]]:
    raw = str(network.get("gatewaySubnet") or "").strip()
    if not raw:
        return None, None
    try:
        iface = ipaddress.IPv4Interface(raw)
        return iface.network, iface.ip
    except ValueError:
        return None, None


def _network_dhcp_ranges(network: Mapping[str, Any]) -> List[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]:
    dhcp = network.get("dhcpSettings") or {}
    if not isinstance(dhcp, Mapping):
        return []
    pools = dhcp.get("ipRangePool") or []
    if not pools and dhcp.get("enable") and dhcp.get("ipaddrStart") and dhcp.get("ipaddrEnd"):
        pools = [{"ipaddrStart": dhcp.get("ipaddrStart"), "ipaddrEnd": dhcp.get("ipaddrEnd")}]
    ranges: List[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]] = []
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
) -> List[Dict[str, str]]:
    if not isinstance(pools, list) or not pools:
        raise OmadaError("pools must be a non-empty array of {ipaddrStart, ipaddrEnd} objects")
    subnet, gw_ip = _network_subnet_and_gw(network)
    if subnet is None:
        raise OmadaError(
            f"target network {network.get('name') or network.get('id')} has no valid IPv4 gatewaySubnet",
        )
    controller_ip, mgmt_nets = _management_endpoints(client)

    parsed: List[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]] = []
    for idx, entry in enumerate(pools):
        if not isinstance(entry, Mapping):
            raise OmadaError(f"pools[{idx}] must be an object with ipaddrStart and ipaddrEnd")
        s_raw = str(entry.get("ipaddrStart") or "").strip()
        e_raw = str(entry.get("ipaddrEnd") or "").strip()
        if not s_raw or not e_raw:
            raise OmadaError(f"pools[{idx}] must include both ipaddrStart and ipaddrEnd")
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
) -> Tuple[bool, bool]:
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


def _normalize_group_output(group_obj: Mapping[str, Any]) -> Dict[str, Any]:
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
    protected: List[Tuple[str, ipaddress.IPv4Network]] = []
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


# -- collection lookup helpers -----------------------------------------------

def _fetch_devices(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    res = client.api(f"sites/{site.site_id}/devices?currentPage=1&currentPageSize=50")
    if res.get("errorCode") != 0:
        raise OmadaError(
            f"devices query failed: {res.get('msg', 'unknown')}",
            code=res.get("errorCode"),
            endpoint="sites/{id}/devices",
        )
    return _unwrap_rows(res.get("result"))


def _fetch_insight_clients(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []
    seen = set()
    for page in range(1, 21):
        payload = client.api(
            f"sites/{site.site_id}/insight/clients?currentPage={page}&currentPageSize=100"
        )
        if payload.get("errorCode") != 0:
            raise OmadaError(
                f"client query failed: {payload.get('msg', 'unknown')}",
                code=payload.get("errorCode"),
                endpoint="sites/{id}/insight/clients",
            )
        result = payload.get("result") or {}
        rows = _unwrap_rows(result)
        if not rows:
            break
        for row in rows:
            mac = _normalize_mac(row.get("mac", ""))
            if mac and mac in seen:
                continue
            if mac:
                seen.add(mac)
            collected.append(row)
        total = int(result.get("totalRows") or 0) if isinstance(result, Mapping) else len(collected)
        if len(collected) >= total:
            break
    return collected


def _fetch_lan_collection(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    payload = client.api_result(
        f"sites/{site.site_id}/setting/lan/networks?currentPage=1&currentPageSize=50"
    )
    return _unwrap_rows(payload)


def _fetch_lan_interfaces(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    payload = client.api_result(f"sites/{site.site_id}/setting/lan/networks/interface")
    return _unwrap_rows(payload)


def _fetch_groups(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    payload = client.api_result(f"sites/{site.site_id}/setting/profiles/groups")
    return _unwrap_rows(payload)


def _fetch_acls(client: OmadaClient, site: SiteInfo) -> Tuple[Optional[bool], List[Dict[str, Any]]]:
    payload = client.api_result(
        f"sites/{site.site_id}/setting/firewall/acls?type=0&currentPage=1&currentPageSize=100"
    )
    if isinstance(payload, Mapping):
        acl_disable = payload.get("aclDisable")
        return (bool(acl_disable) if acl_disable is not None else None), _unwrap_rows(payload)
    return None, _unwrap_rows(payload)


def _resolve_lan_network(
    networks: Sequence[Mapping[str, Any]],
    *,
    vlan: Optional[Any] = None,
    net_id: Optional[str] = None,
    target_ip: Optional[ipaddress.IPv4Address] = None,
) -> Dict[str, Any]:
    by_id = None
    by_vlan = None
    if net_id is not None and str(net_id).strip():
        needle_id = str(net_id).strip().lower()
        for net in networks:
            if str(net.get("id", "")).lower() == needle_id:
                by_id = dict(net)
                break
        if by_id is None:
            raise OmadaError(f"no LAN network matches netId={net_id!r}")

    if vlan is not None and str(vlan).strip():
        vlan_text = str(vlan).strip()
        matches: List[Dict[str, Any]] = []
        for net in networks:
            if str(net.get("vlan", "")) == vlan_text or \
                    str(net.get("name", "")).strip().lower() == vlan_text.lower() or \
                    str(net.get("id", "")).lower() == vlan_text.lower():
                matches.append(dict(net))
        if not matches:
            raise OmadaError(f"no LAN network matches vlan={vlan!r}")
        if len(matches) > 1:
            raise OmadaError(f"vlan={vlan!r} matched multiple networks; specify netId explicitly")
        by_vlan = matches[0]

    if by_id is not None and by_vlan is not None:
        if by_id.get("id") != by_vlan.get("id"):
            raise OmadaError(
                f"conflicting netId={net_id!r} and vlan={vlan!r} refer to different networks",
            )
        return by_id
    if by_id is not None:
        return by_id
    if by_vlan is not None:
        return by_vlan

    if target_ip is not None:
        matched: List[Dict[str, Any]] = []
        for net in networks:
            subnet, _ = _network_subnet_and_gw(net)
            if subnet is not None and target_ip in subnet:
                matched.append(dict(net))
        if len(matched) == 1:
            return matched[0]
        if len(matched) > 1:
            raise OmadaError(
                f"IP {target_ip} matches multiple LAN subnets; pass vlan or netId explicitly",
            )
        raise OmadaError(
            f"IP {target_ip} does not fall inside any configured LAN network subnet",
        )

    raise OmadaError("either netId or vlan must be provided")


def _strip_client_volatiles(client_obj: Mapping[str, Any]) -> Dict[str, Any]:
    return {k: copy.deepcopy(v) for k, v in client_obj.items() if k not in CLIENT_VOLATILE_KEYS}


def _ensure_lan_patch_body(iface_obj: Mapping[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """Return a deep copy with ``lanNetworkIpv6Config.proto`` and ``enable`` guaranteed non-null."""
    body = copy.deepcopy(dict(iface_obj))
    ipv6 = body.get("lanNetworkIpv6Config")
    defaulted_ipv6 = False
    if not isinstance(ipv6, dict):
        body["lanNetworkIpv6Config"] = {"proto": "none", "enable": 0}
        defaulted_ipv6 = True
    else:
        if ipv6.get("proto") in (None, ""):
            ipv6["proto"] = "none"
            defaulted_ipv6 = True
        if ipv6.get("enable") is None:
            proto_val = str(ipv6.get("proto") or "none").strip().lower()
            ipv6["enable"] = 0 if proto_val == "none" else 1
            defaulted_ipv6 = True
    return body, defaulted_ipv6


def _lan_drift_ignore_keys(
    iface_before: Mapping[str, Any],
    iface_after: Mapping[str, Any],
    base_keys: Sequence[str],
    *,
    defaulted_ipv6: bool,
) -> List[str]:
    """Ignore expected intent keys plus benign defaults populated by Omada on LAN PATCH."""
    ignored = list(base_keys)
    if defaulted_ipv6:
        ignored.append("lanNetworkIpv6Config")
    if "qosQueueEnable" not in iface_before and iface_after.get("qosQueueEnable") is False:
        ignored.append("qosQueueEnable")
    return ignored


def _diff_mappings(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    ignore_keys: Sequence[str] = (),
    prefix: str = "",
) -> List[str]:
    """Return sorted dotted paths where ``before`` and ``after`` differ unexpectedly."""
    ignored = set(ignore_keys)
    drifts: List[str] = []
    for key in sorted(set(before.keys()) | set(after.keys())):
        dotted = f"{prefix}.{key}" if prefix else str(key)
        if dotted in ignored:
            continue
        if key not in before or key not in after:
            drifts.append(dotted)
            continue
        bv = before[key]
        av = after[key]
        if isinstance(bv, Mapping) and isinstance(av, Mapping):
            drifts.extend(_diff_mappings(bv, av, ignore_keys=ignored, prefix=dotted))
        elif bv != av:
            drifts.append(dotted)
    return drifts


# -- 1 & 2: Client fixed IP --------------------------------------------------

def set_client_fixed_ip(
    client: OmadaClient,
    mac: str,
    ip: str,
    vlan: Optional[Any] = None,
    netId: Optional[str] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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

    diff = {"ipSetting": {"before": before, "after": desired_ip_setting}}
    warnings = ["effective at next DHCP lease renewal; current client IP does not change immediately"]
    if before.get("useFixedAddr") and before.get("ip") and before.get("netId"):
        rollback: Dict[str, Any] = {
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

    def _read_back() -> Any:
        return client.api_result(endpoint)

    def _verify(_before: Any, after_obj: Any) -> Tuple[bool, Optional[str]]:
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

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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


def release_client_fixed_ip(
    client: OmadaClient,
    mac: str,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Release a client's fixed IP reservation (``useFixedAddr: false``)."""
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
    warnings = ["effective at next DHCP lease renewal"]
    rollback: Optional[Dict[str, Any]] = None
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

    def _verify(_before: Any, after_obj: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_obj, Mapping):
            return False, "clients/{MAC} read-back did not return an object"
        ip_cfg = after_obj.get("ipSetting") or {}
        if bool(ip_cfg.get("useFixedAddr")):
            return False, "ipSetting.useFixedAddr remained true after release"
        return True, None

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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


# -- 3 & 4: VLAN / LAN networks (two-endpoint read-modify-write) -------------

def _fetch_lan_pair(
    client: OmadaClient,
    site: SiteInfo,
    *,
    vlan: Optional[Any] = None,
    net_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    collection = _fetch_lan_collection(client, site)
    interfaces = _fetch_lan_interfaces(client, site)
    col_obj = _resolve_lan_network(collection, vlan=vlan, net_id=net_id)
    resolved_id = str(col_obj["id"])
    iface_obj = next((dict(item) for item in interfaces if str(item.get("id")) == resolved_id), None)
    if iface_obj is None:
        raise OmadaError(
            f"network {resolved_id} was present in setting/lan/networks but missing from "
            "setting/lan/networks/interface",
            endpoint=f"sites/{site.site_id}/setting/lan/networks/interface",
        )
    return col_obj, iface_obj


def set_vlan_isolation(
    client: OmadaClient,
    isolation: bool,
    vlan: Optional[Any] = None,
    netId: Optional[str] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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
    warnings: List[str] = []
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

    def _read_back() -> Dict[str, Any]:
        col_after, iface_after = _fetch_lan_pair(client, site, net_id=target_id)
        return {"collection": col_after, "interface": iface_after}

    def _verify(_before: Any, after_pair: Any) -> Tuple[bool, Optional[str]]:
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

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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
    pools: List[Dict[str, Any]],
    vlan: Optional[Any] = None,
    netId: Optional[str] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Update ``dhcpSettings.ipRangePool`` on a LAN/VLAN with full-object PATCH."""
    site = _site(client)
    col_before, iface_before = _fetch_lan_pair(client, site, vlan=vlan, net_id=netId)
    target_id = str(iface_before["id"])
    _require_confirm("set_vlan_dhcp_pools", target_id, dryRun, confirm)

    devices = _fetch_devices(client, site)
    normalized_pools = _check_dhcp_pools_safety(client, iface_before, pools, devices)
    outer_start = str(min((ipaddress.IPv4Address(p["ipaddrStart"]) for p in normalized_pools)))
    outer_end = str(max((ipaddress.IPv4Address(p["ipaddrEnd"]) for p in normalized_pools)))

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
    warnings: List[str] = []
    if not dhcp_before.get("enable"):
        warnings.append("dhcpSettings.enable is currently false on this network; leases will not be served until enabled")
    rollback: Optional[Dict[str, Any]] = None
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

    def _read_back() -> Dict[str, Any]:
        col_after, iface_after = _fetch_lan_pair(client, site, net_id=target_id)
        return {"collection": col_after, "interface": iface_after}

    def _verify(_before: Any, after_pair: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_pair, Mapping):
            return False, "read-back did not return collection/interface pair"
        col_after = after_pair["collection"]
        iface_after = after_pair["interface"]
        after_dhcp = iface_after.get("dhcpSettings") or {}
        if after_dhcp.get("ipRangePool") != normalized_pools:
            return False, (f"interface dhcpSettings.ipRangePool expected {normalized_pools!r}, "
                           f"got {after_dhcp.get('ipRangePool')!r}")
        col_dhcp = col_after.get("dhcpSettings") or {}
        if isinstance(col_dhcp, Mapping) and "ipRangePool" in col_dhcp:
            if col_dhcp.get("ipRangePool") != normalized_pools:
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

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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


# -- 5 & 6: IP groups --------------------------------------------------------

def _find_ip_group(groups: Sequence[Mapping[str, Any]], needle: str) -> Dict[str, Any]:
    ip_groups = [dict(g) for g in groups if int(g.get("type", 0)) == 0]
    key = str(needle or "").strip()
    by_id = [g for g in ip_groups if _group_id(g) == key]
    if by_id:
        return by_id[0]
    by_name = [g for g in ip_groups if str(g.get("name", "")).strip().lower() == key.lower()]
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        ids = ", ".join(_group_id(g) for g in by_name)
        raise OmadaError(f"group {needle!r} matched multiple IP groups ({ids}); specify id")
    raise OmadaError(f"no IPv4 IP group (type=0) matches {needle!r}")


def create_ip_group(
    client: OmadaClient,
    name: str,
    cidrs: Optional[List[Any]] = None,
    ipRange: Optional[str] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new IPv4 IP profile group (packs CIDRs and enforces <=16 entries)."""
    group_name = str(name or "").strip()
    if not group_name:
        raise OmadaError("group name must be non-empty")

    ip_list = pack_ip_entries(cidrs=cidrs, ip_range=ipRange)
    _require_confirm("create_ip_group", group_name, dryRun, confirm)

    site = _site(client)
    groups_before = _fetch_groups(client, site)
    existing = next(
        (g for g in groups_before if int(g.get("type", 0)) == 0 and str(g.get("name")) == group_name),
        None,
    )
    if existing is not None:
        raise OmadaError(
            f"IP group {group_name!r} already exists (id={_group_id(existing)})",
            hint="use replace_ip_group to update an existing group's entries",
        )

    body = {
        "name": group_name,
        "type": 0,
        "resource": 0,
        "ipList": ip_list,
    }
    diff = {"group": {"before": None, "after": body}}
    warnings: List[str] = []

    if dryRun:
        return _dry_run_result(
            tool_name="create_ip_group",
            target_id=group_name,
            before=None,
            after=body,
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    endpoint = f"sites/{site.site_id}/setting/profiles/groups"
    expected_pairs = _ip_list_canonical(ip_list)

    def _read_back() -> List[Dict[str, Any]]:
        return [g for g in _fetch_groups(client, site) if int(g.get("type", 0)) == 0]

    def _verify(_before: Any, after_groups: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_groups, list):
            return False, "groups read-back did not return a list"
        created = next((g for g in after_groups if str(g.get("name")) == group_name), None)
        if created is None:
            return False, f"created group {group_name!r} not found on read-back"
        if _ip_list_canonical(created.get("ipList") or []) != expected_pairs:
            return False, "created group ipList does not match packed entries"
        return True, None

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
        groups_now = _read_back()
        ok, _ = _verify(None, groups_now)
        return ok, None, None

    write_res = client.write(
        endpoint,
        method="POST",
        data=body,
        tool_name="create_ip_group",
        target=group_name,
        before=None,
        snapshot_payload={"existingIpGroups": [g for g in groups_before if int(g.get("type", 0)) == 0]},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["name", "type", "ipList"],
    )
    raw_res = write_res.get("result")
    fallback_id = (raw_res.get("groupId") or raw_res.get("id")) if isinstance(raw_res, Mapping) else raw_res
    created_obj = _normalize_group_output(
        next(
            (g for g in write_res["after"] if str(g.get("name")) == group_name),
            {"groupId": fallback_id, **body},
        )
    )
    return _committed_result(
        tool_name="create_ip_group",
        target_id=group_name,
        before=None,
        after=created_obj,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )


def _format_ip_list_as_cidrs(ip_list: Sequence[Mapping[str, Any]]) -> List[str]:
    return [f"{item.get('ip')}/{item.get('mask', 32)}" for item in ip_list]


def _swap_rule_group_id(rule: Mapping[str, Any], old_id: str, new_id: str) -> Dict[str, Any]:
    updated = copy.deepcopy(dict(rule))
    if int(updated.get("sourceType", -1)) == 1 and isinstance(updated.get("sourceIds"), list):
        updated["sourceIds"] = [new_id if str(x) == old_id else x for x in updated["sourceIds"]]
    if int(updated.get("destinationType", -1)) == 1 and isinstance(updated.get("destinationIds"), list):
        updated["destinationIds"] = [new_id if str(x) == old_id else x for x in updated["destinationIds"]]
    return updated


def replace_ip_group(
    client: OmadaClient,
    group: str,
    cidrs: Optional[List[Any]] = None,
    ipRange: Optional[str] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Replace an IPv4 IP group's entries via delete+create (or 6-step tmp-group swap if ACL-referenced)."""
    new_ip_list = pack_ip_entries(cidrs=cidrs, ip_range=ipRange)
    site = _site(client)
    groups_before = _fetch_groups(client, site)
    target_group = _find_ip_group(groups_before, group)

    if int(target_group.get("resource", 0) or 0) != 0 or str(target_group.get("name")) == "IPGroup_Any":
        raise OmadaError(
            f"refusing to replace built-in/protected group {target_group.get('name')!r}",
        )

    old_id = _group_id(target_group)
    group_name = str(target_group["name"])
    group_type = int(target_group.get("type", 0))
    _require_confirm("replace_ip_group", old_id, dryRun, confirm)

    _, acls_before = _fetch_acls(client, site)
    networks = _fetch_lan_collection(client, site)
    ref_rules = [
        dict(rule)
        for rule in acls_before
        if (int(rule.get("sourceType", -1)) == 1 and old_id in [str(x) for x in (rule.get("sourceIds") or [])])
        or (int(rule.get("destinationType", -1)) == 1 and old_id in [str(x) for x in (rule.get("destinationIds") or [])])
    ]

    # Check anti-stranding against any active deny ACL rules referencing this group.
    if ref_rules:
        simulated_groups = [
            ({**g, "ipList": new_ip_list} if _group_id(g) == old_id else g)
            for g in groups_before
        ]
        for rule in ref_rules:
            _check_acl_safety(
                client,
                policy=int(rule.get("policy", 1)),
                status=bool(rule.get("status")),
                source_type=int(rule.get("sourceType", -1)),
                source_ids=[str(x) for x in (rule.get("sourceIds") or [])],
                dest_type=int(rule.get("destinationType", -1)),
                dest_ids=[str(x) for x in (rule.get("destinationIds") or [])],
                direction=rule.get("direction") or {},
                networks=networks,
                groups=simulated_groups,
            )

    old_ip_list = copy.deepcopy(target_group.get("ipList") or [])
    diff = {"ipList": {"before": old_ip_list, "after": new_ip_list}}
    warnings = [
        "IP groups do not support PATCH; replacing deletes and recreates the group (non-atomic, receives a new groupId)"
    ]
    if ref_rules:
        warnings.append(
            f"group is referenced by {len(ref_rules)} gateway ACL rule(s) "
            f"({', '.join(str(r.get('name') or r.get('id')) for r in ref_rules)}); "
            "will execute the 6-step tmp-group swap"
        )
        steps_plan = [
            {"step": 1, "action": "create_temp_group", "name": f"{group_name}__tmp"},
            {"step": 2, "action": "repoint_acls_to_temp", "ruleIds": [str(r.get("id")) for r in ref_rules]},
            {"step": 3, "action": "delete_old_group", "groupId": old_id},
            {"step": 4, "action": "recreate_group", "name": group_name},
            {"step": 5, "action": "repoint_acls_to_new", "ruleIds": [str(r.get("id")) for r in ref_rules]},
            {"step": 6, "action": "delete_temp_group"},
        ]
    else:
        steps_plan = [
            {"step": 1, "action": "delete_old_group", "groupId": old_id},
            {"step": 2, "action": "recreate_group", "name": group_name},
        ]

    proposed_after = {
        "groupId": "<new-group-id>",
        "id": "<new-group-id>",
        "name": group_name,
        "type": group_type,
        "resource": 0,
        "ipList": new_ip_list,
    }
    rollback_old_cidrs = _format_ip_list_as_cidrs(old_ip_list)
    dry_rollback = (
        {
            "tool": "replace_ip_group",
            "arguments": {"group": group_name, "cidrs": rollback_old_cidrs, "dryRun": True},
        }
        if rollback_old_cidrs
        else None
    )

    if dryRun:
        return _dry_run_result(
            tool_name="replace_ip_group",
            target_id=old_id,
            before=target_group,
            after=proposed_after,
            diff=diff,
            warnings=warnings,
            rollback=dry_rollback,
            steps=steps_plan,
        )

    expected_new_pairs = _ip_list_canonical(new_ip_list)
    completed: List[Dict[str, Any]] = []
    snapshots: List[str] = []
    tmp_id: Optional[str] = None
    new_id: Optional[str] = None

    def _read_ip_groups() -> List[Dict[str, Any]]:
        return [g for g in _fetch_groups(client, site) if int(g.get("type", 0)) == group_type]

    def _delete_group(gid: str, step_label: str, snap_extra: Any) -> None:
        del_ep = f"sites/{site.site_id}/setting/profiles/groups/{group_type}/{gid}"
        res = client.write(
            del_ep,
            method="DELETE",
            data=None,
            tool_name="replace_ip_group",
            target=gid,
            before=snap_extra,
            snapshot_payload=snap_extra,
            read_back=_read_ip_groups,
            verify_fn=lambda _b, groups_now: (
                (all(_group_id(g) != gid for g in groups_now),
                 f"group {gid} still present after DELETE")
            ),
            fields_changed=[step_label],
        )
        snapshots.append(str(res["snapshot"]))
        completed.append({"action": step_label, "groupId": gid, "snapshot": res["snapshot"]})

    def _create_group(gname: str, glist: List[Dict[str, Any]], step_label: str) -> Dict[str, Any]:
        post_ep = f"sites/{site.site_id}/setting/profiles/groups"
        pairs = _ip_list_canonical(glist)

        def _verify_created(_b: Any, groups_now: Any) -> Tuple[bool, Optional[str]]:
            found = next((g for g in groups_now if str(g.get("name")) == gname), None)
            if found is None:
                return False, f"group {gname!r} missing after POST"
            if _ip_list_canonical(found.get("ipList") or []) != pairs:
                return False, f"group {gname!r} ipList mismatch after POST"
            return True, None

        def _reauth_create() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
            groups_now = _read_ip_groups()
            ok, _ = _verify_created(None, groups_now)
            return ok, None, None

        res = client.write(
            post_ep,
            method="POST",
            data={"name": gname, "type": group_type, "resource": 0, "ipList": glist},
            tool_name="replace_ip_group",
            target=gname,
            before=target_group,
            snapshot_payload={"targetGroup": target_group, "referencingAcls": ref_rules},
            read_back=_read_ip_groups,
            verify_fn=_verify_created,
            reauth_prepare=_reauth_create,
            fields_changed=[step_label],
        )
        snapshots.append(str(res["snapshot"]))
        created = next(g for g in res["after"] if str(g.get("name")) == gname)
        completed.append({"action": step_label, "groupId": _group_id(created), "snapshot": res["snapshot"]})
        return created

    def _repoint_rule(rule: Dict[str, Any], from_id: str, to_id: str, step_label: str) -> None:
        rid = str(rule["id"])
        patched_rule = _swap_rule_group_id(rule, from_id, to_id)
        acl_ep = f"sites/{site.site_id}/setting/firewall/acls/{rid}?type=0"

        def _read_rule() -> Optional[Dict[str, Any]]:
            _, rules_now = _fetch_acls(client, site)
            return next((r for r in rules_now if str(r.get("id")) == rid), None)

        def _verify_rule(_b: Any, after_rule: Any) -> Tuple[bool, Optional[str]]:
            if not isinstance(after_rule, Mapping):
                return False, f"ACL rule {rid} missing on read-back"
            if int(rule.get("sourceType", -1)) == 1 and from_id in [str(x) for x in (rule.get("sourceIds") or [])]:
                sids = [str(x) for x in (after_rule.get("sourceIds") or [])]
                if to_id not in sids or from_id in sids:
                    return False, f"ACL rule {rid} sourceIds={sids!r} did not swap {from_id} -> {to_id}"
            if int(rule.get("destinationType", -1)) == 1 and from_id in [str(x) for x in (rule.get("destinationIds") or [])]:
                dids = [str(x) for x in (after_rule.get("destinationIds") or [])]
                if to_id not in dids or from_id in dids:
                    return False, f"ACL rule {rid} destinationIds={dids!r} did not swap {from_id} -> {to_id}"
            return True, None

        def _reauth_rule() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
            fresh = _read_rule()
            if fresh is None:
                return False, None, None
            ok, _ = _verify_rule(rule, fresh)
            if ok:
                return True, None, None
            return False, _swap_rule_group_id(fresh, from_id, to_id), fresh

        res = client.write(
            acl_ep,
            method="PUT",
            data=patched_rule,
            tool_name="replace_ip_group",
            target=rid,
            before=rule,
            snapshot_payload=rule,
            read_back=_read_rule,
            verify_fn=_verify_rule,
            reauth_prepare=_reauth_rule,
            fields_changed=[step_label, "sourceIds", "destinationIds"],
        )
        snapshots.append(str(res["snapshot"]))
        completed.append({"action": step_label, "ruleId": rid, "fromId": from_id, "toId": to_id})

    try:
        if not ref_rules:
            _delete_group(old_id, "delete_old_group", {"targetGroup": target_group})
            created = _create_group(group_name, new_ip_list, "recreate_group")
            new_id = _group_id(created)
        else:
            existing_names = {str(g.get("name")) for g in groups_before}
            tmp_name = f"{group_name}__tmp"
            suffix = 1
            while tmp_name in existing_names:
                suffix += 1
                tmp_name = f"{group_name}__tmp_{suffix}"
            tmp_group = _create_group(tmp_name, old_ip_list, "create_temp_group")
            tmp_id = _group_id(tmp_group)
            for rule in ref_rules:
                _repoint_rule(rule, old_id, tmp_id, "repoint_acls_to_temp")
            _delete_group(old_id, "delete_old_group", {"targetGroup": target_group, "tmpId": tmp_id})
            created = _create_group(group_name, new_ip_list, "recreate_group")
            new_id = _group_id(created)
            for rule in ref_rules:
                # Re-fetch rule with tmp_id so full object reflects live rule state.
                _, live_acls = _fetch_acls(client, site)
                live_rule = next((r for r in live_acls if str(r.get("id")) == str(rule["id"])), rule)
                _repoint_rule(live_rule, tmp_id, new_id, "repoint_acls_to_new")
            _delete_group(tmp_id, "delete_temp_group", {"tmpGroup": tmp_group, "newId": new_id})
    except OmadaError as exc:
        raise OmadaError(
            f"replace_ip_group failed mid-operation after {len(completed)} step(s): {exc.message}",
            code=exc.code,
            hint=(
                f"completed steps={json_summary(completed)}; "
                f"old_id={old_id}, tmp_id={tmp_id}, new_id={new_id}; "
                f"snapshots={snapshots}; inspect live groups and ACL rules before recovering"
            ),
            endpoint=exc.endpoint,
        ) from None

    # Final verification of the recreated group and any referencing ACLs.
    final_groups = _read_ip_groups()
    final_group = next((g for g in final_groups if _group_id(g) == new_id), None)
    if final_group is None or _ip_list_canonical(final_group.get("ipList") or []) != expected_new_pairs:
        raise OmadaError("final IP group verification failed after replace_ip_group")
    if ref_rules:
        _, final_acls = _fetch_acls(client, site)
        for rule in ref_rules:
            live = next((r for r in final_acls if str(r.get("id")) == str(rule["id"])), None)
            if live is None:
                raise OmadaError(f"referencing ACL rule {rule.get('id')} missing after swap")
            if new_id not in [str(x) for x in (live.get("sourceIds") or [])] and \
                    new_id not in [str(x) for x in (live.get("destinationIds") or [])]:
                raise OmadaError(f"ACL rule {rule.get('id')} was not re-pointed to new group {new_id}")

    committed_rollback = (
        {
            "tool": "replace_ip_group",
            "arguments": {"group": new_id, "cidrs": rollback_old_cidrs, "dryRun": True},
        }
        if rollback_old_cidrs
        else None
    )
    return _committed_result(
        tool_name="replace_ip_group",
        target_id=old_id,
        before=target_group,
        after=_normalize_group_output(final_group),
        diff=diff,
        snapshot=snapshots[0] if snapshots else None,
        warnings=warnings,
        rollback=committed_rollback,
        steps=completed,
    )


def json_summary(obj: Any) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, default=str)


# -- 7 & 8: Gateway ACLs -----------------------------------------------------

def _parse_policy(policy: Any) -> int:
    if isinstance(policy, bool):
        raise OmadaError("policy must be 'deny' (0) or 'permit' (1), not a boolean")
    if isinstance(policy, int):
        if policy in (0, 1):
            return policy
    text = str(policy or "").strip().lower()
    if text in ("0", "deny", "block", "drop"):
        return 0
    if text in ("1", "permit", "allow", "accept"):
        return 1
    raise OmadaError(f"invalid ACL policy {policy!r}; expected 'deny' (0) or 'permit' (1)")


def _resolve_acl_endpoint(
    spec: Mapping[str, Any],
    *,
    label: str,
    networks: Sequence[Mapping[str, Any]],
    groups: Sequence[Mapping[str, Any]],
) -> Tuple[int, List[str]]:
    if not isinstance(spec, Mapping):
        raise OmadaError(f"{label} must be an object with 'type' and 'ids'")
    raw_type = str(spec.get("type", "")).strip().lower()
    if raw_type not in _SOURCE_DEST_TYPES:
        raise OmadaError(
            f"{label}.type={spec.get('type')!r} is invalid; expected 'network' (0), "
            "'ip_group' (1), or 'port_group' (2)",
        )
    ep_type = _SOURCE_DEST_TYPES[raw_type]
    raw_ids = spec.get("ids")
    if not isinstance(raw_ids, list) or not raw_ids:
        raise OmadaError(f"{label}.ids must be a non-empty array")

    resolved: List[str] = []
    for raw_item in raw_ids:
        needle = str(raw_item or "").strip()
        if not needle:
            raise OmadaError(f"{label}.ids contains an empty entry")
        if ep_type == 0:
            found = next(
                (n for n in networks if str(n.get("id")) == needle
                 or str(n.get("name", "")).strip().lower() == needle.lower()),
                None,
            )
            if found is None:
                raise OmadaError(f"{label}: no LAN network matches {needle!r}")
            resolved.append(str(found["id"]))
        elif ep_type == 1:
            found_g = next(
                (g for g in groups
                 if int(g.get("type", 0)) == 0
                 and (_group_id(g) == needle
                      or str(g.get("name", "")).strip().lower() == needle.lower())),
                None,
            )
            if found_g is None:
                raise OmadaError(f"{label}: no IP group matches {needle!r}")
            resolved.append(_group_id(found_g))
        else:
            resolved.append(needle)
    return ep_type, resolved


def _normalize_direction(direction: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(direction, Mapping):
        raise OmadaError("direction must be an object with lanToWan / lanToLan booleans")
    norm = {
        "lanToWan": bool(direction.get("lanToWan", False)),
        "lanToLan": bool(direction.get("lanToLan", False)),
        "wanInIds": list(direction.get("wanInIds") or []),
        "vpnInIds": list(direction.get("vpnInIds") or []),
    }
    if not (norm["lanToWan"] or norm["lanToLan"] or norm["wanInIds"] or norm["vpnInIds"]):
        raise OmadaError("direction must enable at least one of lanToWan, lanToLan, wanInIds, or vpnInIds")
    return norm


def create_gateway_acl(
    client: OmadaClient,
    name: str,
    policy: Any,
    source: Dict[str, Any],
    destination: Dict[str, Any],
    direction: Dict[str, Any],
    status: bool = True,
    protocols: Optional[List[int]] = None,
    biDirectional: bool = False,
    syslog: bool = False,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a gateway ACL rule (``POST setting/firewall/acls?type=0``)."""
    rule_name = str(name or "").strip()
    if not rule_name:
        raise OmadaError("ACL rule name must be non-empty")

    policy_int = _parse_policy(policy)
    norm_direction = _normalize_direction(direction)
    norm_protocols = [int(p) for p in (protocols if protocols is not None else [256])]
    if not norm_protocols:
        raise OmadaError("protocols must be a non-empty list of protocol codes (e.g. [256] for any)")

    _require_confirm("create_gateway_acl", rule_name, dryRun, confirm)

    site = _site(client)
    acl_disable, existing_acls = _fetch_acls(client, site)
    if any(str(r.get("name", "")).strip() == rule_name for r in existing_acls):
        raise OmadaError(
            f"gateway ACL {rule_name!r} already exists",
            hint="use a unique rule name, or set_acl_rule_status to toggle an existing rule",
        )

    networks = _fetch_lan_collection(client, site)
    groups = _fetch_groups(client, site)
    src_type, src_ids = _resolve_acl_endpoint(source, label="source", networks=networks, groups=groups)
    dst_type, dst_ids = _resolve_acl_endpoint(destination, label="destination", networks=networks, groups=groups)
    if (
        norm_direction["lanToWan"]
        and not norm_direction["lanToLan"]
        and not norm_direction["wanInIds"]
        and not norm_direction["vpnInIds"]
        and dst_type == 0
    ):
        raise OmadaError(
            "LAN->WAN gateway ACL rules do not accept destination.type='network' (controller returns -33601)",
            code=-33601,
            hint="use destination.type='ip_group' (e.g. 'IPGroup_Any') or 'port_group' for LAN->WAN rules",
        )

    _check_acl_safety(
        client,
        policy=policy_int,
        status=bool(status),
        source_type=src_type,
        source_ids=src_ids,
        dest_type=dst_type,
        dest_ids=dst_ids,
        direction=norm_direction,
        networks=networks,
        groups=groups,
    )

    body = {
        "name": rule_name,
        "status": bool(status),
        "policy": policy_int,
        "protocols": norm_protocols,
        "sourceType": src_type,
        "sourceIds": src_ids,
        "destinationType": dst_type,
        "destinationIds": dst_ids,
        "direction": norm_direction,
        "type": 0,
        "biDirectional": bool(biDirectional),
        "stateMode": 0,
        "ipSec": 0,
        "syslog": bool(syslog),
        "customAclDevices": [],
        "customAclOsws": [],
        "customAclStacks": [],
    }
    diff = {"rule": {"before": None, "after": body}}
    warnings = [_ACL_DISPATCH_NOTES]
    if acl_disable is not None:
        warnings.append(f"observed controller aclDisable={acl_disable!r} (advisory only)")

    if dryRun:
        return _dry_run_result(
            tool_name="create_gateway_acl",
            target_id=rule_name,
            before=None,
            after=body,
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    endpoint = f"sites/{site.site_id}/setting/firewall/acls?type=0"

    def _read_back() -> List[Dict[str, Any]]:
        _, rules = _fetch_acls(client, site)
        return rules

    def _matches_rule(rule: Mapping[str, Any]) -> bool:
        return (
            str(rule.get("name")) == rule_name
            and int(rule.get("policy", -1)) == policy_int
            and bool(rule.get("status")) == bool(status)
            and int(rule.get("sourceType", -1)) == src_type
            and [str(x) for x in (rule.get("sourceIds") or [])] == src_ids
            and int(rule.get("destinationType", -1)) == dst_type
            and [str(x) for x in (rule.get("destinationIds") or [])] == dst_ids
        )

    def _verify(_before: Any, after_rules: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_rules, list):
            return False, "ACL read-back did not return a rule list"
        found = next((r for r in after_rules if str(r.get("name")) == rule_name), None)
        if found is None:
            return False, f"created ACL rule {rule_name!r} missing on read-back"
        if not _matches_rule(found):
            return False, f"created ACL rule {rule_name!r} fields on read-back did not match intent"
        return True, None

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
        rules_now = _read_back()
        ok, _ = _verify(None, rules_now)
        return ok, None, None

    write_res = client.write(
        endpoint,
        method="POST",
        data=body,
        tool_name="create_gateway_acl",
        target=rule_name,
        before=None,
        snapshot_payload={"aclDisable": acl_disable, "existingAcls": existing_acls},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["name", "policy", "status", "sourceIds", "destinationIds", "direction"],
    )
    created_rule = next(
        (r for r in write_res["after"] if str(r.get("name")) == rule_name),
        body,
    )
    rollback = {
        "tool": "set_acl_rule_status",
        "arguments": {"rule": str(created_rule.get("id") or rule_name), "status": False, "dryRun": True},
    }
    return _committed_result(
        tool_name="create_gateway_acl",
        target_id=rule_name,
        before=None,
        after=created_rule,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def set_acl_rule_status(
    client: OmadaClient,
    rule: str,
    status: bool,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Enable or disable a single gateway ACL rule (never touches ``aclDisable``)."""
    site = _site(client)
    acl_disable, rules = _fetch_acls(client, site)
    needle = str(rule or "").strip()
    by_id = [r for r in rules if str(r.get("id")) == needle]
    if by_id:
        target_rule = dict(by_id[0])
    else:
        by_name = [r for r in rules if str(r.get("name", "")).strip().lower() == needle.lower()]
        if len(by_name) == 1:
            target_rule = dict(by_name[0])
        elif len(by_name) > 1:
            ids = ", ".join(str(r.get("id")) for r in by_name)
            raise OmadaError(f"ACL rule {rule!r} matched multiple rules ({ids}); specify rule id")
        else:
            raise OmadaError(f"no gateway ACL rule matches {rule!r}")

    target_id = str(target_rule["id"])
    _require_confirm("set_acl_rule_status", target_id, dryRun, confirm)

    desired_status = bool(status)
    if desired_status and int(target_rule.get("policy", 1)) == 0:
        networks = _fetch_lan_collection(client, site)
        groups = _fetch_groups(client, site)
        _check_acl_safety(
            client,
            policy=0,
            status=True,
            source_type=int(target_rule.get("sourceType", -1)),
            source_ids=[str(x) for x in (target_rule.get("sourceIds") or [])],
            dest_type=int(target_rule.get("destinationType", -1)),
            dest_ids=[str(x) for x in (target_rule.get("destinationIds") or [])],
            direction=target_rule.get("direction") or {},
            networks=networks,
            groups=groups,
        )

    before_summary = {
        "id": target_id,
        "name": target_rule.get("name"),
        "status": bool(target_rule.get("status")),
        "policy": target_rule.get("policy"),
    }
    proposed_after = dict(before_summary)
    proposed_after["status"] = desired_status
    diff = {"status": {"before": bool(target_rule.get("status")), "after": desired_status}}
    warnings = [_ACL_DISPATCH_NOTES]
    if acl_disable is not None:
        warnings.append(f"observed controller aclDisable={acl_disable!r} (advisory only)")
    rollback = {
        "tool": "set_acl_rule_status",
        "arguments": {"rule": target_id, "status": bool(target_rule.get("status")), "dryRun": True},
    }

    if dryRun:
        return _dry_run_result(
            tool_name="set_acl_rule_status",
            target_id=target_id,
            before=before_summary,
            after=proposed_after,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/setting/firewall/acls/{target_id}?type=0"
    patch_body = copy.deepcopy(target_rule)
    patch_body["status"] = desired_status

    def _read_back() -> Optional[Dict[str, Any]]:
        _, live_rules = _fetch_acls(client, site)
        return next((dict(r) for r in live_rules if str(r.get("id")) == target_id), None)

    def _verify(_before: Any, after_rule: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_rule, Mapping):
            return False, f"ACL rule {target_id} missing on read-back"
        if bool(after_rule.get("status")) != desired_status:
            return False, f"ACL rule status expected {desired_status}, got {after_rule.get('status')!r}"
        drifts = _diff_mappings(target_rule, after_rule, ignore_keys=["status"])
        if drifts:
            return False, "unexpected field drift on ACL rule after PATCH: " + ", ".join(drifts)
        return True, None

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
        fresh = _read_back()
        if fresh is None:
            return False, None, None
        ok, _ = _verify(before_summary, fresh)
        if ok:
            return True, None, None
        fresh_patch = copy.deepcopy(fresh)
        fresh_patch["status"] = desired_status
        fresh_before = {
            "id": target_id,
            "name": fresh.get("name"),
            "status": bool(fresh.get("status")),
            "policy": fresh.get("policy"),
        }
        return False, fresh_patch, fresh_before

    write_res = client.write(
        endpoint,
        method="PUT",
        data=patch_body,
        tool_name="set_acl_rule_status",
        target=target_id,
        before=before_summary,
        snapshot_payload=target_rule,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["status"],
    )
    after_rule = write_res["after"]
    after_summary = {
        "id": target_id,
        "name": after_rule.get("name"),
        "status": bool(after_rule.get("status")),
        "policy": after_rule.get("policy"),
    }
    return _committed_result(
        tool_name="set_acl_rule_status",
        target_id=target_id,
        before=write_res["before"],
        after=after_summary,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )
