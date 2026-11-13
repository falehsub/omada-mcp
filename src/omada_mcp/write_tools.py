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
import re
import urllib.parse
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .client import OmadaClient, OmadaError, SiteInfo, describe_error, redact_secrets

__all__ = [
    "CLIENT_VOLATILE_KEYS",
    "WRITE_ENVELOPE_SCHEMA",
    "create_gateway_acl",
    "create_ip_group",
    "create_lan_network",
    "create_ssid",
    "delete_dhcp_reservation",
    "delete_gateway_acl",
    "delete_ip_group",
    "delete_lan_network",
    "delete_mdns_rule",
    "delete_port_forward",
    "delete_ssid",
    "delete_static_route",
    "pack_ip_entries",
    "reboot_device",
    "reconnect_client",
    "release_client_fixed_ip",
    "replace_ip_group",
    "set_acl_rule_status",
    "set_client_blocked",
    "set_client_fixed_ip",
    "set_upnp",
    "set_vlan_dhcp_pools",
    "set_vlan_isolation",
    "update_client",
    "update_device",
    "update_gateway_acl",
    "update_lan_network",
    "update_ssid",
    "upsert_dhcp_reservation",
    "upsert_mdns_rule",
    "upsert_port_forward",
    "upsert_static_route",
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

def _omada_mac(value: str) -> str:
    """Validate 12 hex digits and format uppercase hyphenated ``AA-BB-CC-DD-EE-FF``."""
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).upper()
    if len(cleaned) == 12 and all(ch in "0123456789ABCDEF" for ch in cleaned):
        return "-".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    raise OmadaError(
        f"invalid MAC address {value!r}",
        hint="expected 12 hex digits (e.g. aa:bb:cc:dd:ee:ff or AA-BB-CC-DD-EE-FF)",
    )


def _fetch_devices(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/devices")
    return rows


def _fetch_insight_clients(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []
    seen = set()
    rows, _ = client.paginate(f"sites/{site.site_id}/insight/clients", max_pages=20)
    for row in rows:
        mac = _normalize_mac(row.get("mac", ""))
        if mac and mac in seen:
            continue
        if mac:
            seen.add(mac)
        collected.append(row)
    return collected


def _fetch_clients_filtered(client: OmadaClient, site: SiteInfo, *, active: Optional[bool]) -> List[Dict[str, Any]]:
    if active is None:
        rows_active, _ = client.paginate(f"sites/{site.site_id}/clients?filters.active=true", max_pages=20)
        rows_inactive, _ = client.paginate(f"sites/{site.site_id}/clients?filters.active=false", max_pages=20)
        by_mac: Dict[str, Dict[str, Any]] = {}
        for row in rows_inactive + rows_active:
            mac = _normalize_mac(row.get("mac", ""))
            if mac:
                by_mac[mac] = row
        return list(by_mac.values())
    flag = "true" if active else "false"
    rows, _ = client.paginate(f"sites/{site.site_id}/clients?filters.active={flag}", max_pages=20)
    return rows


def _fetch_lan_collection(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/lan/networks")
    return rows


def _fetch_lan_interfaces(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/lan/networks/interface")
    return rows


def _fetch_groups(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/profiles/groups")
    return rows


def _fetch_acls(client: OmadaClient, site: SiteInfo) -> Tuple[Optional[bool], List[Dict[str, Any]]]:
    rows, meta = client.paginate(f"sites/{site.site_id}/setting/firewall/acls?type=0")
    if isinstance(meta, Mapping):
        acl_disable = meta.get("aclDisable")
        return (bool(acl_disable) if acl_disable is not None else None), rows
    return None, rows


def _fetch_wan_networks(client: OmadaClient, site: SiteInfo) -> Dict[str, Any]:
    res = client.api_result(f"sites/{site.site_id}/setting/wan/networks")
    return dict(res) if isinstance(res, Mapping) else {}


def _fetch_dhcp_reservations(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/service/dhcp")
    return rows


def _fetch_port_forwards(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/transmission/portForwardings")
    return rows


def _fetch_static_routes(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/transmission/staticRoutings")
    return rows


def _fetch_mdns_rules(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/service/mdns")
    return rows


def _fetch_mdns_profiles(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/profiles/mdns")
    return rows


def _fetch_wlan_groups(client: OmadaClient, site: SiteInfo) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/wlans")
    return rows


def _fetch_ssids(client: OmadaClient, site: SiteInfo, wlan_id: str) -> List[Dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/wlans/{wlan_id}/ssids")
    return rows


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
    """Return a deep copy with ``lanNetworkIpv6Config`` and DHCP guard blocks non-null."""
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
    # Omada 6.2.x POST returns dhcpGuard={} / dhcpv6Guard={}, which PATCH rejects (-1001).
    for guard_key in ("dhcpGuard", "dhcpv6Guard"):
        guard = body.get(guard_key)
        if not isinstance(guard, dict):
            body[guard_key] = {"enable": False}
        elif guard.get("enable") is None:
            guard["enable"] = False
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
    if defaulted_ipv6 or (
        iface_before.get("lanNetworkIpv6Config") == {"proto": "none", "enable": 0}
        and iface_after.get("lanNetworkIpv6Config") == {"enable": 0}
    ):
        ignored.append("lanNetworkIpv6Config")
    if "qosQueueEnable" not in iface_before and iface_after.get("qosQueueEnable") is False:
        ignored.append("qosQueueEnable")
    for guard_key in ("dhcpGuard", "dhcpv6Guard"):
        prev = iface_before.get(guard_key)
        if (not isinstance(prev, Mapping) or prev.get("enable") is None) and iface_after.get(guard_key) == {"enable": False}:
            ignored.append(guard_key)
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


# -- shared helpers for expanded home-network write surface ------------------

_DEV_ENDPOINT_PREFIX: Dict[str, str] = {
    "ap": "eaps",
    "eap": "eaps",
    "switch": "switches",
    "gateway": "gateways",
}

_LED_MODES: Dict[str, int] = {
    "0": 0,
    "off": 0,
    "false": 0,
    "1": 1,
    "on": 1,
    "true": 1,
    "2": 2,
    "use_site": 2,
    "site": 2,
}

_SSID_BAND_BITS: Dict[str, int] = {
    "2g": 1,
    "2.4g": 1,
    "2.4ghz": 1,
    "5g": 2,
    "5ghz": 2,
    "6g": 4,
    "6ghz": 4,
}

_SSID_SERVER_ONLY_KEYS = frozenset({
    "id",
    "idInt",
    "site",
    "wlanId",
    "resource",
    "index",
    "portalEnable",
})


def _resolve_by_id_or_name(
    items: Sequence[Mapping[str, Any]],
    needle: str,
    *,
    label: str,
    id_key: str = "id",
    name_key: str = "name",
    extra_keys: Sequence[str] = (),
) -> Dict[str, Any]:
    raw = str(needle or "").strip()
    if not raw:
        raise OmadaError(f"{label} identifier must be non-empty")
    lower = raw.lower()
    exact_id = [dict(item) for item in items if str(item.get(id_key, "")).strip().lower() == lower]
    if len(exact_id) == 1:
        return exact_id[0]
    matches: List[Dict[str, Any]] = []
    keys = (name_key,) + tuple(extra_keys)
    for item in items:
        for key in keys:
            val = str(item.get(key, "")).strip()
            if val and val.lower() == lower:
                matches.append(dict(item))
                break
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        ids = ", ".join(str(m.get(id_key) or m.get(name_key) or "?") for m in matches)
        raise OmadaError(f"{label} {needle!r} matched multiple entries ({ids}); specify exact id")
    raise OmadaError(f"no {label} matches {needle!r}")


def _parse_ipv4(value: str, label: str = "IP address") -> ipaddress.IPv4Address:
    text = str(value or "").strip()
    try:
        return ipaddress.IPv4Address(text)
    except ValueError as exc:
        raise OmadaError(f"invalid IPv4 {label} {value!r}: {exc}") from None


def _validate_vlan_id(vlan: Any) -> int:
    if isinstance(vlan, bool):
        raise OmadaError("vlan must be an integer between 1 and 4094")
    try:
        vid = int(vlan)
    except (TypeError, ValueError):
        raise OmadaError(f"invalid VLAN ID {vlan!r}; expected integer 1..4094") from None
    if not 1 <= vid <= 4094:
        raise OmadaError(f"VLAN ID {vid} out of range (expected 1..4094)")
    return vid


def _redact_ssid(ssid: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(ssid, Mapping):
        return None
    cleaned = redact_secrets(dict(ssid))
    psk = ssid.get("pskSetting")
    cleaned["hasPresharedKey"] = bool(
        ssid.get("securityKey")
        or (isinstance(psk, Mapping) and psk.get("securityKey"))
        or ssid.get("ppskSetting")
    )
    return cleaned


def _port_range_valid(spec: str, label: str = "port") -> str:
    text = str(spec or "").strip()
    if not text:
        raise OmadaError(f"{label} must be non-empty")
    for part in text.split(","):
        seg = part.strip()
        if not seg:
            raise OmadaError(f"{label} {spec!r} has an empty segment")
        if "-" in seg:
            bounds = seg.split("-", 1)
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
            except ValueError:
                raise OmadaError(f"invalid port range {seg!r} in {label}") from None
            if not (1 <= lo <= hi <= 65535):
                raise OmadaError(f"port range {seg!r} out of valid bounds 1..65535")
        else:
            try:
                num = int(seg)
            except ValueError:
                raise OmadaError(f"invalid port number {seg!r} in {label}") from None
            if not 1 <= num <= 65535:
                raise OmadaError(f"port {num} out of valid bounds 1..65535")
    return text


def _delete_entity(
    client: OmadaClient,
    *,
    tool_name: str,
    target_id: str,
    endpoint: str,
    before: Any,
    snapshot_payload: Any,
    fetch_all: Any,
    match_fn: Any,
    rollback: Optional[Dict[str, Any]],
    warnings: Optional[List[str]],
    dry_run: bool,
    confirm: Optional[str],
    label: str,
) -> Dict[str, Any]:
    _require_confirm(tool_name, target_id, dry_run, confirm)
    diff = {label: {"before": before, "after": None}}
    warn_list = list(warnings or [])
    if dry_run:
        return _dry_run_result(
            tool_name=tool_name,
            target_id=target_id,
            before=before,
            after=None,
            diff=diff,
            warnings=warn_list,
            rollback=rollback,
        )

    def _read_back() -> List[Dict[str, Any]]:
        return list(fetch_all())

    def _verify(_before: Any, after_rows: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_rows, list):
            return False, f"{label} read-back did not return a list"
        still_there = next((r for r in after_rows if match_fn(r)), None)
        if still_there is not None:
            return False, f"{label} {target_id!r} still present after DELETE"
        return True, None

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
        rows_now = _read_back()
        gone = next((r for r in rows_now if match_fn(r)), None) is None
        return gone, None, None

    write_res = client.write(
        endpoint,
        method="DELETE",
        tool_name=tool_name,
        target=target_id,
        before=before,
        snapshot_payload=snapshot_payload,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["deleted"],
    )
    return _committed_result(
        tool_name=tool_name,
        target_id=target_id,
        before=write_res["before"],
        after=None,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warn_list,
        rollback=rollback,
    )


def _match_fields(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> Tuple[bool, Optional[str]]:
    for key, exp_val in expected.items():
        if key not in actual:
            return False, f"field {key!r} missing on read-back"
        act_val = actual[key]
        if isinstance(exp_val, Mapping) and isinstance(act_val, Mapping):
            ok, reason = _match_fields(act_val, exp_val)
            if not ok:
                return False, f"{key}.{reason}"
        elif isinstance(exp_val, bool):
            if bool(act_val) != exp_val:
                return False, f"field {key!r} expected {exp_val!r}, got {act_val!r}"
        elif act_val != exp_val:
            return False, f"field {key!r} expected {exp_val!r}, got {act_val!r}"
    return True, None


# -- 9 & 10: Static DHCP reservations (controller-native) --------------------

def upsert_dhcp_reservation(
    client: OmadaClient,
    mac: str,
    ip: str,
    vlan: Optional[Any] = None,
    netId: Optional[str] = None,
    description: Optional[str] = None,
    status: bool = True,
    exportToIpMacBinding: Optional[bool] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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

    body: Dict[str, Any] = {
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
    warnings: List[str] = []
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

    is_update = before_row is not None
    endpoint = (
        f"sites/{site.site_id}/setting/service/dhcp/{urllib.parse.quote(str(before_row['mac']), safe='')}"
        if is_update
        else f"sites/{site.site_id}/setting/service/dhcp"
    )
    method = "PUT" if is_update else "POST"

    def _read_back() -> Optional[Dict[str, Any]]:
        rows_now = _fetch_dhcp_reservations(client, site)
        return next((dict(r) for r in rows_now if _normalize_mac(r.get("mac", "")) == norm_mac), None)

    def _verify(_before: Any, after_row: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_row, Mapping):
            return False, f"DHCP reservation for {norm_mac} missing on read-back"
        return _match_fields(after_row, expected)

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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


# -- 11, 12, 13: LAN / VLAN lifecycle ---------------------------------------

def _default_dhcp_pool_for_subnet(subnet: ipaddress.IPv4Network, gw_ip: ipaddress.IPv4Address) -> Dict[str, str]:
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
    gatewaySubnet: Optional[str] = None,
    dhcpEnable: bool = True,
    pools: Optional[List[Dict[str, str]]] = None,
    leaseTime: int = 120,
    domain: Optional[str] = None,
    isolation: bool = False,
    igmpSnoopEnable: bool = False,
    icmpPingEnable: bool = True,
    interfaceIds: Optional[List[str]] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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

    body: Dict[str, Any] = {
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

        resolved_if_ids: List[str]
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

        dhcp_block: Dict[str, Any] = {
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
    warnings: List[str] = []
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

    def _read_back() -> Dict[str, Any]:
        return {
            "collection": _fetch_lan_collection(client, site),
            "interfaces": _fetch_lan_interfaces(client, site),
        }

    def _find_created(state: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        for row in state.get("collection") or []:
            if str(row.get("name", "")).strip() == net_name and row.get("vlan") == vid:
                return dict(row)
        return None

    def _verify(_before: Any, after_state: Any) -> Tuple[bool, Optional[str]]:
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

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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
    vlan: Optional[Any] = None,
    netId: Optional[str] = None,
    name: Optional[str] = None,
    dhcpEnable: Optional[bool] = None,
    leaseTime: Optional[int] = None,
    dnsMode: Optional[str] = None,
    dnsServers: Optional[List[str]] = None,
    domain: Optional[str] = None,
    igmpSnoopEnable: Optional[bool] = None,
    icmpPingEnable: Optional[bool] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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
    diff: Dict[str, Any] = {}
    ignored_extra: List[str] = []

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

    rollback_args: Dict[str, Any] = {"netId": target_id, "dryRun": True}
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

    def _read_back() -> Dict[str, Any]:
        col_after, iface_after = _fetch_lan_pair(client, site, net_id=target_id)
        return {"collection": col_after, "interface": iface_after}

    def _verify(_before: Any, after_pair: Any) -> Tuple[bool, Optional[str]]:
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

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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
    vlan: Optional[Any] = None,
    netId: Optional[str] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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

    warnings: List[str] = []
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


# -- 14, 15, 16: ACL & IP Group completion -----------------------------------

def update_gateway_acl(
    client: OmadaClient,
    rule: str,
    name: Optional[str] = None,
    status: Optional[bool] = None,
    policy: Any = None,
    source: Optional[Dict[str, Any]] = None,
    destination: Optional[Dict[str, Any]] = None,
    direction: Optional[Dict[str, Any]] = None,
    protocols: Optional[List[int]] = None,
    biDirectional: Optional[bool] = None,
    syslog: Optional[bool] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Modify fields of an existing gateway ACL rule (``PUT setting/firewall/acls/{id}?type=0``)."""
    if all(
        v is None
        for v in (name, status, policy, source, destination, direction, protocols, biDirectional, syslog)
    ):
        raise OmadaError("specify at least one field to update on the gateway ACL rule")

    site = _site(client)
    acl_disable, rules = _fetch_acls(client, site)
    target_rule = _resolve_by_id_or_name(rules, rule, label="gateway ACL rule")
    target_id = str(target_rule["id"])
    _require_confirm("update_gateway_acl", target_id, dryRun, confirm)

    networks = _fetch_lan_collection(client, site)
    groups = _fetch_groups(client, site)

    patch_body = copy.deepcopy(target_rule)
    changed_keys: List[str] = []
    if name is not None:
        clean_name = str(name).strip()
        if not clean_name:
            raise OmadaError("ACL rule name must be non-empty")
        patch_body["name"] = clean_name
        changed_keys.append("name")
    if status is not None:
        patch_body["status"] = bool(status)
        changed_keys.append("status")
    if policy is not None:
        patch_body["policy"] = _parse_policy(policy)
        changed_keys.append("policy")
    if source is not None:
        src_type, src_ids = _resolve_acl_endpoint(source, label="source", networks=networks, groups=groups)
        patch_body["sourceType"] = src_type
        patch_body["sourceIds"] = src_ids
        changed_keys.extend(["sourceType", "sourceIds"])
    if destination is not None:
        dst_type, dst_ids = _resolve_acl_endpoint(destination, label="destination", networks=networks, groups=groups)
        patch_body["destinationType"] = dst_type
        patch_body["destinationIds"] = dst_ids
        changed_keys.extend(["destinationType", "destinationIds"])
    if direction is not None:
        patch_body["direction"] = _normalize_direction(direction)
        changed_keys.append("direction")
    if protocols is not None:
        if not protocols:
            raise OmadaError("protocols must be non-empty")
        patch_body["protocols"] = [int(p) for p in protocols]
        changed_keys.append("protocols")
    if biDirectional is not None:
        patch_body["biDirectional"] = bool(biDirectional)
        changed_keys.append("biDirectional")
    if syslog is not None:
        patch_body["syslog"] = bool(syslog)
        changed_keys.append("syslog")

    eff_dir = patch_body.get("direction") or {}
    if (
        eff_dir.get("lanToWan")
        and not eff_dir.get("lanToLan")
        and not eff_dir.get("wanInIds")
        and not eff_dir.get("vpnInIds")
        and int(patch_body.get("destinationType", -1)) == 0
    ):
        raise OmadaError(
            "LAN->WAN gateway ACL rules do not accept destination.type='network' (-33601)",
            code=-33601,
        )

    _check_acl_safety(
        client,
        policy=int(patch_body.get("policy", 1)),
        status=bool(patch_body.get("status")),
        source_type=int(patch_body.get("sourceType", -1)),
        source_ids=[str(x) for x in (patch_body.get("sourceIds") or [])],
        dest_type=int(patch_body.get("destinationType", -1)),
        dest_ids=[str(x) for x in (patch_body.get("destinationIds") or [])],
        direction=eff_dir,
        networks=networks,
        groups=groups,
    )

    diff = {k: {"before": target_rule.get(k), "after": patch_body.get(k)} for k in dict.fromkeys(changed_keys)}
    warnings = [_ACL_DISPATCH_NOTES]
    if acl_disable is not None:
        warnings.append(f"observed controller aclDisable={acl_disable!r} (advisory only)")
    expected = {k: patch_body[k] for k in dict.fromkeys(changed_keys)}

    if dryRun:
        return _dry_run_result(
            tool_name="update_gateway_acl",
            target_id=target_id,
            before=target_rule,
            after=patch_body,
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    endpoint = f"sites/{site.site_id}/setting/firewall/acls/{target_id}?type=0"

    def _read_back() -> Optional[Dict[str, Any]]:
        _, live_rules = _fetch_acls(client, site)
        return next((dict(r) for r in live_rules if str(r.get("id")) == target_id), None)

    def _verify(_before: Any, after_rule: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_rule, Mapping):
            return False, f"ACL rule {target_id} missing on read-back"
        ok, reason = _match_fields(after_rule, expected)
        if not ok:
            return False, reason
        ignore = list(expected.keys())
        if "syslog" in expected:
            ignore.append("existSyslog")
        drifts = _diff_mappings(target_rule, after_rule, ignore_keys=ignore)
        if drifts:
            return False, "unexpected field drift on ACL rule: " + ", ".join(drifts)
        return True, None

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
        fresh = _read_back()
        if fresh is None:
            return False, None, None
        ok, _ = _verify(target_rule, fresh)
        if ok:
            return True, None, None
        re_body = copy.deepcopy(fresh)
        for k, v in expected.items():
            re_body[k] = copy.deepcopy(v)
        return False, re_body, fresh

    write_res = client.write(
        endpoint,
        method="PUT",
        data=patch_body,
        tool_name="update_gateway_acl",
        target=target_id,
        before=target_rule,
        snapshot_payload=target_rule,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(expected.keys()),
    )
    return _committed_result(
        tool_name="update_gateway_acl",
        target_id=target_id,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )


def delete_gateway_acl(
    client: OmadaClient,
    rule: str,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Delete a gateway ACL rule (``DELETE setting/firewall/acls/{id}?type=0``)."""
    site = _site(client)
    acl_disable, rules = _fetch_acls(client, site)
    target_rule = _resolve_by_id_or_name(rules, rule, label="gateway ACL rule")
    target_id = str(target_rule["id"])
    warnings = [_ACL_DISPATCH_NOTES]
    if acl_disable is not None:
        warnings.append(f"observed controller aclDisable={acl_disable!r} (advisory only)")
    return _delete_entity(
        client,
        tool_name="delete_gateway_acl",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/firewall/acls/{target_id}?type=0",
        before=target_rule,
        snapshot_payload=target_rule,
        fetch_all=lambda: _fetch_acls(client, site)[1],
        match_fn=lambda row: str(row.get("id")) == target_id,
        rollback=None,
        warnings=warnings,
        dry_run=dryRun,
        confirm=confirm,
        label="aclRule",
    )


def delete_ip_group(
    client: OmadaClient,
    group: str,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Delete an unreferenced IPv4 IP group (``DELETE setting/profiles/groups/0/{id}``)."""
    site = _site(client)
    groups = _fetch_groups(client, site)
    target_grp = _find_ip_group(groups, group)
    target_id = _group_id(target_grp)
    if bool(target_grp.get("default")) or str(target_grp.get("name", "")) == "IPGroup_Any":
        raise OmadaError(f"refusing to delete built-in default IP group {target_grp.get('name') or target_id!r}")

    _, rules = _fetch_acls(client, site)
    refs = [
        str(r.get("name") or r.get("id"))
        for r in rules
        if target_id in [str(x) for x in (r.get("sourceIds") or [])]
        or target_id in [str(x) for x in (r.get("destinationIds") or [])]
    ]
    if refs:
        raise OmadaError(
            f"cannot delete IP group {target_grp.get('name')!r}: referenced by ACL rule(s) {', '.join(refs)} (-33717)",
            code=-33717,
            hint="update or delete the referencing ACL rule(s) first, or use replace_ip_group to update members",
        )

    before_out = _normalize_group_output(target_grp)
    return _delete_entity(
        client,
        tool_name="delete_ip_group",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/profiles/groups/0/{target_id}",
        before=before_out,
        snapshot_payload=before_out,
        fetch_all=lambda: _fetch_groups(client, site),
        match_fn=lambda row: _group_id(row) == target_id,
        rollback=None,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="ipGroup",
    )


# -- 17, 18, 19: Wi-Fi SSID CRUD (secret-redacted) --------------------------

def _parse_ssid_bands(bands: Any) -> int:
    if isinstance(bands, int) and not isinstance(bands, bool):
        if 1 <= bands <= 7:
            return bands
        raise OmadaError(f"band bitmask {bands} must be between 1 and 7")
    if isinstance(bands, str):
        tokens = [t.strip().lower() for t in re.split(r"[,+|/\s]+", bands) if t.strip()]
    elif isinstance(bands, (list, tuple)):
        tokens = [str(t or "").strip().lower() for t in bands if str(t or "").strip()]
    else:
        raise OmadaError("bands must be e.g. ['2g', '5g'] or bitmask 1..7")
    mask = 0
    for tok in tokens:
        if tok == "all":
            mask |= 7
        elif tok in _SSID_BAND_BITS:
            mask |= _SSID_BAND_BITS[tok]
        else:
            raise OmadaError(f"unknown Wi-Fi band {tok!r}; expected '2g', '5g', or '6g'")
    if mask == 0:
        raise OmadaError("at least one Wi-Fi band must be enabled")
    return mask


def _parse_ssid_security(security: str, psk: Optional[str]) -> Tuple[int, Optional[Dict[str, Any]]]:
    mode = str(security or "wpa2-psk").strip().lower()
    if mode in ("open", "none"):
        return 0, None
    key_text = str(psk or "")
    if not (8 <= len(key_text) <= 63):
        raise OmadaError("WPA-PSK passphrase must be between 8 and 63 characters")
    version_map = {
        "wpa-psk": 3,
        "wpa2-psk": 2,
        "wpa-wpa2-psk": 3,
        "wpa3-sae": 4,
        "wpa3": 4,
    }
    if mode not in version_map:
        raise OmadaError(
            f"unsupported SSID security {security!r}; expected 'open', 'wpa2-psk', 'wpa-wpa2-psk', or 'wpa3-sae'",
        )
    return 3, {
        "securityKey": key_text,
        "encryptionPsk": 3,
        "versionPsk": version_map[mode],
        "gikRekeyPskEnable": False,
    }


def _parse_pmf_mode(pmf: Any) -> int:
    if isinstance(pmf, int) and not isinstance(pmf, bool) and pmf in (1, 2, 3):
        return pmf
    text = str(pmf or "disable").strip().lower()
    mapping = {"mandatory": 1, "required": 1, "1": 1, "capable": 2, "optional": 2, "2": 2, "disable": 3, "off": 3, "3": 3}
    if text not in mapping:
        raise OmadaError(f"invalid pmfMode {pmf!r}; expected 'mandatory' (1), 'capable' (2), or 'disable' (3)")
    return mapping[text]


def _resolve_wlan_group(groups: Sequence[Mapping[str, Any]], selector: Optional[str]) -> Dict[str, Any]:
    if not groups:
        raise OmadaError("site has no WLAN groups")
    if selector is not None and str(selector).strip():
        return _resolve_by_id_or_name(groups, str(selector), label="WLAN group")
    if len(groups) == 1:
        return dict(groups[0])
    default = next((dict(g) for g in groups if str(g.get("name", "")).lower() == "default"), None)
    if default is not None:
        return default
    names = ", ".join(str(g.get("name") or g.get("id")) for g in groups)
    raise OmadaError(f"multiple WLAN groups exist ({names}); specify wlanGroup explicitly")


def create_ssid(
    client: OmadaClient,
    name: str,
    wlanGroup: Optional[str] = None,
    bands: Any = None,
    security: str = "wpa2-psk",
    psk: Optional[str] = None,
    vlanId: Optional[int] = None,
    guest: bool = False,
    broadcast: bool = True,
    pmfMode: Any = "disable",
    enable11r: bool = False,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a Wi-Fi SSID in a WLAN group with strict PSK redaction in snapshots/output."""
    ssid_name = str(name or "").strip()
    if not ssid_name:
        raise OmadaError("SSID name must be non-empty")
    band_mask = _parse_ssid_bands(["2g", "5g"] if bands is None else bands)
    sec_code, psk_cfg = _parse_ssid_security(security, psk)
    pmf_int = _parse_pmf_mode(pmfMode)
    if sec_code != 0 and psk_cfg and psk_cfg.get("versionPsk") == 4 and pmf_int != 1:
        pmf_int = 1  # WPA3 requires PMF mandatory

    vlan_setting: Dict[str, Any]
    if vlanId is not None:
        vid = _validate_vlan_id(vlanId)
        vlan_setting = {"mode": 1, "customConfig": {"bridgeVlan": vid}, "currentVlanId": vid}
    else:
        vlan_setting = {"mode": 0, "customConfig": {"bridgeVlan": 1}, "currentVlanId": None}

    _require_confirm("create_ssid", ssid_name, dryRun, confirm)

    site = _site(client)
    wlan_groups = _fetch_wlan_groups(client, site)
    target_wlan = _resolve_wlan_group(wlan_groups, wlanGroup)
    wlan_id = str(target_wlan["id"])
    existing_ssids = _fetch_ssids(client, site, wlan_id)
    if any(str(s.get("name", "")).strip() == ssid_name for s in existing_ssids):
        raise OmadaError(f"SSID {ssid_name!r} already exists in WLAN group {target_wlan.get('name')!r}", code=-33239)

    body: Dict[str, Any] = {
        "name": ssid_name,
        "band": band_mask,
        "guestNetEnable": bool(guest),
        "security": sec_code,
        "broadcast": bool(broadcast),
        "vlanSetting": vlan_setting,
        "rateAndBeaconCtrl": {"rate2gCtrl": 0, "rate5gCtrl": 0, "rate6gCtrl": 0},
        "pmfMode": pmf_int,
        "enable11r": bool(enable11r),
        "greEnable": False,
        "mloEnable": False,
        "wlanScheduleEnable": False,
        "rateLimit": {"downLimitEnable": False, "upLimitEnable": False},
        "ssidRateLimit": {"downLimitEnable": False, "upLimitEnable": False},
        "macFilterEnable": False,
        "multiCastSetting": {
            "multiCastEnable": False,
            "arpCastEnable": False,
            "ipv6CastEnable": False,
            "filterEnable": False,
            "ipv6FilterEnable": False,
        },
        "dhcpOption82": {"dhcpEnable": False},
        "deviceType": 1,
        "prohibitWifiShareEnable": False,
    }
    if psk_cfg is not None:
        body["pskSetting"] = psk_cfg

    redacted_after = _redact_ssid(body)
    diff = {"ssid": {"before": None, "after": redacted_after}}
    warnings = []
    if sec_code == 0:
        warnings.append("creating an OPEN Wi-Fi SSID without encryption")

    if dryRun:
        return _dry_run_result(
            tool_name="create_ssid",
            target_id=ssid_name,
            before=None,
            after=redacted_after,
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    endpoint = f"sites/{site.site_id}/setting/wlans/{wlan_id}/ssids"

    def _read_back() -> List[Dict[str, Any]]:
        return _fetch_ssids(client, site, wlan_id)

    expected = {"name": ssid_name, "band": band_mask, "guestNetEnable": bool(guest), "broadcast": bool(broadcast), "security": sec_code}

    def _verify(_before: Any, rows_now: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(rows_now, list):
            return False, "SSID read-back did not return a list"
        found = next((s for s in rows_now if str(s.get("name")) == ssid_name), None)
        if found is None:
            return False, f"created SSID {ssid_name!r} missing on read-back"
        return _match_fields(found, expected)

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
        ok, _ = _verify(None, _read_back())
        return ok, None, None

    write_res = client.write(
        endpoint,
        method="POST",
        data=body,
        tool_name="create_ssid",
        target=ssid_name,
        before=None,
        snapshot_payload={"wlanGroup": target_wlan.get("name"), "existingSsids": [_redact_ssid(s) for s in existing_ssids]},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(expected.keys()),
    )
    created_raw = next((s for s in write_res["after"] if str(s.get("name")) == ssid_name), body)
    created_safe = _redact_ssid(created_raw)
    rollback = {
        "tool": "delete_ssid",
        "arguments": {"ssid": str(created_raw.get("id") or ssid_name), "wlanGroup": wlan_id, "dryRun": True},
    }
    return _committed_result(
        tool_name="create_ssid",
        target_id=ssid_name,
        before=None,
        after=created_safe,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def update_ssid(
    client: OmadaClient,
    ssid: str,
    wlanGroup: Optional[str] = None,
    name: Optional[str] = None,
    bands: Any = None,
    psk: Optional[str] = None,
    vlanId: Optional[int] = None,
    clearVlan: bool = False,
    guest: Optional[bool] = None,
    broadcast: Optional[bool] = None,
    pmfMode: Any = None,
    enable11r: Optional[bool] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Update an SSID via full-object PATCH (``setting/wlans/{wlanId}/ssids/{ssidId}``)."""
    if all(
        v is None
        for v in (name, bands, psk, vlanId, guest, broadcast, pmfMode, enable11r)
    ) and not clearVlan:
        raise OmadaError("specify at least one SSID setting to update")

    site = _site(client)
    wlan_groups = _fetch_wlan_groups(client, site)
    target_wlan = _resolve_wlan_group(wlan_groups, wlanGroup)
    wlan_id = str(target_wlan["id"])
    ssids = _fetch_ssids(client, site, wlan_id)
    target_raw = _resolve_by_id_or_name(ssids, ssid, label="SSID")
    ssid_id = str(target_raw["id"])
    _require_confirm("update_ssid", ssid_id, dryRun, confirm)

    patch_body = {k: copy.deepcopy(v) for k, v in target_raw.items() if k not in _SSID_SERVER_ONLY_KEYS}
    diff: Dict[str, Any] = {}
    expected: Dict[str, Any] = {}

    if name is not None:
        clean_name = str(name).strip()
        if not clean_name:
            raise OmadaError("SSID name must be non-empty")
        diff["name"] = {"before": target_raw.get("name"), "after": clean_name}
        patch_body["name"] = clean_name
        expected["name"] = clean_name
    if bands is not None:
        band_mask = _parse_ssid_bands(bands)
        diff["band"] = {"before": target_raw.get("band"), "after": band_mask}
        patch_body["band"] = band_mask
        expected["band"] = band_mask
    if guest is not None:
        diff["guestNetEnable"] = {"before": target_raw.get("guestNetEnable"), "after": bool(guest)}
        patch_body["guestNetEnable"] = bool(guest)
        expected["guestNetEnable"] = bool(guest)
    if broadcast is not None:
        diff["broadcast"] = {"before": target_raw.get("broadcast"), "after": bool(broadcast)}
        patch_body["broadcast"] = bool(broadcast)
        expected["broadcast"] = bool(broadcast)
    if pmfMode is not None:
        pmf_int = _parse_pmf_mode(pmfMode)
        diff["pmfMode"] = {"before": target_raw.get("pmfMode"), "after": pmf_int}
        patch_body["pmfMode"] = pmf_int
        expected["pmfMode"] = pmf_int
    if enable11r is not None:
        diff["enable11r"] = {"before": target_raw.get("enable11r"), "after": bool(enable11r)}
        patch_body["enable11r"] = bool(enable11r)
        expected["enable11r"] = bool(enable11r)
    if clearVlan:
        new_vs = {"mode": 0, "customConfig": {"bridgeVlan": 1}, "currentVlanId": None}
        diff["vlanSetting"] = {"before": target_raw.get("vlanSetting"), "after": new_vs}
        patch_body["vlanSetting"] = new_vs
    elif vlanId is not None:
        vid = _validate_vlan_id(vlanId)
        new_vs = {"mode": 1, "customConfig": {"bridgeVlan": vid}, "currentVlanId": vid}
        diff["vlanSetting"] = {"before": target_raw.get("vlanSetting"), "after": new_vs}
        patch_body["vlanSetting"] = new_vs
    if psk is not None:
        if int(patch_body.get("security", 0)) == 0:
            raise OmadaError("cannot set psk on an open SSID")
        if not (8 <= len(str(psk)) <= 63):
            raise OmadaError("WPA-PSK passphrase must be 8..63 characters")
        cur_psk = copy.deepcopy(patch_body.get("pskSetting") or {"encryptionPsk": 3, "versionPsk": 2, "gikRekeyPskEnable": False})
        cur_psk["securityKey"] = str(psk)
        patch_body["pskSetting"] = cur_psk
        diff["pskUpdated"] = {"before": False, "after": True}

    before_safe = _redact_ssid(target_raw)
    after_safe = _redact_ssid(patch_body)
    if dryRun:
        return _dry_run_result(
            tool_name="update_ssid",
            target_id=ssid_id,
            before=before_safe,
            after=after_safe,
            diff=diff,
            warnings=[],
            rollback=None,
        )

    endpoint = f"sites/{site.site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}"

    def _read_back() -> Optional[Dict[str, Any]]:
        return next((dict(s) for s in _fetch_ssids(client, site, wlan_id) if str(s.get("id")) == ssid_id), None)

    def _verify(_before: Any, after_row: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_row, Mapping):
            return False, f"SSID {ssid_id} missing on read-back"
        ok, reason = _match_fields(after_row, expected)
        if not ok:
            return False, reason
        if clearVlan or vlanId is not None:
            want_vid = None if clearVlan else _validate_vlan_id(vlanId)
            got_vs = after_row.get("vlanSetting") or {}
            if clearVlan and got_vs.get("mode") != 0:
                return False, f"vlanSetting.mode expected 0, got {got_vs.get('mode')!r}"
            if vlanId is not None and got_vs.get("currentVlanId") != want_vid and (got_vs.get("customConfig") or {}).get("bridgeVlan") != want_vid:
                return False, f"vlanId expected {want_vid}, got {got_vs!r}"
        return True, None

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
        live = _read_back()
        if live is None:
            return False, None, None
        ok, _ = _verify(target_raw, live)
        if ok:
            return True, None, None
        re_body = {k: copy.deepcopy(v) for k, v in live.items() if k not in _SSID_SERVER_ONLY_KEYS}
        for k in expected:
            re_body[k] = copy.deepcopy(patch_body[k])
        if psk is not None and "pskSetting" in patch_body:
            re_body["pskSetting"] = copy.deepcopy(patch_body["pskSetting"])
        if clearVlan or vlanId is not None:
            re_body["vlanSetting"] = copy.deepcopy(patch_body["vlanSetting"])
        return False, re_body, _redact_ssid(live)

    write_res = client.write(
        endpoint,
        method="PATCH",
        data=patch_body,
        tool_name="update_ssid",
        target=ssid_id,
        before=before_safe,
        snapshot_payload=before_safe,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()),
    )
    return _committed_result(
        tool_name="update_ssid",
        target_id=ssid_id,
        before=write_res["before"],
        after=_redact_ssid(write_res["after"]),
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=None,
    )


def delete_ssid(
    client: OmadaClient,
    ssid: str,
    wlanGroup: Optional[str] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Delete an SSID from a WLAN group (``DELETE setting/wlans/{wlanId}/ssids/{ssidId}``)."""
    site = _site(client)
    wlan_groups = _fetch_wlan_groups(client, site)
    target_wlan = _resolve_wlan_group(wlan_groups, wlanGroup)
    wlan_id = str(target_wlan["id"])
    ssids = _fetch_ssids(client, site, wlan_id)
    target_raw = _resolve_by_id_or_name(ssids, ssid, label="SSID")
    ssid_id = str(target_raw["id"])
    before_safe = _redact_ssid(target_raw)
    warnings = ["this is the last SSID in the WLAN group"] if len(ssids) <= 1 else []
    return _delete_entity(
        client,
        tool_name="delete_ssid",
        target_id=ssid_id,
        endpoint=f"sites/{site.site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}",
        before=before_safe,
        snapshot_payload=before_safe,
        fetch_all=lambda: _fetch_ssids(client, site, wlan_id),
        match_fn=lambda row: str(row.get("id")) == ssid_id,
        rollback=None,
        warnings=warnings,
        dry_run=dryRun,
        confirm=confirm,
        label="ssid",
    )


# -- 20-26: Port forwarding, static routes, mDNS, UPnP ----------------------

def upsert_port_forward(
    client: OmadaClient,
    name: str,
    externalPort: str,
    forwardIp: str,
    forwardPort: str,
    id: Optional[str] = None,
    protocol: Any = "all",
    status: bool = True,
    fromIp: Optional[str] = None,
    interfaceWanPortIds: Optional[List[str]] = None,
    dmz: bool = False,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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
    before_row: Optional[Dict[str, Any]] = None
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

    body: Dict[str, Any] = {
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

    def _read_back() -> Optional[Dict[str, Any]]:
        rows_now = _fetch_port_forwards(client, site)
        if is_update:
            return next((dict(r) for r in rows_now if str(r.get("id")) == target_id), None)
        return next((dict(r) for r in rows_now if str(r.get("name")) == rule_name), None)

    def _verify(_before: Any, after_row: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_row, Mapping):
            return False, f"port forward rule {target_id!r} missing on read-back"
        return _match_fields(after_row, expected)

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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
    id: Optional[str] = None,
    interfaceId: Optional[str] = None,
    routeType: int = 0,
    metric: int = 1,
    status: bool = True,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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
    before_row: Optional[Dict[str, Any]] = None
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

    body: Dict[str, Any] = {
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

    def _read_back() -> Optional[Dict[str, Any]]:
        rows_now = _fetch_static_routes(client, site)
        if is_update:
            return next((dict(r) for r in rows_now if str(r.get("id")) == target_id), None)
        return next((dict(r) for r in rows_now if str(r.get("name")) == route_name), None)

    def _verify(_before: Any, after_row: Any) -> Tuple[bool, Optional[str]]:
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

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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


def upsert_mdns_rule(
    client: OmadaClient,
    name: str,
    profiles: List[str],
    serviceNetworks: List[str],
    clientNetworks: List[str],
    id: Optional[str] = None,
    ruleType: str = "gateway",
    status: bool = True,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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
    before_row: Optional[Dict[str, Any]] = None
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

    body: Dict[str, Any] = {"name": rule_name, "status": bool(status), "type": rtype}
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

    expected: Dict[str, Any] = {"name": rule_name, "status": bool(status), "type": rtype}
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

    def _read_back() -> Optional[Dict[str, Any]]:
        rows_now = _fetch_mdns_rules(client, site)
        if is_update:
            return next((dict(r) for r in rows_now if str(r.get("id")) == target_id), None)
        return next((dict(r) for r in rows_now if str(r.get("name")) == rule_name), None)

    def _verify(_before: Any, after_row: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_row, Mapping):
            return False, f"mDNS rule {target_id!r} missing on read-back"
        return _match_fields(after_row, expected)

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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


def set_upnp(
    client: OmadaClient,
    enable: bool,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Enable or disable UPnP on the site gateway (``PUT setting/upnp``)."""
    site = _site(client)
    target_id = site.site_id
    _require_confirm("set_upnp", target_id, dryRun, confirm)
    before_raw = client.api_result(f"sites/{site.site_id}/setting/upnp")
    before_obj = dict(before_raw) if isinstance(before_raw, Mapping) else {"enable": False}
    desired = bool(enable)
    diff = {"enable": {"before": bool(before_obj.get("enable", False)), "after": desired}}
    after_preview = {**before_obj, "enable": desired}
    rollback = {
        "tool": "set_upnp",
        "arguments": {"enable": bool(before_obj.get("enable", False)), "dryRun": True},
    }
    if dryRun:
        return _dry_run_result(
            tool_name="set_upnp",
            target_id=target_id,
            before=before_obj,
            after=after_preview,
            diff=diff,
            warnings=[],
            rollback=rollback,
        )

    endpoint = f"sites/{site.site_id}/setting/upnp"

    def _read_back() -> Dict[str, Any]:
        raw = client.api_result(endpoint)
        return dict(raw) if isinstance(raw, Mapping) else {}

    def _verify(_before: Any, after_now: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_now, Mapping):
            return False, "UPnP read-back failed"
        if bool(after_now.get("enable")) != desired:
            return False, f"UPnP enable expected {desired!r}, got {after_now.get('enable')!r}"
        return True, None

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
        live = _read_back()
        ok, _ = _verify(before_obj, live)
        return ok, {"enable": desired}, live

    write_res = client.write(
        endpoint,
        method="PUT",
        data={"enable": desired},
        tool_name="set_upnp",
        target=target_id,
        before=before_obj,
        snapshot_payload=before_obj,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["enable"],
    )
    return _committed_result(
        tool_name="set_upnp",
        target_id=target_id,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


# -- 27-31: Client & Device operational controls ----------------------------

def _lookup_client_record(client: OmadaClient, site: SiteInfo, norm_mac: str, omada_mac: str) -> Dict[str, Any]:
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
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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

    def _read_back() -> Dict[str, Any]:
        return _lookup_client_record(client, site, norm_mac, omada_mac)

    def _verify(_before: Any, after_now: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_now, Mapping):
            return False, "client read-back failed"
        if "blocked" in after_now and bool(after_now["blocked"]) != desired:
            return False, f"client blocked expected {desired!r}, got {after_now.get('blocked')!r}"
        return True, None

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
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

    def _read_back() -> Dict[str, Any]:
        got = client.api_result(endpoint)
        return dict(got) if isinstance(got, Mapping) else {}

    def _verify(_before: Any, after_now: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(after_now, Mapping):
            return False, "client read-back failed"
        if str(after_now.get("name", "")) != new_name:
            return False, f"client name expected {new_name!r}, got {after_now.get('name')!r}"
        return True, None

    def _reauth_prepare() -> Tuple[bool, Optional[Dict[str, Any]], Any]:
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


def update_device(
    client: OmadaClient,
    mac: str,
    name: Optional[str] = None,
    ledSetting: Any = None,
    locate: Optional[bool] = None,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Rename an adopted AP/switch/gateway, set LED mode, or toggle LED locator blink."""
    if name is None and ledSetting is None and locate is None:
        raise OmadaError("specify at least one of name, ledSetting, or locate")

    site = _site(client)
    devices = _fetch_devices(client, site)
    target_dev = _resolve_by_id_or_name(
        devices,
        mac,
        label="device",
        id_key="mac",
        name_key="name",
    )
    dev_mac = _omada_mac(str(target_dev["mac"]))
    norm_mac = _normalize_mac(dev_mac)
    _require_confirm("update_device", norm_mac, dryRun, confirm)

    dev_type = str(target_dev.get("type") or "").strip().lower()
    dev_prefix = _DEV_ENDPOINT_PREFIX.get(dev_type)
    if (name is not None or ledSetting is not None) and dev_prefix is None:
        raise OmadaError(f"unsupported device type {dev_type!r} for general settings PATCH")

    general_patch: Dict[str, Any] = {}
    diff: Dict[str, Any] = {}
    if name is not None:
        clean_name = str(name).strip()
        if not clean_name:
            raise OmadaError("device name must be non-empty")
        general_patch["name"] = clean_name
        diff["name"] = {"before": target_dev.get("name"), "after": clean_name}
    if ledSetting is not None:
        led_key = str(ledSetting).strip().lower()
        if led_key not in _LED_MODES:
            raise OmadaError(f"invalid ledSetting {ledSetting!r}; expected 'off' (0), 'on' (1), or 'use_site' (2)")
        led_val = _LED_MODES[led_key]
        general_patch["ledSetting"] = led_val
        diff["ledSetting"] = {"before": target_dev.get("ledSetting"), "after": led_val}
    if locate is not None:
        diff["locateEnable"] = {"before": target_dev.get("locateEnable"), "after": bool(locate)}

    before_summary = {
        "mac": target_dev.get("mac"),
        "name": target_dev.get("name"),
        "type": dev_type,
        "ledSetting": target_dev.get("ledSetting"),
        "locateEnable": target_dev.get("locateEnable"),
    }
    after_preview = {
        **before_summary,
        **general_patch,
        **({"locateEnable": bool(locate)} if locate is not None else {}),
    }

    if dryRun:
        return _dry_run_result(
            tool_name="update_device",
            target_id=norm_mac,
            before=before_summary,
            after=after_preview,
            diff=diff,
            warnings=[],
            rollback=None,
        )

    def _read_back_dev() -> Optional[Dict[str, Any]]:
        for d in _fetch_devices(client, site):
            if _normalize_mac(d.get("mac", "")) == norm_mac:
                return dict(d)
        return None

    last_res: Optional[Dict[str, Any]] = None
    if general_patch:
        def _verify_general(_b: Any, a: Any) -> Tuple[bool, Optional[str]]:
            if not isinstance(a, Mapping):
                return False, f"device {norm_mac} missing on read-back"
            return _match_fields(a, general_patch)

        last_res = client.write(
            f"sites/{site.site_id}/{dev_prefix}/{dev_mac}",
            method="PATCH",
            data=general_patch,
            tool_name="update_device",
            target=norm_mac,
            before=before_summary,
            snapshot_payload=target_dev,
            read_back=_read_back_dev,
            verify_fn=_verify_general,
            reauth_prepare=lambda: (_verify_general(None, _read_back_dev())[0], general_patch, before_summary),
            fields_changed=sorted(general_patch.keys()),
        )

    if locate is not None:
        loc_val = bool(locate)
        def _verify_loc(_b: Any, a: Any) -> Tuple[bool, Optional[str]]:
            if not isinstance(a, Mapping):
                return False, f"device {norm_mac} missing on read-back"
            if "locateEnable" in a and bool(a["locateEnable"]) != loc_val:
                return False, f"locateEnable expected {loc_val!r}, got {a.get('locateEnable')!r}"
            return True, None

        last_res = client.write(
            f"sites/{site.site_id}/cmd/devices/{dev_mac}/locate",
            method="POST",
            data={"locateEnable": loc_val},
            tool_name="update_device",
            target=norm_mac,
            before=before_summary,
            snapshot_payload=target_dev,
            read_back=_read_back_dev,
            verify_fn=_verify_loc,
            reauth_prepare=lambda: (_verify_loc(None, _read_back_dev())[0], {"locateEnable": loc_val}, before_summary),
            fields_changed=["locateEnable"],
        )

    after_dev = (last_res or {}).get("after") or after_preview
    after_summary = {
        "mac": after_dev.get("mac"),
        "name": after_dev.get("name"),
        "type": dev_type,
        "ledSetting": after_dev.get("ledSetting"),
        "locateEnable": after_dev.get("locateEnable"),
    }
    return _committed_result(
        tool_name="update_device",
        target_id=norm_mac,
        before=before_summary,
        after=after_summary,
        diff=diff,
        snapshot=(last_res or {}).get("snapshot"),
        warnings=[],
        rollback=None,
    )


def reboot_device(
    client: OmadaClient,
    mac: str,
    dryRun: bool = True,
    confirm: Optional[str] = None,
) -> Dict[str, Any]:
    """Reboot an adopted Omada device (``POST cmd/devices/{MAC}/reboot``)."""
    site = _site(client)
    devices = _fetch_devices(client, site)
    target_dev = _resolve_by_id_or_name(devices, mac, label="device", id_key="mac", name_key="name")
    dev_mac = _omada_mac(str(target_dev["mac"]))
    norm_mac = _normalize_mac(dev_mac)
    _require_confirm("reboot_device", norm_mac, dryRun, confirm)

    dev_type = str(target_dev.get("type") or "").lower()
    warnings = [
        f"disruptive operation: rebooting {dev_type or 'device'} {target_dev.get('name') or norm_mac!r} "
        "drops traffic during restart; confirm maintenance window before dryRun=false",
    ]
    if dev_type == "gateway":
        warnings.append("rebooting the gateway interrupts WAN internet access for the entire site")

    summary = {
        "mac": target_dev.get("mac"),
        "name": target_dev.get("name"),
        "type": dev_type,
        "model": target_dev.get("showModel") or target_dev.get("model"),
        "statusCategory": target_dev.get("statusCategory"),
    }
    diff = {"action": {"before": "running", "after": "reboot_requested"}}
    if dryRun:
        return _dry_run_result(
            tool_name="reboot_device",
            target_id=norm_mac,
            before=summary,
            after={**summary, "rebootTriggered": True},
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    write_res = client.write(
        f"sites/{site.site_id}/cmd/devices/{dev_mac}/reboot",
        method="POST",
        data={},
        tool_name="reboot_device",
        target=norm_mac,
        before=summary,
        snapshot_payload=target_dev,
        fields_changed=["reboot"],
    )
    return _committed_result(
        tool_name="reboot_device",
        target_id=norm_mac,
        before=write_res["before"],
        after={**summary, "rebootTriggered": True},
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )
