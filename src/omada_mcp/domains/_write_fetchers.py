"""Write domain module: _write_fetchers."""

from __future__ import annotations

import copy
import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError, SiteInfo
from ._common import ACL_TYPE_LABELS, ACL_TYPE_MAP
from ._write_common import CLIENT_VOLATILE_KEYS, _normalize_mac, _unwrap_rows
from ._write_safety import _network_subnet_and_gw


def _omada_mac(value: str) -> str:
    """Validate 12 hex digits and format uppercase hyphenated ``AA-BB-CC-DD-EE-FF``."""
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).upper()
    if len(cleaned) == 12 and all(ch in "0123456789ABCDEF" for ch in cleaned):
        return "-".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    raise OmadaError(
        f"invalid MAC address {value!r}",
        hint="expected 12 hex digits (e.g. aa:bb:cc:dd:ee:ff or AA-BB-CC-DD-EE-FF)",
    )


def _fetch_devices(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/devices")
    return rows


def _fetch_insight_clients(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
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


def _fetch_clients_filtered(client: OmadaClient, site: SiteInfo, *, active: bool | None) -> list[dict[str, Any]]:
    if active is None:
        rows_active, _ = client.paginate(f"sites/{site.site_id}/clients?filters.active=true", max_pages=20)
        rows_inactive, _ = client.paginate(f"sites/{site.site_id}/clients?filters.active=false", max_pages=20)
        by_mac: dict[str, dict[str, Any]] = {}
        for row in rows_inactive + rows_active:
            mac = _normalize_mac(row.get("mac", ""))
            if mac:
                by_mac[mac] = row
        return list(by_mac.values())
    flag = "true" if active else "false"
    rows, _ = client.paginate(f"sites/{site.site_id}/clients?filters.active={flag}", max_pages=20)
    return rows


def _fetch_lan_collection(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/lan/networks")
    return rows


def _fetch_lan_interfaces(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/lan/networks/interface")
    return rows


def _fetch_groups(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/profiles/groups")
    return rows


def _parse_acl_type(acl_type: Any) -> int:
    if isinstance(acl_type, bool):
        raise OmadaError(f"invalid aclType {acl_type!r}")
    if isinstance(acl_type, int) and acl_type in ACL_TYPE_LABELS:
        return acl_type
    raw = str(acl_type or "").strip().lower()
    if raw in ("0", "1", "2"):
        return int(raw)
    if raw in ACL_TYPE_MAP:
        return ACL_TYPE_MAP[raw]
    raise OmadaError(
        f"invalid aclType {acl_type!r}",
        hint="expected 'gateway' (0), 'switch' (1), or 'eap' (2)",
    )


def _fetch_typed_acls_with_meta(
    client: OmadaClient,
    site: SiteInfo,
    acl_type: int,
) -> tuple[bool | None, list[dict[str, Any]]]:
    rows, meta = client.paginate(f"sites/{site.site_id}/setting/firewall/acls?type={int(acl_type)}")
    if isinstance(meta, Mapping):
        acl_disable = meta.get("aclDisable")
        return (bool(acl_disable) if acl_disable is not None else None), rows
    return None, rows


def _fetch_acls(client: OmadaClient, site: SiteInfo) -> tuple[bool | None, list[dict[str, Any]]]:
    return _fetch_typed_acls_with_meta(client, site, 0)


def _find_acl_in_list(
    rules: Sequence[Mapping[str, Any]],
    needle: str,
    *,
    label: str,
) -> dict[str, Any] | None:
    lower = needle.lower()
    exact_id = [dict(r) for r in rules if str(r.get("id", "")).strip().lower() == lower]
    if len(exact_id) == 1:
        return exact_id[0]
    if len(exact_id) > 1:
        raise OmadaError(f"{label} {needle!r} matched multiple rules by ID")
    by_name = [dict(r) for r in rules if str(r.get("name", "")).strip().lower() == lower]
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        ids = ", ".join(str(r.get("id") or "?") for r in by_name)
        raise OmadaError(f"{label} {needle!r} matched multiple rules ({ids}); specify rule id")
    return None


def _resolve_acl_rule(
    client: OmadaClient,
    site: SiteInfo,
    rule: str,
    *,
    acl_type: Any = None,
) -> tuple[int, bool | None, dict[str, Any]]:
    """Resolve an ACL rule by ID or exact name across gateway (0), switch (1), or EAP (2)."""
    needle = str(rule or "").strip()
    if not needle:
        raise OmadaError("ACL rule identifier must be non-empty")

    if acl_type is not None:
        t = _parse_acl_type(acl_type)
        label = f"{ACL_TYPE_LABELS[t]} ACL rule"
        acl_disable, rules = _fetch_typed_acls_with_meta(client, site, t)
        found = _find_acl_in_list(rules, needle, label=label)
        if found is None:
            raise OmadaError(f"no {label} matches {rule!r}")
        found.setdefault("type", t)
        return t, acl_disable, found

    acl_disable0, rules0 = _fetch_typed_acls_with_meta(client, site, 0)
    found0 = _find_acl_in_list(rules0, needle, label="gateway ACL rule")
    if found0 is not None:
        found0.setdefault("type", 0)
        return 0, acl_disable0, found0

    matches: list[tuple[int, bool | None, dict[str, Any]]] = []
    for t in (1, 2):
        try:
            acl_disable_t, rules_t = _fetch_typed_acls_with_meta(client, site, t)
        except OmadaError as exc:
            if exc.code in (-1600, -1001, -1007):
                continue
            raise
        found_t = _find_acl_in_list(rules_t, needle, label=f"{ACL_TYPE_LABELS[t]} ACL rule")
        if found_t is not None:
            found_t.setdefault("type", t)
            matches.append((t, acl_disable_t, found_t))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        scopes = ", ".join(ACL_TYPE_LABELS[t] for t, _, _ in matches)
        raise OmadaError(
            f"ACL rule {rule!r} matched in multiple scopes ({scopes}); specify aclType",
            hint="pass aclType='gateway', aclType='switch', or aclType='eap'",
        )
    raise OmadaError(f"no ACL rule matches {rule!r}")


def _fetch_wan_networks(client: OmadaClient, site: SiteInfo) -> dict[str, Any]:
    res = client.api_result(f"sites/{site.site_id}/setting/wan/networks")
    return dict(res) if isinstance(res, Mapping) else {}


def _fetch_dhcp_reservations(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/service/dhcp")
    return rows


def _fetch_port_forwards(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/transmission/portForwardings")
    return rows


def _fetch_static_routes(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/transmission/staticRoutings")
    return rows


def _fetch_mdns_rules(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/service/mdns")
    return rows


def _fetch_mdns_profiles(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/profiles/mdns")
    return rows


def _fetch_wlan_groups(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/wlans")
    return rows


def _fetch_ssids(client: OmadaClient, site: SiteInfo, wlan_id: str) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/wlans/{wlan_id}/ssids")
    return rows


def _resolve_lan_network(
    networks: Sequence[Mapping[str, Any]],
    *,
    vlan: Any | None = None,
    net_id: str | None = None,
    target_ip: ipaddress.IPv4Address | None = None,
) -> dict[str, Any]:
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
        matches: list[dict[str, Any]] = []
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
        matched: list[dict[str, Any]] = []
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


def _strip_client_volatiles(client_obj: Mapping[str, Any]) -> dict[str, Any]:
    return {k: copy.deepcopy(v) for k, v in client_obj.items() if k not in CLIENT_VOLATILE_KEYS}


def _ensure_lan_patch_body(iface_obj: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
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
) -> list[str]:
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


def _fetch_lan_pair(
    client: OmadaClient,
    site: SiteInfo,
    *,
    vlan: Any | None = None,
    net_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
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


def _fetch_lan_profiles(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/lan/profiles")
    return rows


def _fetch_policy_routes(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    rows, _ = client.paginate(f"sites/{site.site_id}/setting/transmission/policyRoutings")
    return rows


def _fetch_lan_dns_rules(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    try:
        rows, _ = client.paginate(f"sites/{site.site_id}/setting/lan/dns")
        return rows
    except OmadaError as exc:
        if exc.code in (-41011, -1600, -1007) or "HTTP 404" in str(exc):
            raise OmadaError(
                "Local LAN DNS is not supported by this controller or site hardware",
                code=exc.code,
                hint="Local LAN DNS (setting/lan/dns) requires Omada Controller v5.14+ / v6.x with a supported gateway.",
            ) from exc
        raise


def _fetch_typed_acls(client: OmadaClient, site: SiteInfo, acl_type: int) -> list[dict[str, Any]]:
    _, rows = _fetch_typed_acls_with_meta(client, site, acl_type)
    return rows


def _fetch_rate_limit_profiles(client: OmadaClient, site: SiteInfo) -> list[dict[str, Any]]:
    return _unwrap_rows(client.api_result(f"sites/{site.site_id}/setting/profiles/rateLimits"))


def _require_gateway(client: OmadaClient, site: SiteInfo, feature: str) -> list[dict[str, Any]]:
    devs = _fetch_devices(client, site)
    gws = [d for d in devs if str(d.get("type") or "").lower() == "gateway"]
    if not gws:
        raise OmadaError(
            f"{feature} requires an adopted Omada gateway in site {site.name!r}",
            code=-1007,
            hint="No gateway device was found in this site.",
        )
    return gws

