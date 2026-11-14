"""Read domain module: security_read."""

from __future__ import annotations

from typing import Any

from .._projections import project_controller_row
from ..client import OmadaClient, OmadaError
from ._common import ACL_TYPE_MAP, try_paginate
from ._network_helpers import collect_security_status_data
from ._tool_model import _as_int, _site
from ._write_fetchers import _fetch_acls, _fetch_groups
from .networks_read import _parse_group_type


def _project_acl_rule(
    rule: dict[str, Any],
    *,
    acl_type: str | None = None,
) -> dict[str, Any]:
    raw_policy = rule.get("policy")
    policy_map: dict[Any, str] = {0: "deny", 1: "permit"}
    policy_label = policy_map.get(raw_policy, str(raw_policy)) if raw_policy is not None else "None"
    src_ids = rule.get("sourceIds") if rule.get("sourceIds") is not None else rule.get("sourceFilter")
    dst_ids = rule.get("destinationIds") if rule.get("destinationIds") is not None else rule.get("destinationFilter")
    protocols = rule.get("protocols") if rule.get("protocols") is not None else rule.get("protocol")
    if isinstance(protocols, (int, str)):
        proto_list: list[Any] = [protocols]
    elif isinstance(protocols, list):
        proto_list = list(protocols)
    else:
        proto_list = []
    projected: dict[str, Any] = {
        "id": str(rule.get("id") or ""),
        "index": _as_int(rule.get("index"), 0) if rule.get("index") is not None else None,
        "name": str(rule.get("name") or ""),
        "status": bool(rule.get("status", False)),
        "policy": raw_policy if raw_policy is not None else 0,
        "policyLabel": policy_label,
        "sourceType": rule.get("sourceType"),
        "sourceIds": [str(x) for x in (src_ids or [])],
        "destinationType": rule.get("destinationType"),
        "destinationIds": [str(x) for x in (dst_ids or [])],
        "direction": rule.get("direction") if isinstance(rule.get("direction"), dict) else None,
        "protocols": proto_list,
        "biDirectional": bool(rule.get("biDirectional", False)),
        "syslog": bool(rule.get("syslog", False)),
    }
    if acl_type is not None:
        projected["aclType"] = acl_type
    if acl_type in ("switch", "eap") or "bindingType" in rule:
        if rule.get("bindingType") is not None:
            projected["bindingType"] = rule.get("bindingType")
        if rule.get("customAclPorts") is not None:
            projected["customAclPorts"] = [dict(p) for p in (rule.get("customAclPorts") or []) if isinstance(p, dict)]
        if rule.get("networkId") is not None:
            projected["networkId"] = str(rule.get("networkId") or "")
    return projected


def _list_acls(client: OmadaClient, aclType: str = "gateway") -> list[dict[str, Any]]:
    site = _site(client)
    kind = str(aclType or "gateway").strip().lower()
    if kind == "gateway":
        _, rules = _fetch_acls(client, site)
        return [_project_acl_rule(rule) for rule in rules]
    if kind in ("switch", "eap"):
        code = ACL_TYPE_MAP[kind]
        rows, _ = client.paginate(f"sites/{site.site_id}/setting/firewall/acls?type={code}")
        return [_project_acl_rule(rule, acl_type=kind) for rule in rows]
    if kind == "all":
        combined: list[dict[str, Any]] = []
        tmp_warnings: list[str] = []
        for tname in ("gateway", "switch", "eap"):
            code = ACL_TYPE_MAP[tname]
            if tname == "gateway":
                try:
                    _, g_rules = _fetch_acls(client, site)
                    combined.extend(_project_acl_rule(r, acl_type="gateway") for r in g_rules)
                    continue
                except OmadaError:
                    rows, _, ok = try_paginate(
                        client, f"sites/{site.site_id}/setting/firewall/acls?type={code}",
                        tmp_warnings, label=f"ACL {tname}",
                    )
                    if ok:
                        combined.extend(_project_acl_rule(r, acl_type=tname) for r in rows)
            else:
                rows, _, ok = try_paginate(
                    client, f"sites/{site.site_id}/setting/firewall/acls?type={code}",
                    tmp_warnings, label=f"ACL {tname}",
                )
                if ok:
                    combined.extend(_project_acl_rule(r, acl_type=tname) for r in rows)
        return combined
    raise OmadaError(
        f"invalid aclType {aclType!r}",
        hint="valid values: 'gateway' (0), 'switch' (1), 'eap' (2), or 'all'",
    )


_GROUP_TYPE_ALIASES = {"ip": 0, "port": 1, "mac": 2, "ipv6": 3}


_GROUP_TYPE_LABELS = {0: "ip", 1: "port", 2: "mac", 3: "ipv6"}


def _list_ip_groups(
    client: OmadaClient,
    groupType: Any | None = None,
) -> list[dict[str, Any]]:
    site = _site(client)
    groups = _fetch_groups(client, site)
    filter_type: int | None = None
    if groupType is not None and str(groupType).strip().lower() not in ("", "all"):
        raw_gt = str(groupType).strip().lower()
        if raw_gt in _GROUP_TYPE_ALIASES:
            filter_type = _GROUP_TYPE_ALIASES[raw_gt]
        else:
            try:
                filter_type = int(groupType)
            except (TypeError, ValueError):
                raise OmadaError(
                    f"invalid groupType {groupType!r}",
                    hint="valid values: 'ip' (0), 'port' (1), 'mac' (2), or 'all'",
                ) from None

    refs_by_group: dict[str, list[dict[str, str]]] = {}
    try:
        _, acls = _fetch_acls(client, site)
    except OmadaError:
        acls = []
    for rule in acls:
        ref = {"id": str(rule.get("id") or ""), "name": str(rule.get("name") or "")}
        for key in ("sourceIds", "destinationIds"):
            for gid in rule.get(key) or []:
                refs_by_group.setdefault(str(gid), []).append(ref)

    projected: list[dict[str, Any]] = []
    for grp in groups:
        gtype = _parse_group_type(grp)
        if filter_type is not None and gtype != filter_type:
            continue
        gid = str(grp.get("id") or grp.get("groupId") or "")
        raw_ip_list = grp.get("ipList")
        ip_list: list[Any] = raw_ip_list if isinstance(raw_ip_list, list) else []
        refs = refs_by_group.get(gid, [])
        unique_refs = list({r["id"]: r for r in refs}.values())
        projected.append({
            "id": gid,
            "name": str(grp.get("name") or ""),
            "type": gtype,
            "typeLabel": _GROUP_TYPE_LABELS.get(gtype, "unknown") if gtype is not None else "unknown",
            "entryCount": len(ip_list),
            "ipList": project_controller_row("groups", {"ipList": ip_list})["ipList"],
            "referencedByAcls": unique_refs,
        })
    return projected


def _get_security_status(
    client: OmadaClient,
    hours: int = 24,
    limit: int = 20,
) -> dict[str, Any]:
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 0:
        raise OmadaError("hours must be a non-negative integer")
    site = _site(client)
    data = collect_security_status_data(client, site, limit=limit)
    if hours > 0 and isinstance(data.get("warnings"), list):
        data["windowHours"] = hours
    return data


_ACL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "index": {"type": ["integer", "null"]},
        "name": {"type": "string"},
        "aclType": {"type": "string"},
        "status": {"type": "boolean"},
        "policy": {"type": ["integer", "string"]},
        "policyLabel": {"type": "string"},
        "sourceType": {"type": ["integer", "string", "null"]},
        "sourceIds": {"type": "array", "items": {"type": "string"}},
        "destinationType": {"type": ["integer", "string", "null"]},
        "destinationIds": {"type": "array", "items": {"type": "string"}},
        "direction": {"type": ["object", "null"]},
        "bindingType": {"type": ["integer", "string", "null"]},
        "customAclPorts": {"type": "array", "items": {"type": "object"}},
        "networkId": {"type": ["string", "null"]},
        "protocols": {"type": "array", "items": {"type": ["integer", "string"]}},
        "biDirectional": {"type": "boolean"},
        "syslog": {"type": "boolean"},
    },
    "required": ["id", "name", "status", "policy", "sourceIds", "destinationIds"],
}


_IP_GROUP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "type": {"type": ["integer", "null"]},
        "typeLabel": {"type": "string"},
        "entryCount": {"type": "integer"},
        "ipList": {"type": "array", "items": {"type": ["object", "string"]}},
        "referencedByAcls": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                },
            },
        },
    },
    "required": ["id", "name", "type", "entryCount"],
}


_SECURITY_STATUS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "ips": {"type": ["object", "null"]},
        "attackDefense": {"type": ["object", "null"]},
        "wids": {"type": ["object", "null"]},
        "threatAlerts": {"type": "array", "items": {"type": "object"}},
        "rogueAps": {"type": "array", "items": {"type": "object"}},
        "counts": {"type": "object"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["ips", "threatAlerts", "rogueAps", "counts", "warnings"],
}

