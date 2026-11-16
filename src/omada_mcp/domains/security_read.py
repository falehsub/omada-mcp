"""Read domain module: security_read."""

from __future__ import annotations

from typing import Any

from .._projections import project_controller_row
from ..client import OmadaClient, OmadaError
from ._common import ACL_TYPE_MAP, deep_redact, try_api_result, try_paginate
from ._network_helpers import collect_security_status_data
from ._tool_model import _as_int, _iso, _site, normalize_mac
from ._write_fetchers import (
    _fetch_acls,
    _fetch_groups,
    _fetch_rate_limit_profiles,
    _fetch_schedules,
)
from .clients_read import _paginate_client_rows
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
        proj = project_controller_row("groups", grp)
        ip_list: list[Any] = list(proj.get("ipList") or [])
        port_list: list[Any] = list(proj.get("portList") or [])
        mac_list: list[Any] = list(proj.get("macAddressList") or proj.get("macList") or [])
        if gtype == 1:
            entry_count = len(port_list) + len(ip_list)
        elif gtype == 2:
            entry_count = len(mac_list)
        else:
            entry_count = len(ip_list)
        if entry_count == 0 and isinstance(grp.get("count"), int):
            entry_count = int(grp["count"])
        refs = refs_by_group.get(gid, [])
        unique_refs = list({r["id"]: r for r in refs}.values())
        entry: dict[str, Any] = {
            "id": gid,
            "name": str(grp.get("name") or ""),
            "type": gtype,
            "typeLabel": _GROUP_TYPE_LABELS.get(gtype, "unknown") if gtype is not None else "unknown",
            "entryCount": entry_count,
            "ipList": ip_list,
            "referencedByAcls": unique_refs,
        }
        if gtype == 1 or port_list:
            entry["portList"] = port_list
        if gtype == 2 or mac_list:
            entry["macAddressList"] = mac_list
        projected.append(entry)
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


_DAY_MODE_LABELS: dict[int, str] = {
    0: "everyday",
    1: "weekday",
    2: "weekend",
    3: "custom",
}

_DAY_FIELDS: tuple[tuple[str, str], ...] = (
    ("dayMon", "mon"),
    ("dayTue", "tue"),
    ("dayWed", "wed"),
    ("dayThu", "thu"),
    ("dayFri", "fri"),
    ("daySat", "sat"),
    ("daySun", "sun"),
)


def _list_blocked_clients(client: OmadaClient) -> list[dict[str, Any]]:
    """List currently blocked clients on the resolved site."""
    site = _site(client)
    first_error: OmadaError | None = None
    rows: list[dict[str, Any]] = []
    for ep in ("clients?filters.block=true", "insight/clients?filters.block=true"):
        try:
            rows = _paginate_client_rows(client, site, ep)
            first_error = None
            break
        except OmadaError as exc:
            if first_error is None:
                first_error = exc
            if exc.code in (-1007, -1600):
                continue
            raise
    if first_error is not None:
        raise first_error

    out: list[dict[str, Any]] = []
    for row in rows:
        if "block" in row and not bool(row.get("block")):
            continue
        out.append({
            "mac": normalize_mac(str(row.get("mac") or "")),
            "name": str(row.get("name") or row.get("hostName") or ""),
            "hostName": str(row.get("hostName") or ""),
            "ip": str(row.get("ip") or ""),
            "wireless": bool(row.get("wireless", False)),
            "ssid": str(row.get("ssid") or ""),
            "networkName": str(row.get("networkName") or row.get("network") or ""),
            "lastSeen": _iso(row.get("lastSeen")),
            "block": True,
        })
    out.sort(key=lambda item: (item["name"].lower(), item["mac"]))
    return out


def _list_rate_limit_profiles(client: OmadaClient) -> list[dict[str, Any]]:
    """List bandwidth rate-limit profiles configured on the resolved site."""
    site = _site(client)
    rows = _fetch_rate_limit_profiles(client, site)
    out: list[dict[str, Any]] = []
    for row in rows:
        down_raw = row.get("downLimit")
        up_raw = row.get("upLimit")
        down_obj = down_raw if isinstance(down_raw, dict) else {}
        up_obj = up_raw if isinstance(up_raw, dict) else {}
        out.append(deep_redact({
            "id": str(row.get("id") or ""),
            "name": str(row.get("name") or ""),
            "isDefault": bool(row.get("isDefault", False)),
            "downLimitEnable": bool(row["downLimitEnable"]) if "downLimitEnable" in row else bool(down_obj.get("enable", False)),
            "downLimit": down_obj.get("limit") if isinstance(down_raw, dict) else down_raw,
            "downLimitUnit": row.get("downLimitUnit") if "downLimitUnit" in row else down_obj.get("unit"),
            "upLimitEnable": bool(row["upLimitEnable"]) if "upLimitEnable" in row else bool(up_obj.get("enable", False)),
            "upLimit": up_obj.get("limit") if isinstance(up_raw, dict) else up_raw,
            "upLimitUnit": row.get("upLimitUnit") if "upLimitUnit" in row else up_obj.get("unit"),
            "resource": row.get("resource"),
        }))
    out.sort(key=lambda item: (not item["isDefault"], item["name"].lower(), item["id"]))
    return out


def _project_schedule(row: dict[str, Any]) -> dict[str, Any]:
    proj = project_controller_row("schedules", row)
    mode = _as_int(proj.get("dayMode"), 0)
    days = [label for field, label in _DAY_FIELDS if bool(proj.get(field))]
    windows: list[dict[str, Any]] = []
    for slot in proj.get("timeList") or []:
        if not isinstance(slot, dict):
            continue
        sh = _as_int(slot.get("startTimeH"), 0)
        sm = _as_int(slot.get("startTimeM"), 0)
        eh = _as_int(slot.get("endTimeH"), 0)
        em = _as_int(slot.get("endTimeM"), 0)
        windows.append({
            "dayType": _as_int(slot.get("dayType"), 0),
            "start": f"{sh:02d}:{sm:02d}",
            "end": f"{eh:02d}:{em:02d}",
            "startTimeH": sh,
            "startTimeM": sm,
            "endTimeH": eh,
            "endTimeM": em,
            **({"ruleId": slot["ruleId"]} if slot.get("ruleId") is not None else {}),
        })
    return {
        "id": str(proj.get("id") or ""),
        "name": str(proj.get("name") or ""),
        "dayMode": mode,
        "dayModeLabel": _DAY_MODE_LABELS.get(mode, f"mode:{mode}"),
        "days": days,
        "dayMon": bool(proj.get("dayMon", False)),
        "dayTue": bool(proj.get("dayTue", False)),
        "dayWed": bool(proj.get("dayWed", False)),
        "dayThu": bool(proj.get("dayThu", False)),
        "dayFri": bool(proj.get("dayFri", False)),
        "daySat": bool(proj.get("daySat", False)),
        "daySun": bool(proj.get("daySun", False)),
        "timeList": windows,
        "resource": proj.get("resource"),
    }


def _list_schedules(client: OmadaClient) -> list[dict[str, Any]]:
    """List reusable time-range / schedule profiles on the resolved site."""
    site = _site(client)
    rows = _fetch_schedules(client, site)
    out = [_project_schedule(r) for r in rows]
    out.sort(key=lambda item: (item["name"].lower(), item["id"]))
    return out


def _project_user_row(row: dict[str, Any]) -> dict[str, Any]:
    raw_priv = row.get("privilege")
    priv: dict[str, Any] = raw_priv if isinstance(raw_priv, dict) else {}
    raw_role = row.get("role")
    role_obj: dict[str, Any] = raw_role if isinstance(raw_role, dict) else {}
    role_name = str(row.get("roleName") or role_obj.get("name") or "")
    return deep_redact({
        "id": str(row.get("id") or ""),
        "name": str(row.get("name") or ""),
        "type": row.get("type"),
        "roleType": row.get("roleType"),
        "roleId": str(row.get("roleId") or ""),
        "roleName": role_name,
        "verified": bool(row.get("verified", True)),
        "alert": bool(row.get("alert", False)),
        "allSites": bool(priv.get("all", False)) if "all" in priv else None,
        "siteIds": [str(s) for s in (priv.get("sites") or []) if s] if isinstance(priv.get("sites"), list) else [],
    })


def _list_controller_users(client: OmadaClient) -> dict[str, Any]:
    """List controller user/role accounts (secret-free; Viewer accounts see only self)."""
    warnings: list[str] = []
    client.authenticate()
    current_raw, _ = try_api_result(client, "users/current", warnings, label="current user")
    rows, _meta, ok = try_paginate(client, "users", warnings, label="controller users", page_size=100, max_pages=10)
    if not ok and isinstance(current_raw, dict):
        rows = [current_raw]

    users = [_project_user_row(r) for r in rows if isinstance(r, dict)]
    users.sort(key=lambda u: (u["roleName"].lower(), u["name"].lower(), u["id"]))

    viewer_limited = False
    if isinstance(current_raw, dict):
        raw_role = current_raw.get("role")
        nested_role = raw_role.get("name") if isinstance(raw_role, dict) else ""
        priv_str = current_raw.get("privilege") if isinstance(current_raw.get("privilege"), str) else ""
        role_name = str(current_raw.get("roleName") or nested_role or priv_str or "").strip().lower()
        if "viewer" in role_name or current_raw.get("roleType") == 2:
            viewer_limited = len(users) <= 1
    if viewer_limited:
        warnings.append("Controller returned only the authenticated Viewer user; Admin privilege is required to list all controller accounts.")

    return {
        "items": users,
        "count": len(users),
        "currentUser": _project_user_row(current_raw) if isinstance(current_raw, dict) else None,
        "viewerLimited": viewer_limited,
        "warnings": warnings,
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


_BLOCKED_CLIENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "hostName": {"type": "string"},
        "ip": {"type": "string"},
        "wireless": {"type": "boolean"},
        "ssid": {"type": "string"},
        "networkName": {"type": "string"},
        "lastSeen": {"type": ["string", "null"]},
        "block": {"type": "boolean"},
    },
    "required": ["mac", "name", "block"],
}


_RATE_LIMIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "isDefault": {"type": "boolean"},
        "downLimitEnable": {"type": "boolean"},
        "downLimit": {"type": ["integer", "number", "null"]},
        "downLimitUnit": {"type": ["integer", "string", "null"]},
        "upLimitEnable": {"type": "boolean"},
        "upLimit": {"type": ["integer", "number", "null"]},
        "upLimitUnit": {"type": ["integer", "string", "null"]},
        "resource": {"type": ["integer", "null"]},
    },
    "required": ["id", "name", "isDefault", "downLimitEnable", "upLimitEnable"],
}


_SCHEDULE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "dayMode": {"type": "integer"},
        "dayModeLabel": {"type": "string"},
        "days": {"type": "array", "items": {"type": "string"}},
        "dayMon": {"type": "boolean"},
        "dayTue": {"type": "boolean"},
        "dayWed": {"type": "boolean"},
        "dayThu": {"type": "boolean"},
        "dayFri": {"type": "boolean"},
        "daySat": {"type": "boolean"},
        "daySun": {"type": "boolean"},
        "timeList": {"type": "array", "items": {"type": "object"}},
        "resource": {"type": ["integer", "null"]},
    },
    "required": ["id", "name", "dayMode", "dayModeLabel", "days", "timeList"],
}


_CONTROLLER_USER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "type": {"type": ["integer", "string", "null"]},
        "roleType": {"type": ["integer", "string", "null"]},
        "roleId": {"type": "string"},
        "roleName": {"type": "string"},
        "verified": {"type": "boolean"},
        "alert": {"type": "boolean"},
        "allSites": {"type": ["boolean", "null"]},
        "siteIds": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["id", "name", "roleName"],
}


_CONTROLLER_USERS_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "items": {"type": "array", "items": _CONTROLLER_USER_SCHEMA},
        "count": {"type": "integer", "minimum": 0},
        "currentUser": {"type": ["object", "null"]},
        "viewerLimited": {"type": "boolean"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["items", "count", "viewerLimited", "warnings"],
}

