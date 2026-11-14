"""Write domain module: security_acls_write."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError, SiteInfo
from ._common import ACL_TYPE_LABELS
from ._write_common import (
    _ACL_DISPATCH_NOTES,
    _SOURCE_DEST_TYPES,
    _SWITCH_ACL_BINDING_MAP,
    _committed_result,
    _delete_entity,
    _diff_mappings,
    _dry_run_result,
    _match_fields,
    _parse_code_map,
    _require_confirm,
    _site,
)
from ._write_fetchers import (
    _fetch_acls,
    _fetch_groups,
    _fetch_lan_collection,
    _fetch_ssids,
    _fetch_typed_acls,
    _fetch_typed_acls_with_meta,
    _fetch_wlan_groups,
    _resolve_acl_rule,
    _resolve_lan_network,
)
from ._write_safety import _check_acl_safety, _group_id


def _parse_policy(policy: Any) -> int:
    if isinstance(policy, bool):
        raise OmadaError("policy must be 'deny' (0) or 'permit' (1), not a boolean")
    if isinstance(policy, int) and policy in (0, 1):
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
) -> tuple[int, list[str]]:
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

    resolved: list[str] = []
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


def _normalize_direction(direction: Mapping[str, Any]) -> dict[str, Any]:
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
    source: dict[str, Any],
    destination: dict[str, Any],
    direction: dict[str, Any],
    status: bool = True,
    protocols: list[int] | None = None,
    biDirectional: bool = False,
    syslog: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
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

    def _read_back() -> list[dict[str, Any]]:
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

    def _verify(_before: Any, after_rules: Any) -> tuple[bool, str | None]:
        if not isinstance(after_rules, list):
            return False, "ACL read-back did not return a rule list"
        found = next((r for r in after_rules if str(r.get("name")) == rule_name), None)
        if found is None:
            return False, f"created ACL rule {rule_name!r} missing on read-back"
        if not _matches_rule(found):
            return False, f"created ACL rule {rule_name!r} fields on read-back did not match intent"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
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
    aclType: Any | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Enable or disable a gateway, switch, or EAP ACL rule (never touches ``aclDisable``)."""
    site = _site(client)
    resolved_type, acl_disable, target_rule = _resolve_acl_rule(client, site, rule, acl_type=aclType)
    type_label = ACL_TYPE_LABELS[resolved_type]

    target_id = str(target_rule["id"])
    _require_confirm("set_acl_rule_status", target_id, dryRun, confirm)

    desired_status = bool(status)
    if desired_status and int(target_rule.get("policy", 1)) == 0:
        networks = _fetch_lan_collection(client, site)
        groups = _fetch_groups(client, site)
        direction = (
            target_rule.get("direction") or {}
            if resolved_type == 0
            else {"lanToLan": True, "lanToWan": False, "wanInIds": [], "vpnInIds": []}
        )
        _check_acl_safety(
            client,
            policy=0,
            status=True,
            source_type=int(target_rule.get("sourceType", -1)),
            source_ids=[str(x) for x in (target_rule.get("sourceIds") or [])],
            dest_type=int(target_rule.get("destinationType", -1)),
            dest_ids=[str(x) for x in (target_rule.get("destinationIds") or [])],
            direction=direction,
            networks=networks,
            groups=groups,
        )

    before_summary = {
        "id": target_id,
        "name": target_rule.get("name"),
        "aclType": type_label,
        "status": bool(target_rule.get("status")),
        "policy": target_rule.get("policy"),
    }
    proposed_after = dict(before_summary)
    proposed_after["status"] = desired_status
    diff = {"status": {"before": bool(target_rule.get("status")), "after": desired_status}}
    warnings = [_ACL_DISPATCH_NOTES]
    if acl_disable is not None:
        warnings.append(f"observed controller aclDisable={acl_disable!r} (advisory only)")
    rb_args: dict[str, Any] = {"rule": target_id, "status": bool(target_rule.get("status")), "dryRun": True}
    if resolved_type != 0:
        rb_args["aclType"] = type_label
    rollback = {"tool": "set_acl_rule_status", "arguments": rb_args}

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

    endpoint = f"sites/{site.site_id}/setting/firewall/acls/{target_id}?type={resolved_type}"
    patch_body = copy.deepcopy(target_rule)
    patch_body["status"] = desired_status

    def _read_back() -> dict[str, Any] | None:
        _, live_rules = _fetch_typed_acls_with_meta(client, site, resolved_type)
        return next((dict(r) for r in live_rules if str(r.get("id")) == target_id), None)

    def _verify(_before: Any, after_rule: Any) -> tuple[bool, str | None]:
        if not isinstance(after_rule, Mapping):
            return False, f"ACL rule {target_id} missing on read-back"
        if bool(after_rule.get("status")) != desired_status:
            return False, f"ACL rule status expected {desired_status}, got {after_rule.get('status')!r}"
        drifts = _diff_mappings(target_rule, after_rule, ignore_keys=["status"])
        if drifts:
            return False, "unexpected field drift on ACL rule after PUT: " + ", ".join(drifts)
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
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
            "aclType": type_label,
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
        snapshot_payload={**target_rule, "type": target_rule.get("type", resolved_type)},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["status"],
    )
    after_rule = write_res["after"]
    after_summary = {
        "id": target_id,
        "name": after_rule.get("name"),
        "aclType": type_label,
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


def update_gateway_acl(
    client: OmadaClient,
    rule: str,
    name: str | None = None,
    status: bool | None = None,
    policy: Any = None,
    source: dict[str, Any] | None = None,
    destination: dict[str, Any] | None = None,
    direction: dict[str, Any] | None = None,
    protocols: list[int] | None = None,
    biDirectional: bool | None = None,
    syslog: bool | None = None,
    aclType: Any | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Modify fields of an existing gateway, switch, or EAP ACL rule (``PUT setting/firewall/acls/{id}?type=0|1|2``)."""
    if all(
        v is None
        for v in (name, status, policy, source, destination, direction, protocols, biDirectional, syslog)
    ):
        raise OmadaError("specify at least one field to update on the ACL rule")

    site = _site(client)
    resolved_type, acl_disable, target_rule = _resolve_acl_rule(client, site, rule, acl_type=aclType)
    if resolved_type != 0 and direction is not None:
        raise OmadaError(
            "direction flags apply only to gateway ACLs (aclType='gateway')",
            hint="omit direction when updating a switch or EAP ACL rule",
        )
    target_id = str(target_rule["id"])
    _require_confirm("update_gateway_acl", target_id, dryRun, confirm)

    networks = _fetch_lan_collection(client, site)
    groups = _fetch_groups(client, site)

    def _resolve_endpoint_for_scope(spec: dict[str, Any], *, label: str) -> tuple[int, list[str]]:
        if resolved_type == 0:
            return _resolve_acl_endpoint(spec, label=label, networks=networks, groups=groups)
        kind = str(spec.get("type") or "").strip().lower()
        if resolved_type == 1 and kind == "ssid":
            raise OmadaError(f"switch ACL {label}.type does not support 'ssid' (EAP ACLs only)")
        return _resolve_extended_acl_endpoint(
            client, site, spec, label=label, networks=networks, groups=groups,
        )

    patch_body = copy.deepcopy(target_rule)
    changed_keys: list[str] = []
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
        src_type, src_ids = _resolve_endpoint_for_scope(source, label="source")
        patch_body["sourceType"] = src_type
        patch_body["sourceIds"] = src_ids
        changed_keys.extend(["sourceType", "sourceIds"])
    if destination is not None:
        dst_type, dst_ids = _resolve_endpoint_for_scope(destination, label="destination")
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

    eff_dir = (
        (patch_body.get("direction") or {})
        if resolved_type == 0
        else {"lanToLan": True, "lanToWan": False, "wanInIds": [], "vpnInIds": []}
    )
    if (
        resolved_type == 0
        and eff_dir.get("lanToWan")
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
    if biDirectional is not None and "biDirectional" not in target_rule:
        warnings.append(
            "controller ACL schema does not expose 'biDirectional' on read-back "
            "(Omada v6.x uses stateful stateMode instead)"
        )
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

    endpoint = f"sites/{site.site_id}/setting/firewall/acls/{target_id}?type={resolved_type}"
    snap_payload = {**target_rule, "type": target_rule.get("type", resolved_type)}

    def _read_back() -> dict[str, Any] | None:
        _, live_rules = _fetch_typed_acls_with_meta(client, site, resolved_type)
        return next((dict(r) for r in live_rules if str(r.get("id")) == target_id), None)

    def _verify(_before: Any, after_rule: Any) -> tuple[bool, str | None]:
        if not isinstance(after_rule, Mapping):
            return False, f"ACL rule {target_id} missing on read-back"
        verifiable = {
            k: v
            for k, v in expected.items()
            if k != "biDirectional" or "biDirectional" in after_rule or "biDirectional" in target_rule
        }
        ok, reason = _match_fields(after_rule, verifiable)
        if not ok:
            return False, reason
        ignore = list(expected.keys())
        if "syslog" in expected:
            ignore.append("existSyslog")
        drifts = _diff_mappings(target_rule, after_rule, ignore_keys=ignore)
        if drifts:
            return False, "unexpected field drift on ACL rule: " + ", ".join(drifts)
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
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
        snapshot_payload=snap_payload,
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
    aclType: Any | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a gateway, switch, or EAP ACL rule (``DELETE setting/firewall/acls/{id}?type=0|1|2``)."""
    site = _site(client)
    resolved_type, acl_disable, target_rule = _resolve_acl_rule(client, site, rule, acl_type=aclType)
    target_id = str(target_rule["id"])
    warnings = [_ACL_DISPATCH_NOTES]
    if acl_disable is not None:
        warnings.append(f"observed controller aclDisable={acl_disable!r} (advisory only)")
    return _delete_entity(
        client,
        tool_name="delete_gateway_acl",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/firewall/acls/{target_id}?type={resolved_type}",
        before=target_rule,
        snapshot_payload={**target_rule, "type": target_rule.get("type", resolved_type)},
        fetch_all=lambda: _fetch_typed_acls(client, site, resolved_type),
        match_fn=lambda row: str(row.get("id")) == target_id,
        rollback=None,
        warnings=warnings,
        dry_run=dryRun,
        confirm=confirm,
        label="aclRule",
    )


def _resolve_extended_acl_endpoint(
    client: OmadaClient,
    site: SiteInfo,
    spec: Mapping[str, Any],
    *,
    label: str,
    networks: Sequence[Mapping[str, Any]],
    groups: Sequence[Mapping[str, Any]],
) -> tuple[int, list[str]]:
    if not isinstance(spec, Mapping):
        raise OmadaError(f"{label} must be an object with 'type' and 'ids'")
    kind = str(spec.get("type") or "").strip().lower()
    raw_ids = spec.get("ids")
    if not isinstance(raw_ids, Sequence) or isinstance(raw_ids, (str, bytes)) or not raw_ids:
        raise OmadaError(f"{label}.ids must be a non-empty list")
    if kind in ("network", "ip_group", "port_group", "ip_port_group"):
        mapped = {**spec, "type": "port_group" if kind == "ip_port_group" else kind}
        return _resolve_acl_endpoint(mapped, label=label, networks=networks, groups=groups)
    if kind == "mac_group":
        mac_groups = [g for g in groups if str(g.get("type")) in ("2", "3", "mac") or "macList" in g]
        pool = mac_groups or list(groups)
        by_id = {_group_id(g): _group_id(g) for g in pool if _group_id(g)}
        by_name = {str(g.get("name") or "").strip(): _group_id(g) for g in pool if g.get("name") and _group_id(g)}
        out = [by_id.get(str(x).strip()) or by_name.get(str(x).strip()) or "" for x in raw_ids]
        if any(not v for v in out):
            raise OmadaError(f"{label} contains unknown mac_group(s): {raw_ids!r}")
        return 3, out
    if kind == "ssid":
        wgroups = _fetch_wlan_groups(client, site)
        all_ssids: list[dict[str, Any]] = []
        for wg in wgroups:
            wid = str(wg.get("id") or "")
            if wid:
                all_ssids.extend(_fetch_ssids(client, site, wid))
        by_id = {str(s.get("id") or ""): str(s.get("id") or "") for s in all_ssids if s.get("id")}
        by_name = {str(s.get("name") or "").strip(): str(s.get("id") or "") for s in all_ssids if s.get("name") and s.get("id")}
        out = [by_id.get(str(x).strip()) or by_name.get(str(x).strip()) or "" for x in raw_ids]
        if any(not v for v in out):
            raise OmadaError(f"{label} contains unknown SSID(s): {raw_ids!r}")
        return 4, out
    raise OmadaError(f"unsupported {label}.type {kind!r}; expected network, ip_group, port_group, mac_group, or ssid")


def _create_scoped_acl(
    client: OmadaClient,
    *,
    tool_name: str,
    acl_type: int,
    name: str,
    policy: Any,
    source: dict[str, Any],
    destination: dict[str, Any],
    status: bool = True,
    protocols: list[int] | None = None,
    bi_directional: bool = False,
    syslog: bool = False,
    binding_type: Any | None = None,
    custom_acl_ports: Sequence[Any] | None = None,
    network_id: str | None = None,
    ether_type: str | None = None,
    dry_run: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    rule_name = str(name or "").strip()
    if not rule_name:
        raise OmadaError("ACL rule name must be non-empty")
    policy_int = _parse_policy(policy)
    norm_protocols = [int(p) for p in (protocols if protocols is not None else [256])]
    if not norm_protocols:
        raise OmadaError("protocols must be non-empty (e.g. [256])")
    _require_confirm(tool_name, rule_name, dry_run, confirm)

    site = _site(client)
    existing = _fetch_typed_acls(client, site, acl_type)
    if any(str(r.get("name") or "").strip() == rule_name for r in existing):
        raise OmadaError(
            f"{'switch' if acl_type == 1 else 'EAP'} ACL {rule_name!r} already exists",
            hint="Use a unique name or update/toggle the existing ACL rule.",
        )

    networks = _fetch_lan_collection(client, site)
    groups = _fetch_groups(client, site)
    src_type, src_ids = _resolve_extended_acl_endpoint(client, site, source, label="source", networks=networks, groups=groups)
    dst_type, dst_ids = _resolve_extended_acl_endpoint(client, site, destination, label="destination", networks=networks, groups=groups)

    warnings: list[str] = [_ACL_DISPATCH_NOTES]
    _check_acl_safety(
        client,
        policy=policy_int,
        status=bool(status),
        source_type=src_type,
        source_ids=src_ids,
        dest_type=dst_type,
        dest_ids=dst_ids,
        direction={"lanToLan": True, "lanToWan": False, "wanInIds": [], "vpnInIds": []},
        networks=networks,
        groups=groups,
    )

    body: dict[str, Any] = {
        "name": rule_name,
        "status": bool(status),
        "policy": policy_int,
        "protocols": norm_protocols,
        "sourceType": src_type,
        "sourceIds": src_ids,
        "destinationType": dst_type,
        "destinationIds": dst_ids,
        "type": int(acl_type),
        "biDirectional": bool(bi_directional),
        "syslog": bool(syslog),
    }

    if acl_type == 1:
        btype = _parse_code_map(
            "all_ports" if binding_type is None else binding_type,
            _SWITCH_ACL_BINDING_MAP,
            label="bindingType",
        )
        body["bindingType"] = btype
        body["customAclPorts"] = list(custom_acl_ports or [])
        body["customAclOsws"] = []
        body["customAclDevices"] = []
        body["customAclStacks"] = []
        if btype == 1 and not body["customAclPorts"]:
            raise OmadaError("bindingType='custom_ports' requires non-empty customAclPorts")
        if btype in (2, 3) and network_id:
            net = _resolve_lan_network(networks, vlan=network_id)
            body["networkId"] = str(net.get("id") or network_id)
        if ether_type:
            body["etherType"] = {"enable": True, "value": str(ether_type).strip()}
        else:
            body["etherType"] = {"enable": False}

    diff = {"rule": {"before": None, "after": body}}
    if dry_run:
        return _dry_run_result(
            tool_name=tool_name,
            target_id=rule_name,
            before=None,
            after=body,
            diff=diff,
            warnings=warnings,
            rollback=None,
        )

    endpoint = f"sites/{site.site_id}/setting/firewall/acls?type={acl_type}"

    def _read_back() -> list[dict[str, Any]]:
        return _fetch_typed_acls(client, site, acl_type)

    def _verify(_before: Any, after_rules: Any) -> tuple[bool, str | None]:
        if not isinstance(after_rules, list):
            return False, "ACL read-back did not return a list"
        found = next((r for r in after_rules if str(r.get("name")) == rule_name), None)
        if found is None:
            return False, f"created ACL {rule_name!r} missing on read-back"
        if int(found.get("policy", -1)) != policy_int or bool(found.get("status")) != bool(status):
            return False, f"created ACL {rule_name!r} read-back did not match policy/status"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        rules_now = _read_back()
        ok, _ = _verify(None, rules_now)
        return ok, None, None

    write_res = client.write(
        endpoint,
        method="POST",
        data=body,
        tool_name=tool_name,
        target=rule_name,
        before=None,
        snapshot_payload={"type": acl_type, "existingAcls": existing},
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["name", "policy", "status", "sourceIds", "destinationIds"],
    )
    created = next((r for r in write_res["after"] if str(r.get("name")) == rule_name), body)
    return _committed_result(
        tool_name=tool_name,
        target_id=rule_name,
        before=None,
        after=created,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=None,
    )


def create_switch_acl(
    client: OmadaClient,
    name: str,
    policy: Any,
    source: dict[str, Any],
    destination: dict[str, Any],
    bindingType: Any = "all_ports",
    customAclPorts: list[Any] | None = None,
    networkId: str | None = None,
    status: bool = True,
    protocols: list[int] | None = None,
    biDirectional: bool = False,
    etherType: str | None = None,
    syslog: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create a Switch ACL rule (``POST setting/firewall/acls?type=1``)."""
    return _create_scoped_acl(
        client,
        tool_name="create_switch_acl",
        acl_type=1,
        name=name,
        policy=policy,
        source=source,
        destination=destination,
        status=status,
        protocols=protocols,
        bi_directional=biDirectional,
        syslog=syslog,
        binding_type=bindingType,
        custom_acl_ports=customAclPorts,
        network_id=networkId,
        ether_type=etherType,
        dry_run=dryRun,
        confirm=confirm,
    )


def create_eap_acl(
    client: OmadaClient,
    name: str,
    policy: Any,
    source: dict[str, Any],
    destination: dict[str, Any],
    status: bool = True,
    protocols: list[int] | None = None,
    syslog: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create an EAP (wireless) ACL rule (``POST setting/firewall/acls?type=2``)."""
    return _create_scoped_acl(
        client,
        tool_name="create_eap_acl",
        acl_type=2,
        name=name,
        policy=policy,
        source=source,
        destination=destination,
        status=status,
        protocols=protocols,
        bi_directional=False,
        syslog=syslog,
        dry_run=dryRun,
        confirm=confirm,
    )

