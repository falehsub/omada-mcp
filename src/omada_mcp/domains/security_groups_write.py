"""Write domain module: security_groups_write."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError
from ._write_common import (
    _committed_result,
    _delete_entity,
    _dry_run_result,
    _require_confirm,
    _site,
    json_summary,
)
from ._write_fetchers import _fetch_acls, _fetch_groups, _fetch_lan_collection
from ._write_safety import (
    _check_acl_safety,
    _group_id,
    _ip_list_canonical,
    _normalize_group_output,
    pack_ip_entries,
)


def _find_ip_group(groups: Sequence[Mapping[str, Any]], needle: str) -> dict[str, Any]:
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
    cidrs: list[Any] | None = None,
    ipRange: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
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
    warnings: list[str] = []

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

    def _read_back() -> list[dict[str, Any]]:
        return [g for g in _fetch_groups(client, site) if int(g.get("type", 0)) == 0]

    def _verify(_before: Any, after_groups: Any) -> tuple[bool, str | None]:
        if not isinstance(after_groups, list):
            return False, "groups read-back did not return a list"
        created = next((g for g in after_groups if str(g.get("name")) == group_name), None)
        if created is None:
            return False, f"created group {group_name!r} not found on read-back"
        if _ip_list_canonical(created.get("ipList") or []) != expected_pairs:
            return False, "created group ipList does not match packed entries"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
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


def _format_ip_list_as_cidrs(ip_list: Sequence[Mapping[str, Any]]) -> list[str]:
    return [f"{item.get('ip')}/{item.get('mask', 32)}" for item in ip_list]


def _swap_rule_group_id(rule: Mapping[str, Any], old_id: str, new_id: str) -> dict[str, Any]:
    updated = copy.deepcopy(dict(rule))
    if int(updated.get("sourceType", -1)) == 1 and isinstance(updated.get("sourceIds"), list):
        updated["sourceIds"] = [new_id if str(x) == old_id else x for x in updated["sourceIds"]]
    if int(updated.get("destinationType", -1)) == 1 and isinstance(updated.get("destinationIds"), list):
        updated["destinationIds"] = [new_id if str(x) == old_id else x for x in updated["destinationIds"]]
    return updated


def replace_ip_group(
    client: OmadaClient,
    group: str,
    cidrs: list[Any] | None = None,
    ipRange: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
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
    completed: list[dict[str, Any]] = []
    snapshots: list[str] = []
    tmp_id: str | None = None
    new_id: str | None = None

    def _read_ip_groups() -> list[dict[str, Any]]:
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

    def _create_group(gname: str, glist: list[dict[str, Any]], step_label: str) -> dict[str, Any]:
        post_ep = f"sites/{site.site_id}/setting/profiles/groups"
        pairs = _ip_list_canonical(glist)

        def _verify_created(_b: Any, groups_now: Any) -> tuple[bool, str | None]:
            found = next((g for g in groups_now if str(g.get("name")) == gname), None)
            if found is None:
                return False, f"group {gname!r} missing after POST"
            if _ip_list_canonical(found.get("ipList") or []) != pairs:
                return False, f"group {gname!r} ipList mismatch after POST"
            return True, None

        def _reauth_create() -> tuple[bool, dict[str, Any] | None, Any]:
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

    def _repoint_rule(rule: dict[str, Any], from_id: str, to_id: str, step_label: str) -> None:
        rid = str(rule["id"])
        patched_rule = _swap_rule_group_id(rule, from_id, to_id)
        acl_ep = f"sites/{site.site_id}/setting/firewall/acls/{rid}?type=0"

        def _read_rule() -> dict[str, Any] | None:
            _, rules_now = _fetch_acls(client, site)
            return next((r for r in rules_now if str(r.get("id")) == rid), None)

        def _verify_rule(_b: Any, after_rule: Any) -> tuple[bool, str | None]:
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

        def _reauth_rule() -> tuple[bool, dict[str, Any] | None, Any]:
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


def delete_ip_group(
    client: OmadaClient,
    group: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
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

