"""Write domain module: security_groups_write."""

from __future__ import annotations

import copy
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from .._projections import project_controller_row
from ..client import OmadaClient, OmadaError
from ._common import as_int
from ._ip_group_checkpoint import (
    checkpoint_key,
    checkpoint_path,
    checkpoint_scope,
    claim_checkpoint,
    persist_checkpoint,
    read_checkpoint,
    recovery_path,
)
from ._write_common import (
    _committed_result,
    _delete_entity,
    _dry_run_result,
    _field_diff,
    _normalize_mac,
    _port_range_valid,
    _require_confirm,
    _site,
    json_summary,
)
from ._write_fetchers import (
    _fetch_acls,
    _fetch_groups,
    _fetch_lan_collection,
    _fetch_typed_acls,
    _omada_mac,
)
from ._write_safety import (
    _check_acl_safety,
    _group_id,
    _ip_list_canonical,
    _normalize_group_output,
    pack_ip_entries,
)


def _find_typed_group(
    groups: Sequence[Mapping[str, Any]],
    needle: str,
    *,
    group_type: int,
    type_label: str,
) -> dict[str, Any]:
    typed = [dict(g) for g in groups if int(g.get("type", 0)) == group_type]
    key = str(needle or "").strip()
    by_id = [g for g in typed if _group_id(g) == key]
    if by_id:
        return by_id[0]
    by_name = [g for g in typed if str(g.get("name", "")).strip().lower() == key.lower()]
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        ids = ", ".join(_group_id(g) for g in by_name)
        raise OmadaError(f"group {needle!r} matched multiple {type_label} groups ({ids}); specify id")
    raise OmadaError(f"no {type_label} group (type={group_type}) matches {needle!r}")


def _find_ip_group(groups: Sequence[Mapping[str, Any]], needle: str) -> dict[str, Any]:
    return _find_typed_group(groups, needle, group_type=0, type_label="IPv4 IP")


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


def _verify_rule_references(expected: Mapping[str, Any], actual: Any) -> tuple[bool, str | None]:
    if not isinstance(actual, Mapping):
        return False, "ACL rule missing on read-back"
    for endpoint in ("source", "destination"):
        type_key = f"{endpoint}Type"
        ids_key = f"{endpoint}Ids"
        expected_type = as_int(expected.get(type_key), -1)
        if as_int(actual.get(type_key), -1) != expected_type:
            return False, f"ACL {type_key} changed during IP group replacement"
        if sorted(map(str, actual.get(ids_key) or [])) != sorted(map(str, expected.get(ids_key) or [])):
            return False, f"ACL {ids_key} did not preserve all intended references"
    return True, None


def _swap_plan(rule_ids: Sequence[str]) -> list[dict[str, str]]:
    plan = [{"action": "create_temp_group"}] if rule_ids else []
    plan.extend({"action": "repoint_acls_to_temp", "ruleId": rid} for rid in rule_ids)
    plan.extend(({"action": "delete_old_group"}, {"action": "recreate_group"}))
    plan.extend({"action": "repoint_acls_to_new", "ruleId": rid} for rid in rule_ids)
    if rule_ids:
        plan.append({"action": "delete_temp_group"})
    return plan


def _swap_state(groups: Sequence[dict[str, Any]], rules: Sequence[dict[str, Any]],
                operation: Mapping[str, Any]) -> dict[str, Any]:
    original = operation["original"]
    group_names = {original["name"].casefold(), operation["temporaryName"].casefold()}
    known_ids = {original["id"], operation.get("temporaryId"), operation.get("replacementId")}
    related = [row for row in groups if _group_id(row) in known_ids
               or (as_int(row.get("type"), -1) == 0 and str(row.get("name") or "").casefold() in group_names)]
    group_state = {_group_id(row): _swap_group_state(row) for row in related}
    if "" in group_state or len(group_state) != len(related):
        raise OmadaError("IP group recovery inventory has ambiguous group identities")
    known_ids.update(group_state)
    rule_ids = set(operation["ruleIds"])
    rule_state: dict[str, Any] = {}
    for rule in rules:
        rid = str(rule.get("id") or "")
        references = any(as_int(rule.get(f"{side}Type"), -1) == 1
                         and any(str(item) in known_ids for item in rule.get(f"{side}Ids") or [])
                         for side in ("source", "destination"))
        if rid in rule_ids or references:
            if not rid or rid in rule_state:
                raise OmadaError("IP group recovery inventory has ambiguous ACL identities")
            rule_state[rid] = project_controller_row("acls", rule)
    return {"groups": group_state, "rules": rule_state}


def _swap_group_state(group: Mapping[str, Any]) -> dict[str, Any]:
    return {"name": group.get("name"), "type": as_int(group.get("type"), -1),
            "resource": as_int(group.get("resource"), 0),
            "ipList": [list(pair) for pair in _ip_list_canonical(group.get("ipList") or [])]}


def _swap_transition(operation: Mapping[str, Any], step: Mapping[str, str],
                     created_id: str | None = None) -> dict[str, Any]:
    state = copy.deepcopy(operation["expected"])
    action = step["action"]
    old_id = operation["original"]["id"]
    temporary_id = operation.get("temporaryId")
    if action in ("create_temp_group", "recreate_group"):
        if not created_id or created_id in (old_id, temporary_id) or created_id in state["groups"]:
            raise OmadaError("IP group recovery could not establish a distinct new group identity")
        temporary = action == "create_temp_group"
        state["groups"][created_id] = _swap_group_state({
            "name": operation["temporaryName"] if temporary else operation["original"]["name"],
            "type": 0, "resource": 0,
            "ipList": operation["original"]["ipList"] if temporary else operation["entries"],
        })
    elif action == "delete_old_group":
        del state["groups"][old_id]
    elif action == "delete_temp_group":
        del state["groups"][temporary_id]
    else:
        rid = step["ruleId"]
        before_id, after_id = ((old_id, temporary_id) if action == "repoint_acls_to_temp"
                               else (temporary_id, operation["replacementId"]))
        if not isinstance(before_id, str) or not isinstance(after_id, str):
            raise OmadaError("IP group recovery could not establish the referenced group identities")
        state["rules"][rid] = _swap_rule_group_id(state["rules"][rid], before_id, after_id)
    return state


def _observe_pending(operation: Mapping[str, Any], step: Mapping[str, str],
                     observed: dict[str, Any]) -> tuple[dict[str, Any], str | None] | None:
    if observed == operation["expected"]:
        return None
    action = step["action"]
    created_id = None
    if action in ("create_temp_group", "recreate_group"):
        name = operation["temporaryName"] if action == "create_temp_group" else operation["original"]["name"]
        ids = [gid for gid, row in observed["groups"].items() if row["name"] == name]
        if len(ids) != 1:
            raise OmadaError("IP group recovery could not identify the pending creation")
        created_id = ids[0]
    expected = _swap_transition(operation, step, created_id)
    if observed != expected:
        raise OmadaError("live IP groups or ACLs changed outside the checkpoint; inspect them before recovering")
    return expected, created_id


def replace_ip_group(
    client: OmadaClient,
    group: str,
    cidrs: list[Any] | None = None,
    ipRange: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
    recoveryId: str | None = None,
) -> dict[str, Any]:
    """Replace an IPv4 IP group or resume a checkpointed swap."""
    site = _site(client)
    scope = checkpoint_scope(client)
    groups_before = _fetch_groups(client, site)
    _, acls_before = _fetch_acls(client, site)
    if recoveryId is not None:
        if cidrs is not None or ipRange is not None:
            raise OmadaError("omit cidrs and ipRange when resuming; use the checkpointed entries")
        path = recovery_path(client, recoveryId)
        prior = read_checkpoint(path)
        if prior is None or prior.get("operationId") != recoveryId or prior.get("scope") != scope:
            raise OmadaError("IP group recoveryId is unknown or belongs to a different controller or site")
        if prior.get("finished") is True:
            raise OmadaError("IP group recovery checkpoint is already complete")
        operation = prior
        try:
            target_group = operation["original"]
            group_name = target_group["name"]
            old_id = target_group["id"]
            ref_rules = operation["originalRules"]
            plan = _swap_plan(operation["ruleIds"])
            new_ip_list = pack_ip_entries(cidrs=operation["entries"])
            seen_steps = operation["completed"]
            if (checkpoint_path(client, checkpoint_key(scope, group_name)) != path
                    or not isinstance(seen_steps, list) or len(seen_steps) > len(plan)
                    or type(operation.get("pending")) is not bool
                    or (operation["pending"] and len(seen_steps) == len(plan))
                    or not isinstance(operation.get("expected"), dict)
                    or not isinstance(operation["expected"].get("groups"), dict)
                    or not isinstance(operation["expected"].get("rules"), dict)
                    or not isinstance(ref_rules, list)
                    or sorted(rule["id"] for rule in ref_rules) != operation["ruleIds"]
                    or any(any(event.get(key) != value for key, value in step.items())
                           for event, step in zip(seen_steps, plan, strict=False))):
                raise ValueError("checkpoint fields are inconsistent")
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise OmadaError("IP group recovery checkpoint is inconsistent") from exc
        if group.strip().casefold() not in (group_name.casefold(), old_id.casefold()):
            raise OmadaError("group must match the original name or ID in the recovery checkpoint")
    else:
        new_ip_list = pack_ip_entries(cidrs=cidrs, ip_range=ipRange)
        target_group = _normalize_group_output(project_controller_row("groups", _find_ip_group(groups_before, group)))
        old_id = _group_id(target_group)
        group_name = str(target_group.get("name") or "")
        path = checkpoint_path(client, checkpoint_key(scope, group_name))
        prior = read_checkpoint(path)
        if prior is not None and prior.get("finished") is not True:
            raise OmadaError("an unfinished IP group replacement already exists",
                             hint=f"preview {group_name!r} with recoveryId={prior.get('operationId')!r}")
        used_names = {str(row.get("name") or "").casefold() for row in groups_before}
        tmp_name = f"{group_name}__tmp"
        suffix = 1
        while tmp_name.casefold() in used_names:
            suffix += 1
            tmp_name = f"{group_name}__tmp_{suffix}"
        operation = {"version": 1, "scope": scope, "original": target_group,
                     "entries": new_ip_list, "temporaryName": tmp_name,
                     "ruleIds": [], "temporaryId": None, "replacementId": None,
                     "completed": [], "pending": False, "finished": False}
        observed = _swap_state(groups_before, acls_before, operation)
        operation["ruleIds"] = sorted(observed["rules"])
        ref_rules = [observed["rules"][rid] for rid in operation["ruleIds"]]
        operation["originalRules"] = ref_rules
        operation["expected"] = observed
        plan = _swap_plan(operation["ruleIds"])

    if not old_id or int(target_group.get("resource", 0) or 0) != 0 or group_name == "IPGroup_Any":
        raise OmadaError(f"refusing to replace built-in/protected or unidentified group {group_name!r}")
    group_type = int(target_group.get("type", 0))
    if group_type != 0:
        raise OmadaError("IP group replacement requires an IPv4 IP profile group")
    _require_confirm("replace_ip_group", old_id, dryRun, confirm)

    # Check anti-stranding against any active deny ACL rules referencing this group.
    if ref_rules:
        networks = _fetch_lan_collection(client, site)
        simulated_groups = [
            *[g for g in groups_before if _group_id(g) != old_id],
            {**target_group, "ipList": new_ip_list},
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
    observed = _swap_state(groups_before, acls_before, operation)
    observed_progress = len(operation["completed"])
    if operation["pending"] and observed_progress < len(plan):
        if _observe_pending(operation, plan[observed_progress], observed) is not None:
            observed_progress += 1
    elif observed != operation["expected"]:
        raise OmadaError("live IP groups or ACLs changed outside the checkpoint; inspect them before recovering")
    diff = {"ipList": {"before": old_ip_list, "after": new_ip_list},
            "swapProgress": {"before": observed_progress, "after": len(plan)}}
    warnings = [
        "IP groups do not support PATCH; replacing deletes and recreates the group (non-atomic, receives a new groupId)"
    ]
    if ref_rules:
        warnings.append(
            f"group is referenced by {len(ref_rules)} gateway ACL rule(s) "
            f"({', '.join(str(r.get('name') or r.get('id')) for r in ref_rules)}); "
            f"will execute the {len(plan)}-step temporary-group swap"
        )
    if recoveryId is not None:
        warnings.append("Resume will finish the originally approved swap from the verified checkpoint.")
    steps_plan = [{"step": index, **step} for index, step in enumerate(plan, start=1) if index > observed_progress]

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
            before={**target_group, "swapInventory": observed},
            after=proposed_after,
            diff=diff,
            warnings=warnings,
            rollback=dry_rollback,
            steps=steps_plan,
        )

    completed: list[dict[str, Any]] = operation["completed"]
    snapshots = [str(step["snapshot"]) for step in completed if step.get("snapshot")]
    operation_id = recoveryId or f"{path.stem}-{uuid.uuid4().hex}"
    durable = recoveryId is not None

    def _read_ip_groups() -> list[dict[str, Any]]:
        return [g for g in _fetch_groups(client, site) if int(g.get("type", 0)) == group_type]

    def _delete_group(gid: str, step_label: str, snap_extra: Any) -> str:
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
        return str(res["snapshot"])

    def _create_group(gname: str, glist: list[dict[str, Any]], step_label: str) -> str:
        post_ep = f"sites/{site.site_id}/setting/profiles/groups"
        pairs = _ip_list_canonical(glist)

        def _verify_created(_b: Any, groups_now: Any) -> tuple[bool, str | None]:
            found = next((g for g in groups_now if str(g.get("name")) == gname), None)
            if found is None or not _group_id(found):
                return False, f"group {gname!r} missing after POST"
            if _ip_list_canonical(found.get("ipList") or []) != pairs:
                return False, f"group {gname!r} ipList mismatch after POST"
            return True, None

        def _reauth_create() -> tuple[bool, dict[str, Any] | None, Any]:
            groups_now = _read_ip_groups()
            ok, reason = _verify_created(None, groups_now)
            if not ok and any(str(group.get("name")) == gname for group in groups_now):
                raise OmadaError(reason or f"group {gname!r} changed during session recovery")
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
        return str(res["snapshot"])

    def _repoint_rule(rule: dict[str, Any], from_id: str, to_id: str, step_label: str) -> str:
        rid = str(rule["id"])
        patched_rule = _swap_rule_group_id(rule, from_id, to_id)
        acl_ep = f"sites/{site.site_id}/setting/firewall/acls/{rid}?type=0"

        def _read_rule() -> dict[str, Any] | None:
            _, rules_now = _fetch_acls(client, site)
            return next((r for r in rules_now if str(r.get("id")) == rid), None)

        def _verify_rule(_b: Any, after_rule: Any) -> tuple[bool, str | None]:
            return _verify_rule_references(patched_rule, after_rule)

        def _reauth_rule() -> tuple[bool, dict[str, Any] | None, Any]:
            fresh = _read_rule()
            if fresh is None:
                raise OmadaError(f"ACL rule {rid} disappeared during IP group replacement")
            ok, _ = _verify_rule(rule, fresh)
            if ok:
                return True, None, None
            if project_controller_row("acls", rule) != project_controller_row("acls", fresh):
                raise OmadaError(f"ACL rule {rid} changed during session recovery")
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
        return str(res["snapshot"])

    def _execute_step(step: Mapping[str, str], live_rules: Sequence[dict[str, Any]]) -> str:
        action = step["action"]
        if action == "create_temp_group":
            return _create_group(operation["temporaryName"], old_ip_list, action)
        if action == "recreate_group":
            return _create_group(group_name, new_ip_list, action)
        if action == "delete_old_group":
            return _delete_group(old_id, action, {"targetGroup": target_group, "tmpId": operation["temporaryId"]})
        if action == "delete_temp_group":
            return _delete_group(operation["temporaryId"], action, {"newId": operation["replacementId"]})
        rule_id = step["ruleId"]
        rule = next(row for row in live_rules if str(row.get("id")) == rule_id)
        if action == "repoint_acls_to_temp":
            return _repoint_rule(rule, old_id, operation["temporaryId"], action)
        return _repoint_rule(rule, operation["temporaryId"], operation["replacementId"], action)

    def _finish_step(step: Mapping[str, str], checked: tuple[dict[str, Any], str | None],
                     snapshot: str | None) -> None:
        state, group_id = checked
        event: dict[str, Any] = dict(step)
        if group_id is not None:
            key = "temporaryId" if step["action"] == "create_temp_group" else "replacementId"
            operation[key] = group_id
            event["groupId"] = group_id
        if snapshot is None:
            event["reconciled"] = True
        else:
            event["snapshot"] = snapshot
            snapshots.append(snapshot)
        completed.append(event)
        operation["expected"] = state
        operation["pending"] = False
        persist_checkpoint(path, operation)

    try:
        with claim_checkpoint(client, path):
            if read_checkpoint(path) != prior:
                raise OmadaError("IP group recovery checkpoint changed; preview the current state again")
            if not durable:
                operation["operationId"] = operation_id
                persist_checkpoint(path, operation)
                durable = True
            for step in plan[len(completed):]:
                live_groups, (_, live_rules) = _fetch_groups(client, site), _fetch_acls(client, site)
                observed = _swap_state(live_groups, live_rules, operation)
                if operation["pending"]:
                    reconciled = _observe_pending(operation, step, observed)
                    if reconciled is not None:
                        _finish_step(step, reconciled, None)
                        continue
                elif observed != operation["expected"]:
                    raise OmadaError("live IP groups or ACLs changed outside the checkpoint; inspect them before recovering")
                operation["pending"] = True
                persist_checkpoint(path, operation)
                latest_snapshot = _execute_step(step, live_rules)
                live_groups, (_, live_rules) = _fetch_groups(client, site), _fetch_acls(client, site)
                checked = _observe_pending(operation, step, _swap_state(live_groups, live_rules, operation))
                if checked is None:
                    raise OmadaError(f"live state did not verify the {step['action']} step")
                _finish_step(step, checked, latest_snapshot)

            new_id = operation["replacementId"]
            final_groups, (_, final_acls) = _fetch_groups(client, site), _fetch_acls(client, site)
            final_group = next((g for g in final_groups if _group_id(g) == new_id), None)
            if final_group is None or _swap_state(final_groups, final_acls, operation) != operation["expected"]:
                raise OmadaError("final IP group verification failed after replace_ip_group")
            operation["finished"] = True
            persist_checkpoint(path, operation)
    except OmadaError as exc:
        if not durable:
            raise
        failure = OmadaError(
            f"replace_ip_group failed mid-operation after {len(completed)} step(s): {exc.message}",
            code=exc.code,
            hint=(
                f"completed steps={json_summary(completed)}; "
                f"inspect the live inventory, then preview group={group_name!r} "
                f"with recoveryId={operation_id!r} and omit cidrs and ipRange"
            ),
            endpoint=exc.endpoint,
        )
        failure.write_status = {**(exc.write_status or {"outcome": "uncertain", "verified": False,
                                                       "snapshot": snapshots[-1] if snapshots else None}),
                                "recoveryId": operation_id}
        raise failure from None

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
        after=_normalize_group_output(project_controller_row("groups", final_group)),
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


def _pack_port_entries(ports: Sequence[Any]) -> list[str]:
    if not ports:
        raise OmadaError(
            "at least one port or port range is required",
            hint="provide ports e.g. ['80', '443', '8000-8080']",
        )
    out: list[str] = []
    seen: set[str] = set()
    for raw in ports:
        norm = _port_range_valid(str(raw), label="portList entry").replace(" ", "")
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def _pack_mac_entries(entries: Sequence[Any]) -> list[dict[str, str]]:
    if not entries:
        raise OmadaError(
            "at least one MAC address entry is required",
            hint="provide entries e.g. [{'name': 'printer', 'mac': 'AA:BB:CC:DD:EE:01'}] or ['AA:BB:CC:DD:EE:01']",
        )
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for idx, raw in enumerate(entries, start=1):
        if isinstance(raw, Mapping):
            raw_mac = str(raw.get("macAddress") or raw.get("mac") or "").strip()
            entry_name = str(raw.get("name") or f"entry-{idx}").strip() or f"entry-{idx}"
        else:
            raw_mac = str(raw or "").strip()
            entry_name = f"entry-{idx}"
        norm = _normalize_mac(raw_mac)
        if len(norm) != 17 or ":" not in norm:
            raise OmadaError(f"invalid MAC address {raw_mac!r}")
        wire_mac = _omada_mac(norm)
        if wire_mac in seen:
            continue
        seen.add(wire_mac)
        out.append({"name": entry_name[:64], "macAddress": wire_mac})
    return out


def _acl_refs_for_group(client: OmadaClient, site: Any, gid: str) -> list[str]:
    refs: list[str] = []
    for acl_type in (0, 1, 2):
        try:
            rules = _fetch_typed_acls(client, site, acl_type)
        except OmadaError:
            continue
        for rule in rules:
            sids = [str(x) for x in (rule.get("sourceIds") or [])]
            dids = [str(x) for x in (rule.get("destinationIds") or [])]
            if gid in sids or gid in dids:
                refs.append(str(rule.get("name") or rule.get("id")))
    return refs


def _upsert_profile_group(
    client: OmadaClient,
    *,
    tool_name: str,
    group_type: int,
    type_label: str,
    name: str,
    group_id: str | None,
    body: dict[str, Any],
    diff_keys: tuple[str, ...],
    canon_fn: Any,
    rollback_builder: Any,
    dry_run: bool,
    confirm: str | None,
) -> dict[str, Any]:
    clean_name = str(name or "").strip()
    if not clean_name or len(clean_name) > 64:
        raise OmadaError(f"{type_label} group name must be 1..64 characters")

    site = _site(client)
    groups = _fetch_groups(client, site)
    existing: dict[str, Any] | None = None
    if group_id:
        existing = _find_typed_group(groups, group_id, group_type=group_type, type_label=type_label)
    else:
        existing = next(
            (dict(g) for g in groups if int(g.get("type", 0)) == group_type and str(g.get("name") or "").strip() == clean_name),
            None,
        )

    is_update = existing is not None
    existing_id = _group_id(existing) if existing is not None else ""
    if existing is not None and (int(existing.get("resource", 0) or 0) != 0 or bool(existing.get("default"))):
        raise OmadaError(f"refusing to modify built-in/protected {type_label} group {existing.get('name') or existing_id!r}")

    target_id = existing_id if is_update and existing_id else clean_name
    _require_confirm(tool_name, target_id, dry_run, confirm)

    diff = _field_diff(existing or {}, body, diff_keys)
    dry_rollback = rollback_builder(existing) if is_update and existing is not None else None
    if dry_run:
        return _dry_run_result(
            tool_name=tool_name,
            target_id=target_id,
            before=existing,
            after={**({"groupId": existing_id} if existing_id else {}), **body},
            diff=diff,
            warnings=[],
            rollback=dry_rollback,
        )

    expected_canon = canon_fn(body)
    existing_ids = [_group_id(g) for g in groups if _group_id(g)]
    method = "PATCH" if is_update else "POST"
    endpoint = (
        f"sites/{site.site_id}/setting/profiles/groups/{group_type}/{existing_id}"
        if is_update
        else f"sites/{site.site_id}/setting/profiles/groups"
    )
    snap_payload = (
        {"action": "update", "groupType": group_type, "group": copy.deepcopy(existing)}
        if is_update
        else {"action": "create", "groupType": group_type, "name": clean_name, "existingIds": existing_ids}
    )

    def _read_back() -> dict[str, Any]:
        rows_now = [g for g in _fetch_groups(client, site) if int(g.get("type", 0)) == group_type]
        if is_update:
            found = next((g for g in rows_now if _group_id(g) == existing_id), None)
        else:
            found = next((g for g in rows_now if str(g.get("name") or "").strip() == clean_name), None)
        return dict(found) if found is not None else {}

    def _verify(_b: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping) or not after_now:
            return False, f"{type_label} group {clean_name!r} missing after {method}"
        if canon_fn(after_now) != expected_canon:
            return False, f"{type_label} group {clean_name!r} entries mismatch after {method}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(existing, live)
        return ok, body, live

    write_res = client.write(
        endpoint,
        method=method,
        data=body,
        tool_name=tool_name,
        target=target_id,
        before=existing,
        snapshot_payload=snap_payload,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()) or [diff_keys[-1]],
    )
    after_obj = write_res["after"]
    new_id = _group_id(after_obj) if isinstance(after_obj, Mapping) else existing_id
    delete_tool = "delete_port_group" if group_type == 1 else "delete_mac_group"
    committed_rollback = (
        dry_rollback
        if is_update
        else {"tool": delete_tool, "arguments": {"group": new_id or clean_name, "dryRun": True}}
    )
    return _committed_result(
        tool_name=tool_name,
        target_id=target_id,
        before=write_res["before"],
        after=after_obj,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=committed_rollback,
    )


def _delete_profile_group(
    client: OmadaClient,
    *,
    tool_name: str,
    group: str,
    group_type: int,
    type_label: str,
    label: str,
    dry_run: bool,
    confirm: str | None,
) -> dict[str, Any]:
    site = _site(client)
    groups = _fetch_groups(client, site)
    target_grp = _find_typed_group(groups, group, group_type=group_type, type_label=type_label)
    target_id = _group_id(target_grp)
    if bool(target_grp.get("default")) or int(target_grp.get("resource", 0) or 0) != 0:
        raise OmadaError(f"refusing to delete built-in/protected {type_label} group {target_grp.get('name') or target_id!r}")

    refs = _acl_refs_for_group(client, site, target_id)
    if refs:
        raise OmadaError(
            f"cannot delete {type_label} group {target_grp.get('name')!r}: referenced by ACL rule(s) {', '.join(refs)} (-33717)",
            code=-33717,
            hint="update or delete the referencing ACL rule(s) first",
        )

    return _delete_entity(
        client,
        tool_name=tool_name,
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/profiles/groups/{group_type}/{target_id}",
        before=target_grp,
        snapshot_payload={"action": "delete", "groupType": group_type, "group": copy.deepcopy(target_grp)},
        fetch_all=lambda: _fetch_groups(client, site),
        match_fn=lambda row: _group_id(row) == target_id,
        rollback=None,
        warnings=[],
        dry_run=dry_run,
        confirm=confirm,
        label=label,
    )


def _port_group_canon(row: Mapping[str, Any]) -> tuple[Any, ...]:
    ports = sorted(str(p).strip() for p in (row.get("portList") or []) if p is not None)
    return (str(row.get("name") or ""), _ip_list_canonical(row.get("ipList") or []), tuple(ports))


def _mac_group_canon(row: Mapping[str, Any]) -> tuple[Any, ...]:
    macs = sorted(
        (str(m.get("name") or ""), _omada_mac(_normalize_mac(str(m.get("macAddress") or m.get("mac") or ""))))
        for m in (row.get("macAddressList") or [])
        if isinstance(m, Mapping)
    )
    return (str(row.get("name") or ""), tuple(macs))


def upsert_port_group(
    client: OmadaClient,
    name: str,
    ports: list[Any],
    ips: list[Any] | None = None,
    groupId: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a TCP/UDP port group (``type=1`` on ``setting/profiles/groups``)."""
    clean_name = str(name or "").strip()
    port_list = _pack_port_entries(ports)
    ip_list = pack_ip_entries(cidrs=ips) if ips else []
    body = {"name": clean_name, "type": 1, "ipList": ip_list, "portList": port_list}
    return _upsert_profile_group(
        client,
        tool_name="upsert_port_group",
        group_type=1,
        type_label="IP-Port",
        name=clean_name,
        group_id=groupId,
        body=body,
        diff_keys=("name", "ipList", "portList"),
        canon_fn=_port_group_canon,
        rollback_builder=lambda ex: {
            "tool": "upsert_port_group",
            "arguments": {
                "groupId": _group_id(ex),
                "name": ex.get("name"),
                "ports": list(ex.get("portList") or []),
                "ips": [f"{i.get('ip')}/{i.get('mask', 32)}" for i in (ex.get("ipList") or []) if isinstance(i, Mapping)],
                "dryRun": True,
            },
        },
        dry_run=dryRun,
        confirm=confirm,
    )


def delete_port_group(
    client: OmadaClient,
    group: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete an unreferenced IP-Port group (``DELETE setting/profiles/groups/1/{id}``)."""
    return _delete_profile_group(
        client,
        tool_name="delete_port_group",
        group=group,
        group_type=1,
        type_label="IP-Port",
        label="portGroup",
        dry_run=dryRun,
        confirm=confirm,
    )


def upsert_mac_group(
    client: OmadaClient,
    name: str,
    entries: list[Any],
    groupId: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a MAC address group (``type=2`` on ``setting/profiles/groups``)."""
    clean_name = str(name or "").strip()
    mac_list = _pack_mac_entries(entries)
    body = {"name": clean_name, "type": 2, "macAddressList": mac_list}
    return _upsert_profile_group(
        client,
        tool_name="upsert_mac_group",
        group_type=2,
        type_label="MAC",
        name=clean_name,
        group_id=groupId,
        body=body,
        diff_keys=("name", "macAddressList"),
        canon_fn=_mac_group_canon,
        rollback_builder=lambda ex: {
            "tool": "upsert_mac_group",
            "arguments": {
                "groupId": _group_id(ex),
                "name": ex.get("name"),
                "entries": list(ex.get("macAddressList") or []),
                "dryRun": True,
            },
        },
        dry_run=dryRun,
        confirm=confirm,
    )


def delete_mac_group(
    client: OmadaClient,
    group: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete an unreferenced MAC address group (``DELETE setting/profiles/groups/2/{id}``)."""
    return _delete_profile_group(
        client,
        tool_name="delete_mac_group",
        group=group,
        group_type=2,
        type_label="MAC",
        label="macGroup",
        dry_run=dryRun,
        confirm=confirm,
    )

