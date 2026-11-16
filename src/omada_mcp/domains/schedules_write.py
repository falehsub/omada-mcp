"""Write domain module: schedules_write."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import as_int, deep_redact, resolve_raw_device
from ._write_common import (
    _committed_result,
    _delete_entity,
    _dry_run_result,
    _field_diff,
    _normalize_mac,
    _require_confirm,
    _resolve_by_id_or_name,
    _site,
)
from ._write_fetchers import (
    _fetch_acls,
    _fetch_poe_schedules,
    _fetch_schedules,
    _omada_mac,
)

_DAY_MODE_MAP: dict[str, int] = {
    "everyday": 0,
    "all": 0,
    "0": 0,
    "weekday": 1,
    "weekdays": 1,
    "1": 1,
    "weekend": 2,
    "weekends": 2,
    "2": 2,
    "custom": 3,
    "3": 3,
}

_DAY_NAME_TO_CODE: dict[str, int] = {
    "mon": 1, "monday": 1, "1": 1,
    "tue": 2, "tuesday": 2, "2": 2,
    "wed": 3, "wednesday": 3, "3": 3,
    "thu": 4, "thursday": 4, "4": 4,
    "fri": 5, "friday": 5, "5": 5,
    "sat": 6, "saturday": 6, "6": 6,
    "sun": 7, "sunday": 7, "7": 7,
}

_DAY_CODE_FIELDS: dict[int, str] = {
    1: "dayMon", 2: "dayTue", 3: "dayWed", 4: "dayThu",
    5: "dayFri", 6: "daySat", 7: "daySun",
}


def _parse_hhmm(value: Any, *, allow_24: bool) -> tuple[int, int]:
    text = str(value or "").strip()
    if ":" not in text:
        raise OmadaError(f"invalid time {value!r}; expected 'HH:MM'")
    parts = text.split(":", 1)
    try:
        hh, mm = int(parts[0]), int(parts[1])
    except ValueError:
        raise OmadaError(f"invalid time {value!r}; expected 'HH:MM'") from None
    if hh == 24 and mm == 0 and allow_24:
        return 24, 0
    if not (0 <= hh <= 23 and 0 <= mm <= 59):
        raise OmadaError(f"time {value!r} out of range (00:00..24:00)")
    return hh, mm


def _parse_day_mode(day_mode: Any) -> int:
    if isinstance(day_mode, bool):
        raise OmadaError(f"invalid dayMode {day_mode!r}")
    if isinstance(day_mode, int) and str(day_mode) in _DAY_MODE_MAP:
        return _DAY_MODE_MAP[str(day_mode)]
    key = str(day_mode or "").strip().lower()
    if key in _DAY_MODE_MAP:
        return _DAY_MODE_MAP[key]
    raise OmadaError(
        f"invalid dayMode {day_mode!r}",
        hint="valid values: 'everyday' (0), 'weekday' (1), 'weekend' (2), or 'custom' (3)",
    )


def _resolve_day_flags(mode: int, days: Sequence[Any] | None) -> tuple[dict[str, bool], list[int]]:
    if mode == 0:
        codes = [1, 2, 3, 4, 5, 6, 7]
    elif mode == 1:
        codes = [1, 2, 3, 4, 5]
    elif mode == 2:
        codes = [6, 7]
    else:
        if not days:
            raise OmadaError(
                "days is required when dayMode='custom'",
                hint="pass days e.g. ['mon', 'tue', 'wed'] or [1, 2, 3]",
            )
        codes = []
        for d in days:
            key = str(d or "").strip().lower()
            if key not in _DAY_NAME_TO_CODE:
                raise OmadaError(f"invalid day {d!r}", hint="use mon..sun or 1..7")
            code = _DAY_NAME_TO_CODE[key]
            if code not in codes:
                codes.append(code)
    flags = {field: (code in codes) for code, field in _DAY_CODE_FIELDS.items()}
    return flags, codes


def _build_time_list(
    mode: int,
    custom_codes: list[int],
    windows: Sequence[Mapping[str, Any]],
) -> list[dict[str, int]]:
    if not windows:
        raise OmadaError(
            "at least one time window is required",
            hint="provide windows=[{'start': '08:00', 'end': '17:00'}]",
        )
    default_day_type = {0: 0, 1: -1, 2: -2}.get(mode, 1)
    entries: list[dict[str, int]] = []
    for win in windows:
        if not isinstance(win, Mapping):
            raise OmadaError("each time window must be an object with start/end or startTimeH/endTimeH")
        if "start" in win and "end" in win:
            sh, sm = _parse_hhmm(win["start"], allow_24=False)
            eh, em = _parse_hhmm(win["end"], allow_24=True)
        else:
            sh = as_int(win.get("startTimeH"), -1)
            sm = as_int(win.get("startTimeM"), 0)
            eh = as_int(win.get("endTimeH"), -1)
            em = as_int(win.get("endTimeM"), 0)
            if not (0 <= sh <= 23 and 0 <= sm <= 59 and (eh == 24 and em == 0 or (0 <= eh <= 23 and 0 <= em <= 59))):
                raise OmadaError(f"invalid time window {dict(win)!r}")
        if (eh * 60 + em) <= (sh * 60 + sm):
            raise OmadaError(f"time window end ({eh:02d}:{em:02d}) must follow start ({sh:02d}:{sm:02d})")

        if win.get("day") is not None:
            dkey = str(win["day"]).strip().lower()
            if dkey not in _DAY_NAME_TO_CODE:
                raise OmadaError(f"invalid window day {win['day']!r}")
            target_types = [_DAY_NAME_TO_CODE[dkey]]
        elif win.get("dayType") is not None:
            target_types = [as_int(win["dayType"], default_day_type)]
        elif mode == 3:
            target_types = list(custom_codes)
        else:
            target_types = [default_day_type]

        for dtype in target_types:
            entries.append({
                "dayType": dtype,
                "startTimeH": sh,
                "startTimeM": sm,
                "endTimeH": eh,
                "endTimeM": em,
            })
    return entries


def _schedule_canonical(row: Mapping[str, Any]) -> tuple[Any, ...]:
    slots = sorted(
        (
            as_int(s.get("dayType"), 0),
            as_int(s.get("startTimeH"), 0),
            as_int(s.get("startTimeM"), 0),
            as_int(s.get("endTimeH"), 0),
            as_int(s.get("endTimeM"), 0),
        )
        for s in (row.get("timeList") or [])
        if isinstance(s, Mapping)
    )
    return (
        str(row.get("name") or ""),
        as_int(row.get("dayMode"), 0),
        tuple(bool(row.get(f, False)) for f in _DAY_CODE_FIELDS.values()),
        tuple(slots),
    )


def upsert_schedule(
    client: OmadaClient,
    name: str,
    windows: list[dict[str, Any]],
    dayMode: Any = "everyday",
    days: list[Any] | None = None,
    scheduleId: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a reusable schedule/time-range profile (``setting/profiles/timeranges``)."""
    clean_name = str(name or "").strip()
    if not clean_name or len(clean_name) > 64:
        raise OmadaError("schedule name must be 1..64 characters")

    mode = _parse_day_mode(dayMode)
    if mode == 3 and not days and any(isinstance(w, Mapping) and w.get("day") is not None for w in (windows or [])):
        days = [w["day"] for w in windows if isinstance(w, Mapping) and w.get("day") is not None]
    day_flags, custom_codes = _resolve_day_flags(mode, days)
    time_list = _build_time_list(mode, custom_codes, windows or [])

    site = _site(client)
    existing_all = _fetch_schedules(client, site)
    existing: dict[str, Any] | None = None
    if scheduleId:
        existing = _resolve_by_id_or_name(existing_all, str(scheduleId), label="schedule")
    else:
        existing = next(
            (dict(r) for r in existing_all if str(r.get("name") or "").strip() == clean_name),
            None,
        )

    is_update = existing is not None
    existing_id = str(existing.get("id") or "") if existing else ""
    target_id = existing_id if is_update and existing_id else clean_name
    _require_confirm("upsert_schedule", target_id, dryRun, confirm)

    body: dict[str, Any] = {
        "name": clean_name,
        "dayMode": mode,
        **day_flags,
        "timeList": time_list,
    }
    before_obj = copy.deepcopy(existing) if is_update else None
    diff = _field_diff(before_obj or {}, body, ("name", "dayMode", *_DAY_CODE_FIELDS.values(), "timeList"))
    dry_rollback: dict[str, Any] | None = None
    if is_update and existing is not None:
        dry_rollback = {
            "tool": "upsert_schedule",
            "arguments": {
                "scheduleId": existing_id,
                "name": existing.get("name"),
                "dayMode": existing.get("dayMode", 0),
                "windows": list(existing.get("timeList") or []),
                "dryRun": True,
            },
        }

    if dryRun:
        return _dry_run_result(
            tool_name="upsert_schedule",
            target_id=target_id,
            before=before_obj,
            after={**({"id": existing_id} if existing_id else {}), **body},
            diff=diff,
            warnings=[],
            rollback=dry_rollback,
        )

    expected_canon = _schedule_canonical(body)
    existing_ids = [str(r.get("id")) for r in existing_all if r.get("id")]
    method = "PATCH" if is_update else "POST"
    endpoint = (
        f"sites/{site.site_id}/setting/profiles/timeranges/{existing_id}"
        if is_update
        else f"sites/{site.site_id}/setting/profiles/timeranges"
    )
    snap_payload = (
        {"action": "update", "schedule": copy.deepcopy(existing)}
        if is_update
        else {"action": "create", "name": clean_name, "existingIds": existing_ids}
    )

    def _read_back() -> dict[str, Any]:
        rows_now = _fetch_schedules(client, site)
        if is_update:
            found = next((r for r in rows_now if str(r.get("id")) == existing_id), None)
        else:
            found = next((r for r in rows_now if str(r.get("name") or "").strip() == clean_name), None)
        return dict(found) if found is not None else {}

    def _verify(_b: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping) or not after_now:
            return False, f"schedule {clean_name!r} missing after {method}"
        if _schedule_canonical(after_now) != expected_canon:
            return False, f"schedule {clean_name!r} payload mismatch after {method}"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        ok, _ = _verify(before_obj, live)
        return ok, body, live

    write_res = client.write(
        endpoint,
        method=method,
        data=body,
        tool_name="upsert_schedule",
        target=target_id,
        before=before_obj,
        snapshot_payload=snap_payload,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()) or ["timeList"],
    )
    after_obj = write_res["after"]
    new_id = str(after_obj.get("id") or existing_id or target_id)
    committed_rollback = (
        dry_rollback
        if is_update
        else {"tool": "delete_schedule", "arguments": {"schedule": new_id, "dryRun": True}}
    )
    return _committed_result(
        tool_name="upsert_schedule",
        target_id=target_id,
        before=write_res["before"],
        after=after_obj,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=[],
        rollback=committed_rollback,
    )


def delete_schedule(
    client: OmadaClient,
    schedule: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a time-range / schedule profile by ID or exact name."""
    site = _site(client)
    schedules = _fetch_schedules(client, site)
    target_sched = _resolve_by_id_or_name(schedules, schedule, label="schedule")
    target_id = str(target_sched.get("id") or "")
    if int(target_sched.get("resource", 0) or 0) != 0:
        raise OmadaError(f"refusing to delete protected/built-in schedule {target_sched.get('name') or target_id!r}")

    refs: list[str] = []
    try:
        _, acls = _fetch_acls(client, site)
    except OmadaError:
        acls = []
    for rule in acls:
        if str(rule.get("timeRangeId") or rule.get("scheduleId") or "") == target_id:
            refs.append(f"ACL:{rule.get('name') or rule.get('id')}")
    try:
        for poe_row in _fetch_poe_schedules(client, site):
            if str(poe_row.get("turnOnTime") or "") == target_id:
                refs.append(f"PoE:{poe_row.get('name') or poe_row.get('id')}")
    except OmadaError:
        pass
    if refs:
        raise OmadaError(
            f"cannot delete schedule {target_sched.get('name')!r}: referenced by {', '.join(refs)}",
            hint="remove the schedule reference from the ACL/feature before deleting it",
        )

    rollback = {
        "tool": "upsert_schedule",
        "arguments": {
            "name": target_sched.get("name"),
            "dayMode": target_sched.get("dayMode", 0),
            "windows": list(target_sched.get("timeList") or []),
            "dryRun": True,
        },
    }
    return _delete_entity(
        client,
        tool_name="delete_schedule",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/profiles/timeranges/{target_id}",
        before=target_sched,
        snapshot_payload={"action": "delete", "schedule": copy.deepcopy(target_sched)},
        fetch_all=lambda: _fetch_schedules(client, site),
        match_fn=lambda row: str(row.get("id") or "") == target_id,
        rollback=rollback,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="schedule",
    )


def _normalize_poe_ports_map(
    client: OmadaClient,
    site: Any,
    raw_bindings: Mapping[str, Any] | None,
) -> tuple[dict[str, list[int]], list[str]]:
    if not raw_bindings:
        return {}, []
    if not isinstance(raw_bindings, Mapping):
        raise OmadaError("portBindings must map switch MAC/name -> list of PoE port numbers")
    out: dict[str, list[int]] = {}
    warnings: list[str] = []
    for dev_key, raw_ports in raw_bindings.items():
        if not isinstance(raw_ports, Sequence) or isinstance(raw_ports, (str, bytes)):
            raise OmadaError(f"ports for switch {dev_key!r} must be a list of port integers")
        sw = resolve_raw_device(client, site, str(dev_key), expected_type="switch")
        omada_mac = _omada_mac(str(sw.get("mac") or dev_key))
        clean_ports: list[int] = []
        raw_port_map = {as_int(p.get("port"), 0): p for p in (sw.get("ports") or []) if isinstance(p, Mapping)}
        for pno in raw_ports:
            if not isinstance(pno, int) or isinstance(pno, bool) or pno <= 0:
                raise OmadaError(f"invalid port number {pno!r} for switch {dev_key!r}")
            p_row = raw_port_map.get(pno)
            if p_row is not None and not bool(p_row.get("supportPoe", True)):
                raise OmadaError(f"switch {omada_mac} port {pno} does not support PoE")
            if pno not in clean_ports:
                clean_ports.append(pno)
        if clean_ports:
            out[omada_mac] = sorted(clean_ports)
            warnings.append(f"PoE schedule controls power on {_normalize_mac(omada_mac)} ports {out[omada_mac]}.")
    return out, warnings


def upsert_poe_schedule(
    client: OmadaClient,
    name: str,
    poeScheduleId: str | None = None,
    schedule: str | None = None,
    enabled: bool | None = None,
    portBindings: Mapping[str, Any] | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create or update a site PoE power schedule (``setting/service/poeSchedules``)."""
    poe_name = str(name or "").strip()
    if not poe_name:
        raise OmadaError("PoE schedule name must be non-empty")

    site = _site(client)
    existing_rows = _fetch_poe_schedules(client, site)
    existing: dict[str, Any] | None = None
    if poeScheduleId:
        existing = _resolve_by_id_or_name(existing_rows, str(poeScheduleId), label="PoE schedule")
    else:
        matches = [dict(r) for r in existing_rows if str(r.get("name") or "").strip() == poe_name]
        if matches:
            existing = matches[0]

    is_update = existing is not None
    existing_id = str(existing.get("id") or "") if existing else ""
    target_id = existing_id or poe_name
    _require_confirm("upsert_poe_schedule", target_id, dryRun, confirm)

    if schedule is not None and str(schedule).strip():
        sched_obj = _resolve_by_id_or_name(_fetch_schedules(client, site), str(schedule), label="schedule")
        turn_on_id = str(sched_obj["id"])
    elif existing is not None and existing.get("turnOnTime"):
        turn_on_id = str(existing["turnOnTime"])
    else:
        raise OmadaError("schedule (time-range profile ID or exact name) is required when creating a PoE schedule")

    if portBindings is not None:
        ports_map, bind_warnings = _normalize_poe_ports_map(client, site, portBindings)
    else:
        raw_existing_map = (existing or {}).get("poePortsMap") or {}
        ports_map = {
            _omada_mac(str(k)): [as_int(p, 0) for p in (v or [])]
            for k, v in raw_existing_map.items()
            if isinstance(k, str)
        }
        bind_warnings = []

    en_val = bool(enabled) if enabled is not None else bool((existing or {}).get("status", True))
    body: dict[str, Any] = {
        "name": poe_name,
        "status": en_val,
        "turnOnTime": turn_on_id,
        "poePortsMap": ports_map,
    }
    before_clean = deep_redact(existing) if existing else None
    after_preview = {**(before_clean or {}), **body}
    diff = _field_diff(before_clean or {}, after_preview, ["name", "status", "turnOnTime", "poePortsMap"])

    dry_rollback = (
        {
            "tool": "upsert_poe_schedule",
            "arguments": {
                "poeScheduleId": existing_id,
                "name": existing.get("name"),
                "schedule": existing.get("turnOnTime"),
                "enabled": bool(existing.get("status", True)),
                "portBindings": dict(existing.get("poePortsMap") or {}),
                "dryRun": True,
            },
        }
        if existing is not None
        else None
    )
    if dryRun:
        return _dry_run_result(
            tool_name="upsert_poe_schedule",
            target_id=target_id,
            before=before_clean,
            after=after_preview,
            diff=diff,
            warnings=bind_warnings,
            rollback=dry_rollback,
        )

    existing_ids = {str(r.get("id")) for r in existing_rows if r.get("id")}
    endpoint = (
        f"sites/{site.site_id}/setting/service/poeSchedules/{existing_id}"
        if is_update
        else f"sites/{site.site_id}/setting/service/poeSchedules"
    )
    method = "PUT" if is_update else "POST"

    def _read_back() -> dict[str, Any] | None:
        rows = _fetch_poe_schedules(client, site)
        # Omada PUT on poeSchedules may assign a new ID; match by exact name cleanly.
        matched = next((dict(r) for r in rows if str(r.get("name") or "").strip() == poe_name), None)
        if matched is not None:
            return matched
        if existing_id:
            return next((dict(r) for r in rows if str(r.get("id")) == existing_id), None)
        return None

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, f"PoE schedule {poe_name!r} not found after {method}"
        if str(after_now.get("turnOnTime") or "") != turn_on_id:
            return False, f"turnOnTime expected {turn_on_id!r}, got {after_now.get('turnOnTime')!r}"
        if bool(after_now.get("status", True)) != en_val:
            return False, "PoE schedule enabled status did not persist"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        live = _read_back()
        if is_update:
            ok, _ = _verify(existing, live)
            return ok, body, live
        return (live is not None), body, live

    write_res = client.write(
        endpoint,
        method=method,
        data=body,
        tool_name="upsert_poe_schedule",
        target=target_id,
        before=before_clean,
        snapshot_payload={
            "action": "update" if is_update else "create",
            "poeSchedule": copy.deepcopy(existing),
            "existingIds": sorted(existing_ids),
            "name": poe_name,
        },
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=sorted(diff.keys()) or ["poePortsMap"],
    )
    after_obj = deep_redact(write_res["after"])
    new_id = str((write_res["after"] or {}).get("id") or existing_id or target_id)
    committed_rb = (
        dry_rollback
        if is_update
        else {"tool": "delete_poe_schedule", "arguments": {"poeSchedule": new_id, "dryRun": True}}
    )
    return _committed_result(
        tool_name="upsert_poe_schedule",
        target_id=target_id,
        before=write_res["before"],
        after=after_obj,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=bind_warnings,
        rollback=committed_rb,
    )


def bind_poe_schedule(
    client: OmadaClient,
    poeSchedule: str,
    mac: str,
    ports: Sequence[int],
    replace: bool = False,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Bind or unbind a switch's PoE ports on an existing PoE schedule."""
    if not isinstance(ports, Sequence) or isinstance(ports, (str, bytes)):
        raise OmadaError("ports must be a list of port integers")
    site = _site(client)
    rows = _fetch_poe_schedules(client, site)
    sched = _resolve_by_id_or_name(rows, poeSchedule, label="PoE schedule")
    sched_id = str(sched.get("id") or "")
    sched_name = str(sched.get("name") or sched_id)

    sw = resolve_raw_device(client, site, mac, expected_type="switch")
    omada_mac = _omada_mac(str(sw.get("mac") or mac))
    norm_mac = _normalize_mac(omada_mac)
    target_id = f"{sched_id}:{norm_mac}"
    _require_confirm("bind_poe_schedule", target_id, dryRun, confirm)

    raw_port_map = {as_int(p.get("port"), 0): p for p in (sw.get("ports") or []) if isinstance(p, Mapping)}
    req_ports: list[int] = []
    for pno in ports:
        if not isinstance(pno, int) or isinstance(pno, bool) or pno <= 0:
            raise OmadaError(f"invalid port {pno!r}")
        p_row = raw_port_map.get(pno)
        if p_row is not None and not bool(p_row.get("supportPoe", True)):
            raise OmadaError(f"switch {norm_mac} port {pno} does not support PoE")
        if pno not in req_ports:
            req_ports.append(pno)

    cur_map = {
        _omada_mac(str(k)): sorted({as_int(p, 0) for p in (v or [])})
        for k, v in (sched.get("poePortsMap") or {}).items()
        if isinstance(k, str)
    }
    new_map = copy.deepcopy(cur_map)
    if replace:
        if req_ports:
            new_map[omada_mac] = sorted(req_ports)
        else:
            new_map.pop(omada_mac, None)
    else:
        existing_ports = set(new_map.get(omada_mac, []))
        existing_ports.update(req_ports)
        if existing_ports:
            new_map[omada_mac] = sorted(existing_ports)

    warnings = [f"PoE schedule {sched_name!r} updated for {norm_mac} ports {new_map.get(omada_mac, [])}."]
    body = {
        "name": sched_name,
        "status": bool(sched.get("status", True)),
        "turnOnTime": str(sched.get("turnOnTime") or ""),
        "poePortsMap": new_map,
    }
    before_summary = {"id": sched_id, "name": sched_name, "poePortsMap": cur_map}
    after_summary = {"id": sched_id, "name": sched_name, "poePortsMap": new_map}
    diff = _field_diff(before_summary, after_summary, ["poePortsMap"])
    rollback = {
        "tool": "bind_poe_schedule",
        "arguments": {
            "poeSchedule": sched_name,
            "mac": norm_mac,
            "ports": cur_map.get(omada_mac, []),
            "replace": True,
            "dryRun": True,
        },
    }
    if dryRun:
        return _dry_run_result(
            tool_name="bind_poe_schedule",
            target_id=target_id,
            before=before_summary,
            after=after_summary,
            diff=diff,
            warnings=warnings,
            rollback=rollback,
        )

    def _read_back() -> dict[str, Any] | None:
        now = next((dict(r) for r in _fetch_poe_schedules(client, site) if str(r.get("name") or "").strip() == sched_name), None)
        if now is None:
            return None
        return {
            "id": str(now.get("id") or ""),
            "name": sched_name,
            "poePortsMap": {
                _omada_mac(str(k)): sorted({as_int(p, 0) for p in (v or [])})
                for k, v in (now.get("poePortsMap") or {}).items()
                if isinstance(k, str)
            },
        }

    def _verify(_before: Any, after_now: Any) -> tuple[bool, str | None]:
        if not isinstance(after_now, Mapping):
            return False, f"PoE schedule {sched_name!r} not found after PUT"
        if after_now.get("poePortsMap") != new_map:
            return False, "poePortsMap binding mismatch after PUT"
        return True, None

    write_res = client.write(
        f"sites/{site.site_id}/setting/service/poeSchedules/{sched_id}",
        method="PUT",
        data=body,
        tool_name="bind_poe_schedule",
        target=target_id,
        before=before_summary,
        snapshot_payload={"poeSchedule": copy.deepcopy(sched), "mac": omada_mac, "previousPorts": cur_map.get(omada_mac, [])},
        read_back=_read_back,
        verify_fn=_verify,
        fields_changed=["poePortsMap"],
    )
    return _committed_result(
        tool_name="bind_poe_schedule",
        target_id=target_id,
        before=write_res["before"],
        after=write_res["after"],
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warnings,
        rollback=rollback,
    )


def delete_poe_schedule(
    client: OmadaClient,
    poeSchedule: str,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Delete a PoE schedule by ID or exact name."""
    site = _site(client)
    rows = _fetch_poe_schedules(client, site)
    target = _resolve_by_id_or_name(rows, poeSchedule, label="PoE schedule")
    target_id = str(target.get("id") or "")
    rollback = {
        "tool": "upsert_poe_schedule",
        "arguments": {
            "name": target.get("name"),
            "schedule": target.get("turnOnTime"),
            "enabled": bool(target.get("status", True)),
            "portBindings": dict(target.get("poePortsMap") or {}),
            "dryRun": True,
        },
    }
    return _delete_entity(
        client,
        tool_name="delete_poe_schedule",
        target_id=target_id,
        endpoint=f"sites/{site.site_id}/setting/service/poeSchedules/{target_id}",
        before=deep_redact(target),
        snapshot_payload={"action": "delete", "poeSchedule": copy.deepcopy(target)},
        fetch_all=lambda: _fetch_poe_schedules(client, site),
        match_fn=lambda row: str(row.get("id") or "") == target_id,
        rollback=rollback,
        warnings=[],
        dry_run=dryRun,
        confirm=confirm,
        label="poeSchedule",
    )

