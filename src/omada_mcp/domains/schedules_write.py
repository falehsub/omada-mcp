"""Write domain module: schedules_write."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import as_int
from ._write_common import (
    _committed_result,
    _delete_entity,
    _dry_run_result,
    _field_diff,
    _require_confirm,
    _resolve_by_id_or_name,
    _site,
)
from ._write_fetchers import _fetch_acls, _fetch_schedules

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
