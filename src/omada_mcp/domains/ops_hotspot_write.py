"""Write domain module: controller backup export and hotspot vouchers."""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import os
import re
import time
import urllib.parse
from collections.abc import Iterator
from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import as_int, deep_redact, require_complete_collection
from ._write_common import (
    _committed_result,
    _dry_run_result,
    _field_diff,
    _require_confirm,
    _site,
)
from .fleet_vpn_read import _project_hotspot_row

_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_VALID_RETENTION_DAYS = frozenset({-1, 0, 7, 30, 60, 90, 180, 365})

_VOUCHER_CODE_FORMATS: dict[str, list[int]] = {
    "0": [0],
    "numbers": [0],
    "numeric": [0],
    "1": [1],
    "letters": [1],
    "alpha": [1],
    "numbers_letters": [0, 1],
    "alphanumeric": [0, 1],
}


def _validate_backup_filename(file_name: str) -> str:
    clean = str(file_name or "").strip()
    if (
        not clean
        or "/" in clean
        or "\\" in clean
        or ".." in clean
        or "\x00" in clean
        or not _SAFE_FILENAME_RE.fullmatch(clean)
    ):
        raise OmadaError(
            f"unsafe backup fileName {file_name!r}",
            hint="provide a basename like 'omada_backup.cfg' containing only letters, digits, '.', '_' or '-'",
        )
    return clean


def export_controller_backup(
    client: OmadaClient,
    retentionDays: int = -1,
    retainUsers: bool = True,
    fileName: str | None = None,
    timeoutSeconds: int = 60,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Export a controller backup into ``OMADA_SNAPSHOT_DIR/backups`` (never auto-restores)."""
    mode = "auto_backup_file" if fileName else "manual_backup"
    target_id = _validate_backup_filename(fileName) if fileName else f"manual-retention-{retentionDays}"
    ret_days = as_int(retentionDays, -1)
    if not fileName and ret_days not in _VALID_RETENTION_DAYS:
        raise OmadaError(
            f"retentionDays={retentionDays} must be one of {sorted(_VALID_RETENTION_DAYS)}",
            hint="use -1 for settings only, 0 for all history, or 7/30/60/90/180/365 days",
        )
    timeout_val = max(5, min(as_int(timeoutSeconds, 60), 300))

    endpoint = (
        f"autoBackup/autoBackupFile?fileName={urllib.parse.quote(target_id)}"
        if fileName
        else f"files/backup?retention={ret_days}&retainUser={'true' if retainUsers else 'false'}"
    )
    client._require_write_allowed("export_controller_backup", endpoint)
    _require_confirm("export_controller_backup", target_id, dryRun, confirm)

    backup_dir = client._snapshot_dir() / "backups"
    stamp = (
        "<utc-timestamp>" if dryRun else
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    )
    out_name = target_id if fileName else f"omada-backup-{stamp}.cfg"
    out_path = backup_dir / out_name

    before_state = {"mode": mode, "retentionDays": ret_days, "retainUsers": bool(retainUsers)}
    after_preview = {
        "mode": mode,
        "outputPath": str(out_path),
        "retentionDays": ret_days,
        "retainUsers": bool(retainUsers),
    }
    diff = _field_diff(before_state, after_preview)
    if dryRun:
        return _dry_run_result(
            tool_name="export_controller_backup",
            target_id=target_id,
            before=before_state,
            after=after_preview,
            diff=diff,
            warnings=[],
            rollback=None,
        )

    if not fileName:
        client.api_result("maintenance/backup/prepareBackup", method="POST", data={})
        deadline = time.monotonic() + float(timeout_val)
        while time.monotonic() < deadline:
            progress = client.api_result("maintenance/backup/result") or {}
            status_val = progress.get("status") if isinstance(progress, dict) else 0
            # status=1 indicates in-progress in Omada backup worker
            if status_val != 1:
                break
            time.sleep(1.0)

    raw_bytes = client.download(endpoint)
    root_dir = client._ensure_snapshot_dir().resolve()
    backup_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            os.chmod(backup_dir, 0o700)
    final_path = out_path.resolve()
    try:
        final_path.relative_to(root_dir)
    except ValueError as exc:
        raise OmadaError(f"backup destination {out_path} escaped OMADA_SNAPSHOT_DIR") from exc

    fd = os.open(final_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw_bytes)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            os.chmod(final_path, 0o600)

    digest = hashlib.sha256(raw_bytes).hexdigest()
    snap_id = client._save_snapshot(
        "export_controller_backup",
        target_id,
        {"path": str(final_path), "bytes": len(raw_bytes), "sha256": digest, "mode": mode},
    )
    warnings: list[str] = []
    try:
        client._append_audit(
            tool_name="export_controller_backup",
            target=target_id,
            snapshot_id=snap_id,
            fields_changed=["exported"],
            result="verified",
            verified=True,
        )
    except OSError:
        warnings.append("Backup file exported and verified, but the write audit could not be saved.")
    after_committed = {
        "mode": mode,
        "outputPath": str(final_path),
        "bytes": len(raw_bytes),
        "sha256": digest,
    }
    return _committed_result(
        tool_name="export_controller_backup",
        target_id=target_id,
        before=before_state,
        after=after_committed,
        diff=_field_diff(before_state, after_committed),
        snapshot=snap_id,
        warnings=warnings,
        rollback=None,
    )


# -- Hotspot voucher CRUD ----------------------------------------------------


@contextlib.contextmanager
def _hotspot_request(action: str) -> Iterator[None]:
    """Keep controller-provided error text out of voucher tool responses."""
    try:
        yield
    except OmadaError as exc:
        code = exc.code if type(exc.code) is int else None
        suffix = f" (controller code {code})" if code is not None else ""
        safe_error = OmadaError(f"could not {action}{suffix}", code=code)
        safe_error.write_status = exc.write_status
        raise safe_error from None


def _fetch_hotspot_rows(client: OmadaClient, endpoint: str) -> list[dict[str, Any]]:
    with _hotspot_request("read hotspot voucher metadata"):
        rows, _ = require_complete_collection(client, endpoint)
    return rows


def create_hotspot_vouchers(
    client: OmadaClient,
    name: str,
    amount: int = 10,
    durationMinutes: int = 480,
    codeLength: int = 6,
    codeFormat: str = "numbers_letters",
    maxUsers: int = 1,
    downLimitKbps: int | None = None,
    upLimitKbps: int | None = None,
    trafficLimitMb: int | None = None,
    description: str | None = None,
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Create a batch/group of hotspot vouchers (category 'hotspot')."""
    site = _site(client)
    clean_name = str(name or "").strip()
    if not (1 <= len(clean_name) <= 64):
        raise OmadaError("voucher group name must be 1..64 characters")
    qty = as_int(amount, 0)
    if not (1 <= qty <= 1000):
        raise OmadaError(f"amount={amount} must be between 1 and 1000")
    mins = as_int(durationMinutes, 0)
    if mins < 1:
        raise OmadaError(f"durationMinutes={durationMinutes} must be >= 1")
    code_len = as_int(codeLength, 0)
    if not (6 <= code_len <= 10):
        raise OmadaError(f"codeLength={codeLength} must be between 6 and 10")
    fmt_key = str(codeFormat or "numbers_letters").strip().lower()
    if fmt_key not in _VOUCHER_CODE_FORMATS:
        raise OmadaError(
            f"unsupported codeFormat {codeFormat!r}",
            hint="use 'numbers' ([0]), 'letters' ([1]), or 'numbers_letters' ([0, 1])",
        )
    max_u = as_int(maxUsers, 0)
    if not (1 <= max_u <= 999):
        raise OmadaError(f"maxUsers={maxUsers} must be between 1 and 999")

    _require_confirm("create_hotspot_vouchers", clean_name, dryRun, confirm)

    payload: dict[str, Any] = {
        "name": clean_name,
        "amount": qty,
        "codeLength": code_len,
        "codeForm": list(_VOUCHER_CODE_FORMATS[fmt_key]),
        "type": 0 if max_u == 1 else 1,
        "maxUsers": max_u,
        "logout": True,
        "durationType": 1,
        "duration": mins,
        "voucherValidityEnable": False,
        "upTimeLimitEnable": False,
        "validityType": 0,
        "applyToAllPortals": True,
        "downLimitEnable": downLimitKbps is not None,
        "downLimit": max(1, as_int(downLimitKbps, 1)) if downLimitKbps is not None else None,
        "downLimitUnit": 0,
        "upLimitEnable": upLimitKbps is not None,
        "upLimit": max(1, as_int(upLimitKbps, 1)) if upLimitKbps is not None else None,
        "upLimitUnit": 0,
        "trafficLimitEnable": trafficLimitMb is not None,
        "trafficLimit": max(1, as_int(trafficLimitMb, 1)) if trafficLimitMb is not None else None,
        "trafficLimitUnit": 0,
        "trafficLimitFrequency": 1,
    }
    if description:
        payload["description"] = str(description).strip()[:128]

    preview_after = deep_redact(payload)
    diff = _field_diff({}, preview_after)
    rollback = {
        "tool": "revoke_hotspot_voucher",
        "arguments": {"target": clean_name, "targetType": "group"},
    }
    if dryRun:
        return _dry_run_result(
            tool_name="create_hotspot_vouchers",
            target_id=clean_name,
            before={},
            after=preview_after,
            diff=diff,
            warnings=[],
            rollback=rollback,
        )

    endpoint = f"hotspot/sites/{site.site_id}/voucherGroups"
    with _hotspot_request("create a hotspot voucher group"):
        res = client.write(
            endpoint,
            "POST",
            data=payload,
            expect_keys={"name": clean_name},
            tool_name="create_hotspot_vouchers",
            target=clean_name,
            before={},
            snapshot_payload={"siteId": site.site_id, "created": True, "groupName": clean_name},
            read_back=lambda: next(
                (r for r in _fetch_hotspot_rows(client, endpoint)
                 if str(r.get("name") or "").strip().lower() == clean_name.lower()),
                {},
            ),
            fields_changed=["name", "amount", "duration"],
        )
    after_safe = _project_hotspot_row(res["after"], group=True)
    group_id = str(after_safe.get("id") or clean_name)
    if after_safe.get("id"):
        rollback = {
            "tool": "revoke_hotspot_voucher",
            "arguments": {"target": group_id, "targetType": "group"},
        }
    return _committed_result(
        tool_name="create_hotspot_vouchers",
        target_id=group_id,
        before={},
        after=after_safe,
        diff=diff,
        snapshot=res["snapshot"],
        warnings=[],
        rollback=rollback,
    )


def revoke_hotspot_voucher(
    client: OmadaClient,
    target: str,
    targetType: str = "group",
    dryRun: bool = True,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Revoke/delete a hotspot voucher group or single voucher code."""
    site = _site(client)
    kind = str(targetType or "group").strip().lower()
    if kind not in ("group", "voucher"):
        raise OmadaError(f"invalid targetType {targetType!r}", hint="use 'group' or 'voucher'")
    needle = str(target or "").strip()
    if not needle:
        raise OmadaError("target ID, name, or voucher code is required")

    group = kind == "group"
    collection = f"hotspot/sites/{site.site_id}/{'voucherGroups' if group else 'vouchers'}"
    rows = _fetch_hotspot_rows(client, collection)
    matches = [row for row in rows if str(row.get("id", "")) == needle]
    if not matches:
        if group:
            matches = [row for row in rows if str(row.get("name") or "").strip().casefold() == needle.casefold()]
        else:
            matches = [row for row in rows if str(row.get("code") or "") == needle]
    if not matches:
        raise OmadaError(f"hotspot {kind} not found")
    if len(matches) != 1:
        raise OmadaError(f"more than one hotspot {kind} matches", hint="use a unique ID")
    before_safe = _project_hotspot_row(matches[0], group=group)
    tid = str(before_safe.get("id", ""))
    if not tid:
        raise OmadaError(f"hotspot {kind} has no usable non-credential ID")
    endpoint = f"{collection}/{urllib.parse.quote(tid, safe='')}"

    def _read_back() -> dict[str, Any]:
        rows_after = _fetch_hotspot_rows(client, collection)
        return {"id": tid} if any(str(row.get("id")) == tid for row in rows_after) else {}

    _require_confirm("revoke_hotspot_voucher", tid, dryRun, confirm)
    diff = _field_diff(before_safe, {})
    if dryRun:
        return _dry_run_result(
            tool_name="revoke_hotspot_voucher",
            target_id=tid,
            before=before_safe,
            after={},
            diff=diff,
            warnings=[],
            rollback=None,
        )

    with _hotspot_request(f"revoke a hotspot {kind}"):
        res = client.write(
            endpoint,
            "DELETE",
            tool_name="revoke_hotspot_voucher",
            target=tid,
            before=before_safe,
            snapshot_payload={"siteId": site.site_id, "targetType": kind, "deleted": before_safe},
            read_back=_read_back,
            verify_fn=lambda _req, after: (
                (False, f"{kind} {tid} still present after DELETE") if after else (True, None)
            ),
            fields_changed=["revoked"],
        )
    return _committed_result(
        tool_name="revoke_hotspot_voucher",
        target_id=tid,
        before=before_safe,
        after={},
        diff=diff,
        snapshot=res["snapshot"],
        warnings=[],
        rollback=None,
    )
