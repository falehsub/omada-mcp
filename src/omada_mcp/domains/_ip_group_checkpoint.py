"""Durable, controller- and site-scoped checkpoints for IP group swaps."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from ..client import OmadaClient, OmadaError

_RECOVERY_ID = re.compile(r"[a-f0-9]{32}-[a-f0-9]{32}")
_CHECKPOINT_LIMIT = 8 * 1024 * 1024


def checkpoint_scope(client: OmadaClient) -> dict[str, str]:
    site = client.current_site()
    if not client.controller_id:
        raise OmadaError("controller identity is required for IP group recovery")
    return {"controllerId": client.controller_id, "siteId": site.site_id, "baseUrl": client.config.base_url.rstrip("/")}


def checkpoint_key(scope: Mapping[str, str], name: str) -> str:
    identity = json.dumps([scope, name.casefold()], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def checkpoint_path(client: OmadaClient, key: str) -> Path:
    return client._snapshot_dir() / "ip-group-recovery" / f"{key}.json"


def recovery_path(client: OmadaClient, operation_id: str) -> Path:
    if not _RECOVERY_ID.fullmatch(operation_id):
        raise OmadaError("invalid IP group recoveryId")
    return checkpoint_path(client, operation_id.split("-", 1)[0])


def read_checkpoint(path: Path) -> dict[str, Any] | None:
    if path.is_symlink() or path.parent.is_symlink():
        raise OmadaError("refusing symlinked IP group recovery storage")
    try:
        with path.open(encoding="utf-8") as handle:
            text = handle.read(_CHECKPOINT_LIMIT + 1)
        if len(text) > _CHECKPOINT_LIMIT:
            raise OmadaError("IP group recovery checkpoint exceeds its storage limit")
        checkpoint = json.loads(text)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise OmadaError("IP group recovery checkpoint is unreadable") from exc
    if not isinstance(checkpoint, dict) or checkpoint.get("version") != 1:
        raise OmadaError("unsupported IP group recovery checkpoint")
    return checkpoint


@contextmanager
def claim_checkpoint(client: OmadaClient, path: Path) -> Iterator[None]:
    client._ensure_snapshot_dir()
    try:
        path.parent.mkdir(mode=0o700, exist_ok=True)
        lock_path = path.with_suffix(".lock")
        if path.parent.is_symlink() or lock_path.is_symlink():
            raise OmadaError("refusing symlinked IP group recovery storage")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as exc:
        raise OmadaError("could not open IP group recovery storage") from exc
    with os.fdopen(fd, "r+b") as handle:
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise OmadaError("another IP group operation is using this recovery checkpoint") from exc
        yield


def persist_checkpoint(path: Path, checkpoint: Mapping[str, Any]) -> None:
    serialized = json.dumps(checkpoint, ensure_ascii=True, sort_keys=True) + "\n"
    if len(serialized) > _CHECKPOINT_LIMIT:
        raise OmadaError("IP group recovery checkpoint exceeds its storage limit")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".swap-", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if sys.platform != "win32":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as exc:
        raise OmadaError("could not persist IP group recovery checkpoint") from exc
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
