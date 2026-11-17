"""Bounded in-memory storage for replay-safe client-list checkpoints."""

from __future__ import annotations

import copy
import json
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class CursorError(Exception):
    """A cursor is unknown, expired, or does not belong to the requested scope."""


class CursorCapacityError(CursorError):
    """A checkpoint cannot fit within the cursor store's configured limits."""


@dataclass
class _Checkpoint:
    scope: str
    state: dict[str, Any]
    created_at: float
    last_access: float
    size_bytes: int


class CursorStore:
    """Store immutable snapshots behind opaque, scope-bound process-local tokens.

    The stored state should contain only safe projected data. The caller owns
    scope construction and must include every identity and query option that
    should invalidate a cursor.
    """

    def __init__(
        self,
        *,
        max_entries: int = 32,
        max_bytes: int = 8 * 1024 * 1024,
        idle_ttl: float = 600,
        absolute_ttl: float = 3600,
        clock: Callable[[], float] = time.monotonic,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        if max_entries < 0:
            raise ValueError("max_entries must be non-negative")
        if max_bytes < 0:
            raise ValueError("max_bytes must be non-negative")
        if idle_ttl <= 0:
            raise ValueError("idle_ttl must be positive")
        if absolute_ttl <= 0:
            raise ValueError("absolute_ttl must be positive")
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._idle_ttl = idle_ttl
        self._absolute_ttl = absolute_ttl
        self._clock = clock
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._entries: OrderedDict[str, _Checkpoint] = OrderedDict()
        self._bytes_used = 0
        self._lock = threading.RLock()

    def put(self, scope: str, state: dict[str, Any]) -> str:
        """Save a deep-copied checkpoint and return its opaque token."""
        if not isinstance(scope, str):
            raise TypeError("scope must be a string")
        if not isinstance(state, dict):
            raise TypeError("state must be a dictionary")

        snapshot = copy.deepcopy(state)
        serialized = json.dumps(
            {"scope": scope, "state": snapshot},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        size_bytes = len(serialized)
        if size_bytes > self._max_bytes:
            raise CursorCapacityError("checkpoint exceeds the cursor store byte limit")

        with self._lock:
            now = self._clock()
            self._evict_expired(now)
            token = self._new_token()
            while self._entries and (
                len(self._entries) >= self._max_entries
                or self._bytes_used + size_bytes > self._max_bytes
            ):
                self._evict_oldest()
            if self._max_entries == 0 or self._bytes_used + size_bytes > self._max_bytes:
                raise CursorCapacityError("checkpoint cannot fit in the cursor store")

            self._entries[token] = _Checkpoint(
                scope=scope,
                state=snapshot,
                created_at=now,
                last_access=now,
                size_bytes=size_bytes,
            )
            self._bytes_used += size_bytes
            return token

    def get(self, token: str, scope: str) -> dict[str, Any]:
        """Return a fresh deep copy, leaving the checkpoint reusable."""
        if not isinstance(token, str) or not isinstance(scope, str):
            raise CursorError("cursor is unknown or invalid")
        with self._lock:
            now = self._clock()
            self._evict_expired(now)
            checkpoint = self._entries.get(token)
            if checkpoint is None or checkpoint.scope != scope:
                raise CursorError("cursor is unknown, expired, or belongs to another scope")
            checkpoint.last_access = now
            self._entries.move_to_end(token)
            return copy.deepcopy(checkpoint.state)

    def clear(self) -> None:
        """Discard every checkpoint and reset logical serialized-state accounting."""
        with self._lock:
            self._entries.clear()
            self._bytes_used = 0

    @property
    def bytes_used(self) -> int:
        """Logical UTF-8 serialized size of retained scope and state payloads."""
        with self._lock:
            self._evict_expired(self._clock())
            return self._bytes_used

    def __len__(self) -> int:
        with self._lock:
            self._evict_expired(self._clock())
            return len(self._entries)

    def _new_token(self) -> str:
        for _ in range(8):
            token = self._token_factory()
            if isinstance(token, str) and token and token not in self._entries:
                return token
        raise CursorError("could not create a unique cursor token")

    def _evict_expired(self, now: float) -> None:
        expired = [
            token
            for token, entry in self._entries.items()
            if now - entry.last_access >= self._idle_ttl
            or now - entry.created_at >= self._absolute_ttl
        ]
        for token in expired:
            self._remove(token)

    def _evict_oldest(self) -> None:
        token = next(iter(self._entries))
        self._remove(token)

    def _remove(self, token: str) -> None:
        checkpoint = self._entries.pop(token, None)
        if checkpoint is not None:
            self._bytes_used -= checkpoint.size_bytes
