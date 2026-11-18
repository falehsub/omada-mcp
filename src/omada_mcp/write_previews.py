"""Session-local confirmation of inspected controller changes."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from collections import OrderedDict
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from .client import OmadaClient, OmadaError

_CONFIRMED: ContextVar[tuple[str, str, str] | None] = ContextVar("confirmed_write", default=None)
_PREVIEW_TTL_SECONDS = 300
_MAX_PREVIEWS = 128
_PREVIEW_HINT = "run the same tool with dryRun=true and use its fresh confirmToken"
_MAC_SELECTOR = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|[0-9a-fA-F]{12}")


def require_confirmation(tool: str, target: str, dry_run: bool, token: str | None) -> None:
    if not dry_run and (not token or _CONFIRMED.get() != (tool, target, token)):
        raise OmadaError(f"confirmation mismatch for {tool}", hint=_PREVIEW_HINT)


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Preview:
    tool: str
    scope: tuple[str, str | None, str]
    arguments: str
    target: str
    state: str
    expires: float


class WritePreviews:
    """Preview and apply through the same handler to check the same preconditions."""

    def __init__(self) -> None:
        self._entries: OrderedDict[str, _Preview] = OrderedDict()
        self._lock = threading.RLock()

    def call(self, client: OmadaClient, tool: str, handler: Callable[..., Any],
             arguments: dict[str, Any]) -> dict[str, Any]:
        intent = {k: v for k, v in arguments.items() if k not in ("dryRun", "confirm")}
        comparable_intent = dict(intent)
        mac = comparable_intent.get("mac")
        if isinstance(mac, str) and _MAC_SELECTOR.fullmatch(mac):
            comparable_intent["mac"] = mac.replace(":", "").replace("-", "").lower()
        args_hash = _digest(comparable_intent)
        dry_run = arguments.get("dryRun", True)
        token = arguments.get("confirm")

        with self._lock, client.scoped_cache():
            site_id = client.current_site().site_id
            scope = (client.config.base_url, client.controller_id, site_id)
            now = client._clock()
            while self._entries and next(iter(self._entries.values())).expires <= now:
                self._entries.popitem(last=False)

            previous = None
            if not dry_run:
                if not isinstance(token, str):
                    raise OmadaError(f"confirmation mismatch for {tool}", hint=_PREVIEW_HINT)
                previous = self._entries.get(token)
                if (previous is None or previous.tool != tool or previous.scope != scope
                        or previous.arguments != args_hash):
                    raise OmadaError(f"confirmation mismatch for {tool}", hint=_PREVIEW_HINT)
                # Consume before rechecking state. A failed attempt always requires a fresh preview.
                del self._entries[token]

            with client.write_scope(preview=True):
                preview = handler(client, **intent, dryRun=True)
            if (client.config.base_url, client.controller_id, client.current_site().site_id) != scope:
                raise OmadaError("controller or site changed while reading the preview", hint=_PREVIEW_HINT)
            target = preview["target"]
            state = _digest([preview["before"], preview["after"], preview["diff"]])

            if dry_run:
                token = secrets.token_urlsafe(32)
                self._entries[token] = _Preview(tool, scope, args_hash, target, state,
                                                client._clock() + _PREVIEW_TTL_SECONDS)
                if len(self._entries) > _MAX_PREVIEWS:
                    self._entries.popitem(last=False)
                preview["confirmToken"] = token
                return preview

            assert previous is not None and isinstance(token, str)
            if previous.target != target or previous.state != state:
                raise OmadaError(f"observed state changed for {tool} since preview", hint=_PREVIEW_HINT)
            if previous.expires <= client._clock():
                raise OmadaError(f"confirmation expired for {tool}", hint=_PREVIEW_HINT)

            binding = _CONFIRMED.set((tool, target, token))
            try:
                with client.write_scope(expected_scope=scope) as outcomes:
                    result = handler(client, **intent, dryRun=False, confirm=token)
            finally:
                _CONFIRMED.reset(binding)

        result.pop("confirmToken", None)
        if outcomes:
            result["verified"] = all(write["verified"] for write in outcomes)
            result["outcome"] = "verified" if result["verified"] else "accepted"
            for write in outcomes:
                if write.get("auditWarning"):
                    result["warnings"].append(write["auditWarning"])
        else:
            result["outcome"] = "verified" if result.get("verified") else "accepted"
        return result
