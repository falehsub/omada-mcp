"""Deterministic, allocation-light client fixtures for query tests and benchmarks.

The source computes rows by index and the fake serializes only requested pages.
No controller configuration, network access, or runtime dependency is involved.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

from omada_mcp.client import RequestBudgetExceeded, SiteInfo
from omada_mcp.client_cursors import CursorStore

SUPPORTED_ROW_COUNTS = (13, 50, 205, 500, 2_000, 5_000, 10_000)
DEFAULT_SECRET_CANARY = "SYNTHETIC-SECRET-CANARY-DO-NOT-EXPOSE"


@dataclass
class _RequestBudget:
    limit: int
    used: int = 0


class SyntheticClientSource:
    """A deterministic row source that does not retain a full row collection."""

    def __init__(
        self,
        row_count: int,
        *,
        role: str = "Admin",
        active_pattern: str = "all",
        secret_canary: str = DEFAULT_SECRET_CANARY,
    ) -> None:
        if row_count < 0:
            raise ValueError("row_count must be non-negative")
        if active_pattern not in {"all", "alternating", "inactive", "active-first"}:
            raise ValueError("unsupported active_pattern")
        self.row_count = row_count
        self.role = role
        self.active_pattern = active_pattern
        self.secret_canary = secret_canary

    def is_active(self, index: int) -> bool:
        if self.active_pattern == "all":
            return True
        if self.active_pattern == "inactive":
            return False
        if self.active_pattern == "active-first":
            return index < (self.row_count + 1) // 2
        return index % 2 == 0

    def row_at(self, index: int) -> dict[str, Any]:
        """Build one stable synthetic Omada client row (zero-based index)."""
        if not 0 <= index < self.row_count:
            raise IndexError(index)
        wireless = index % 3 != 0
        active = self.is_active(index)
        mac = f"02:00:{(index >> 24) & 255:02x}:{(index >> 16) & 255:02x}:{(index >> 8) & 255:02x}:{index & 255:02x}"
        return {
            "mac": mac,
            "name": f"synthetic-client-{index:05d}",
            "hostName": f"fixture-{index:05d}",
            "ip": f"192.0.2.{(index % 254) + 1}",
            "wireless": wireless,
            "guest": index % 11 == 0,
            "active": active,
            "ssid": f"Synthetic-{index % 4}" if wireless else "",
            "apName": f"Fixture-AP-{index % 7}" if wireless else "",
            "networkName": f"Synthetic-Network-{index % 5}",
            "vid": 10 + (index % 5),
            "download": index * 101,
            "upload": index * 17,
            "duration": 60 + index,
            "lastSeen": 1_700_000_000_000 + index * 1_000,
            "signalLevel": -40 - (index % 35) if wireless else None,
            "rssi": -42 - (index % 30) if wireless else None,
            "snr": 20 + (index % 25) if wireless else None,
            "txRate": 72 + (index % 600) if wireless else None,
            "rxRate": 65 + (index % 500) if wireless else None,
            "uptime": 60 + index,
            "connectType": "wireless" if wireless else "wired",
            "radioId": index % 3 if wireless else None,
            "channel": (1, 6, 11)[index % 3] if wireless else None,
            # Explicit canary proves whitelist projections do not return raw rows.
            "secretCanary": self.secret_canary,
        }

    def matching_indices(self, active: bool | None = None) -> Iterator[int]:
        for index in range(self.row_count):
            if active is None or self.is_active(index) == active:
                yield index


class FakeOmadaClient:
    """Small OmadaClient-compatible fake with native page-size semantics."""

    def __init__(
        self,
        source: SyntheticClientSource,
        *,
        site_id: str = "fixture-site",
    ) -> None:
        self.source = source
        self.site_id = site_id
        self.config = SimpleNamespace(base_url="https://synthetic.invalid", username="synthetic")
        self.controller_id = "fixture-controller"
        self.request_count = 0
        self.collection_request_count = 0
        self.response_body_bytes = 0
        self.source_seconds = 0.0
        self.client_cursors = CursorStore()
        self._budgets: list[_RequestBudget] = []
        self._site = SiteInfo(site_id, "Synthetic Test Site")

    def authenticate(self) -> bool:
        return True

    def current_site(self) -> SiteInfo:
        return self._site

    @contextmanager
    def use_site(self, wanted: str | None) -> Iterator[SiteInfo]:
        if wanted and wanted not in (self._site.site_id, self._site.name):
            raise AssertionError("unexpected synthetic site override")
        yield self._site

    @contextmanager
    def request_budget(self, max_requests: int = 24) -> Iterator[_RequestBudget]:
        budget = _RequestBudget(max_requests)
        self._budgets.append(budget)
        try:
            yield budget
        finally:
            if self._budgets and self._budgets[-1] is budget:
                self._budgets.pop()
            else:  # pragma: no cover - defensive cleanup for nested scopes
                self._budgets.remove(budget)

    def api(self, endpoint: str, **_kwargs: Any) -> dict[str, Any]:
        for budget in self._budgets:
            if budget.used >= budget.limit:
                raise RequestBudgetExceeded(used=budget.used, limit=budget.limit)
        for budget in self._budgets:
            budget.used += 1
        self.request_count += 1

        parsed = urlsplit(endpoint)
        path = parsed.path
        is_insight = path.endswith("/insight/clients")
        is_rich = path.endswith("/clients") and not is_insight
        if not (is_rich or is_insight):
            raise AssertionError(f"unexpected fixture endpoint: {endpoint}")
        self.collection_request_count += 1
        query = parse_qs(parsed.query)
        if is_rich and self.source.role.casefold() == "viewer":
            denied = {"errorCode": -1007, "msg": "Permission denied", "result": {}}
            self.response_body_bytes += len(
                json.dumps(denied, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            )
            return denied

        active_filter: bool | None = None
        if is_rich and "filters.active" in query:
            active_filter = query["filters.active"][0].casefold() == "true"
        page = max(1, int(query.get("currentPage", ["1"])[0]))
        page_size = max(1, int(query.get("currentPageSize", ["100"])[0]))

        started = time.perf_counter()
        offset = (page - 1) * page_size
        if active_filter is None:
            matching_indices = range(self.source.row_count)
        elif self.source.active_pattern == "all":
            matching_indices = range(self.source.row_count) if active_filter else range(0)
        elif self.source.active_pattern == "inactive":
            matching_indices = range(self.source.row_count) if not active_filter else range(0)
        elif self.source.active_pattern == "alternating":
            matching_indices = range(0 if active_filter else 1, self.source.row_count, 2)
        else:
            split = (self.source.row_count + 1) // 2
            matching_indices = range(0, split) if active_filter else range(split, self.source.row_count)
        matching_total = len(matching_indices)
        indices = matching_indices[offset : offset + page_size]
        rows = [self.source.row_at(index) for index in indices]
        payload = {
            "errorCode": 0,
            "result": {
                "data": rows,
                "totalRows": matching_total,
                "currentPage": page,
                "currentPageSize": page_size,
            },
        }
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.source_seconds += time.perf_counter() - started
        self.response_body_bytes += len(encoded)
        return payload
