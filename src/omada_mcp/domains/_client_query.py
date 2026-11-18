"""Bounded, resumable read-only client collection traversal.

Checkpoints contain whitelist projections, never raw controller responses. Numbered
controller pages offer best-effort consistency, not a snapshot of a changing site.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..client import OmadaClient, OmadaError, RequestBudgetExceeded
from ..client_cursors import CursorCapacityError, CursorError
from ._client_projection import (
    _CLIENT_SCHEMA,
    _SEARCH_CLIENT_SCHEMA,
    client_flag,
    client_text,
    client_vlan,
    project_client,
)
from ._common import PaginatedList, as_mapping
from ._tool_model import normalize_mac

NATIVE_SIZE = 100
MAX_PAGES = 20
MAX_REQUESTS = 24
MAX_ROWS = 100_000
FALLBACK_CODES = (-1007, -41011, -1600)
VIEWER_HISTORY_WARNING = "Using Viewer-safe insight/clients history; matching totals are not authoritative."
FILTER_EVIDENCE_WARNING = "Some rows omit or contain invalid filter fields; matching totals are incomplete."


def selected_fields(fields: list[str] | None, search: bool) -> list[str]:
    allowed = (_SEARCH_CLIENT_SCHEMA if search else _CLIENT_SCHEMA)["properties"]
    if fields is None:
        return list(allowed)
    if not fields or len(fields) != len(set(fields)) or any(f not in allowed for f in fields):
        raise OmadaError("fields must be a nonempty unique list of supported client fields")
    return [key for key in allowed if key == "mac" or key in fields]


def project_search_client(row: dict[str, Any]) -> dict[str, Any]:
    projected = project_client(row)
    blocked = client_flag(row.get("blocked"))
    if blocked is not None:
        projected["blocked"] = blocked
    setting = row.get("ipSetting")
    if isinstance(setting, dict) and client_flag(setting.get("useFixedAddr")) is True:
        projected["fixedIp"] = client_text(setting.get("ip")) or ""
        if network_id := client_text(setting.get("netId")):
            projected["fixedNetId"] = network_id
    return projected


def _available(row: dict[str, Any]) -> dict[str, str | bool | int]:
    """Return validated filter evidence before display defaults are applied."""
    values: dict[str, str | bool | int | None] = {
        "active": client_flag(row.get("active")),
        "wireless": client_flag(row.get("wireless")),
        "guest": client_flag(row.get("guest")),
        "vlan": client_vlan(row),
        "mac": client_text(row.get("mac")),
        "name": client_text(row.get("name"), row.get("hostName")),
        "hostName": client_text(row.get("hostName")),
        "ip": client_text(row.get("ip"), as_mapping(row.get("ipSetting")).get("ip")),
        "ssid": client_text(row.get("ssid")),
        "networkName": client_text(row.get("networkName"), row.get("network")),
    }
    return {key: value for key, value in values.items() if value is not None}


def matches(available: dict[str, str | bool | int], filters: dict[str, Any]) -> tuple[bool, bool]:
    """Return (match, indeterminate). A definite nonmatch resolves an AND query."""
    missing = False
    for key in ("active", "wireless", "guest", "vlan", "ssid"):
        wanted = filters.get(key)
        if wanted is None or (key == "ssid" and not str(wanted).strip()):
            continue
        if key not in available:
            missing = True
            continue
        value = available[key]
        if key == "ssid":
            if str(wanted).strip().lower() not in str(value).strip().lower():
                return False, False
        elif value != wanted:
            return False, False
    query = str(filters.get("query") or "").strip().lower()
    if query:
        keys = ("mac", "name", "hostName", "ip", "ssid", "networkName")
        mac_query = normalize_mac(query)
        values = [str(available[key]).lower() for key in keys if key in available]
        if not any(query in value for value in values) and not (
            mac_query and mac_query in normalize_mac(str(available.get("mac", "")))
        ):
            return False, any(key not in available for key in keys)
    return not missing, missing


def _source_filters(options: dict[str, Any], search: bool, source: str) -> dict[str, Any]:
    if not search and source == "insight/clients":
        return {**options["filters"], "active": True}
    return options["filters"]


def _scope(client: OmadaClient, tool: str, site_id: str) -> str:
    # Store is already per-client. Bind explicitly to the effective site and identity
    # as well, including configurations changed in-process by embedding callers.
    return json.dumps([client.config.base_url, client.config.username,
                       client.controller_id, site_id, tool], separators=(",", ":"))


def _sources(search: bool, active: bool | None) -> list[str]:
    if not search or active is True:
        return ["clients?filters.active=true"]
    if active is False:
        return ["clients?filters.active=false"]
    return ["clients?filters.active=true", "clients?filters.active=false"]


def _new_state(options: dict[str, Any], search: bool) -> dict[str, Any]:
    return {"options": options, "sources": _sources(search, options["filters"].get("active")),
            "index": 0, "page": 1, "pending": [], "seen": [], "fingerprints": [],
            "sourceTotal": None, "rowsScanned": 0, "matched": 0, "emitted": False,
            "warnings": [], "missing": False, "source": "clients", "sourceSeen": [],
            "sourceCount": 0, "sourceEnded": False, "reportedTotal": None, "identityMissing": False}


def _warning(state: dict[str, Any], message: str) -> None:
    if message not in state["warnings"]:
        state["warnings"].append(message)


def _fingerprint(rows: list[dict[str, Any]]) -> str:
    identities = [normalize_mac(row.get("mac", "")) or
                  [str(row.get(k) or "") for k in ("name", "hostName", "ip")]
                  for row in rows]
    return hashlib.sha256(json.dumps(identities, separators=(",", ":")).encode()).hexdigest()


def _next_source(state: dict[str, Any]) -> None:
    state["index"] += 1
    state["page"] = 1
    state["fingerprints"] = []
    state["sourceTotal"] = None
    state["sourceSeen"] = []
    state["sourceCount"] = 0
    state["sourceEnded"] = False


def query_clients(
    client: OmadaClient, tool: str, *, limit: int | None = None,
    pageSize: int | None = None, cursor: str | None = None,
    fields: list[str] | None = None, resultFormat: str | None = None,
    filters: dict[str, Any] | None = None,
) -> PaginatedList | dict[str, Any]:
    """Execute one opted-in paged query. Legacy callers use their existing adapters."""
    if limit is not None:
        raise OmadaError("limit cannot be combined with pageSize or cursor")
    search = tool == "search_clients"
    scope = _scope(client, tool, client.current_site().site_id)
    supplied_filters = {key: value for key, value in (filters or {}).items() if value is not None}
    if cursor is not None:
        try:
            state = client.client_cursors.get(cursor, scope)
        except CursorError as exc:
            raise OmadaError(str(exc), hint="restart the query without cursor") from None
        options = state["options"]
        if ((pageSize is not None and pageSize != options["size"])
                or (fields is not None and selected_fields(fields, search) != options["fields"])
                or (resultFormat is not None and resultFormat != options["format"])
                or any(options["filters"].get(k) != v for k, v in supplied_filters.items())):
            raise OmadaError("cursor options conflict with the original query")
    else:
        options = {"size": pageSize or 100, "fields": selected_fields(fields, search),
                   "format": resultFormat or "legacy", "filters": supplied_filters}
        state = _new_state(options, search)
    if not 1 <= options["size"] <= 500 or options["format"] not in ("legacy", "envelope"):
        raise OmadaError("invalid pageSize or resultFormat")
    site = client.current_site()
    source_filters = _source_filters(options, search, state["source"])
    output: list[dict[str, Any]] = []
    seen = set(state["seen"])
    source_seen = set(state["sourceSeen"])
    pages = 0
    scanned = 0
    stop = "complete"
    terminal = False
    with client.request_budget(MAX_REQUESTS) as budget:
        while len(output) < options["size"]:
            if state["pending"]:
                item = state["pending"].pop(0)
                row = item["row"]
                mac = normalize_mac(row.get("mac", ""))
                if not mac or mac not in source_seen:
                    state["sourceCount"] += 1
                if mac:
                    source_seen.add(mac)
                if mac and mac in seen:
                    continue
                if mac:
                    seen.add(mac)  # Active always wins, even when it fails a filter.
                else:
                    state["identityMissing"] = True
                    _warning(state, "A row has no MAC; identity deduplication is unavailable for that row.")
                hit, missing = matches(item["available"], source_filters)
                if missing:
                    state["missing"] = True
                    _warning(state, FILTER_EVIDENCE_WARNING)
                if hit:
                    state["matched"] += 1
                    output.append({key: row[key] for key in options["fields"] if key in row})
                continue
            if state["sourceEnded"]:
                if (state["sourceTotal"] is not None
                        and state["sourceCount"] != state["sourceTotal"]):
                    stop, terminal = "source_changed", True
                    _warning(state, "Unique source rows disagree with totalRows; traversal is incomplete.")
                    break
                _next_source(state)
                source_seen.clear()
            if state["index"] >= len(state["sources"]):
                break
            if state["rowsScanned"] >= MAX_ROWS:
                stop, terminal = "traversal_limit", True
                break
            if pages >= MAX_PAGES:
                stop = "scan_budget"
                break
            endpoint = state["sources"][state["index"]]
            separator = "&" if "?" in endpoint else "?"
            try:
                pages += 1
                payload = client.api(f"sites/{site.site_id}/{endpoint}{separator}"
                                     f"currentPage={state['page']}&currentPageSize={NATIVE_SIZE}")
                if payload.get("errorCode") != 0:
                    raise OmadaError("client collection unavailable", code=payload.get("errorCode"))
            except RequestBudgetExceeded:
                pages -= 1
                stop = "scan_budget"
                break
            except OmadaError as exc:
                if (not state["emitted"] and state["source"] == "clients"
                        and (not search or exc.code in FALLBACK_CODES)):
                    # No rows have escaped yet, so restarting with Viewer-safe data
                    # cannot mix source semantics. Keep the already-spent budget.
                    previously_scanned = state["rowsScanned"]
                    state = _new_state(options, search)
                    state["rowsScanned"] = previously_scanned
                    state["sources"] = ["insight/clients"]
                    state["source"] = "insight/clients"
                    source_filters = _source_filters(options, search, state["source"])
                    output.clear()
                    seen.clear()
                    source_seen.clear()
                    _warning(state, VIEWER_HISTORY_WARNING)
                    continue
                if not state["emitted"] and not output:
                    raise
                stop, terminal = "source_error", True
                _warning(state, "Client source failed during traversal; restart the query.")
                break
            result = payload.get("result")
            if not isinstance(result, dict) or not isinstance(result.get("data"), list):
                stop, terminal = "source_error", True
                _warning(state, "Controller returned a malformed client page.")
                break
            raw = result.get("data") or []
            if len(raw) > NATIVE_SIZE or any(not isinstance(row, dict) for row in raw):
                stop, terminal = "source_error", True
                _warning(state, "Controller returned an invalid or oversized client page.")
                break
            reported = result.get("totalRows")
            total = reported if isinstance(reported, int) and not isinstance(reported, bool) and reported >= 0 else None
            if state["sourceTotal"] is not None and total is not None and total != state["sourceTotal"]:
                stop, terminal = "source_changed", True
                _warning(state, "Controller totalRows changed; restart to avoid claiming a complete snapshot.")
                break
            if total is not None:
                state["sourceTotal"] = total
                if len(state["sources"]) == 1:
                    state["reportedTotal"] = total
            total = state["sourceTotal"]
            if raw:
                fingerprint = _fingerprint(raw)
                if fingerprint in state["fingerprints"]:
                    stop, terminal = "repeated_page", True
                    _warning(state, "Controller repeated a client page; traversal is incomplete.")
                    break
                state["fingerprints"].append(fingerprint)
            state["pending"] = [{"row": project_search_client(row) if search else project_client(row),
                                 "available": _available(row) if source_filters else {}} for row in raw]
            scanned += len(raw)
            state["rowsScanned"] += len(raw)
            page = state["page"]
            state["page"] += 1
            # A reported count describes raw source rows, not the unique matches.
            if not raw or (total is not None and page * NATIVE_SIZE >= total) or (total is None and len(raw) < NATIVE_SIZE):
                state["sourceEnded"] = True
        requests = budget.used
    # A page ending exactly at the requested match count still needs the same
    # source-count verification as a page ending below it, without an extra GET.
    if state["sourceEnded"] and not state["pending"] and not terminal:
        if state["sourceTotal"] is not None and state["sourceCount"] != state["sourceTotal"]:
            stop, terminal = "source_changed", True
            _warning(state, "Unique source rows disagree with totalRows; traversal is incomplete.")
        else:
            _next_source(state)
            source_seen.clear()
    has_more = bool(state["pending"] or state["index"] < len(state["sources"])) and not terminal
    if stop == "complete" and has_more:
        stop = "result_limit"
    if not has_more and not terminal and state["missing"]:
        stop = "field_unavailable"
    complete = not has_more and not terminal and not state["missing"]
    state["seen"] = sorted(seen)
    state["sourceSeen"] = sorted(source_seen)
    state["emitted"] = True
    next_cursor = None
    if has_more:
        try:
            next_cursor = client.client_cursors.put(scope, state)
        except CursorCapacityError:
            stop, has_more = "cursor_capacity", False
            _warning(state, "Cursor state capacity reached; narrow the query and restart.")
    exact = complete and not state["identityMissing"] and state["source"] != "insight/clients"
    metadata: dict[str, Any] = {
        "totalRowsExact": exact, "totalRowsSource": "matched" if exact else "observed",
        "rowsScanned": scanned, "pagesFetched": pages, "controllerRequests": requests,
        "maxPages": MAX_PAGES, "hasMore": has_more, "complete": complete,
        "truncated": not complete, "stopReason": stop, "consistency": "bestEffort",
        "source": state["source"], "warnings": state["warnings"], "selectedFields": options["fields"],
    }
    if exact:
        metadata["totalRows"] = state["matched"]
    if len(state["sources"]) == 1 and state["reportedTotal"] is not None:
        metadata["sourceTotalRows"] = state["reportedTotal"]
    if next_cursor is not None:
        metadata["nextCursor"] = next_cursor
    if not complete:
        metadata["truncationReason"] = stop
    data = PaginatedList(output)
    data.pagination = metadata
    if options["format"] == "envelope":
        return {"items": list(data), "count": len(data), **metadata}
    return data


def format_legacy(data: PaginatedList, *, fields: list[str] | None,
                  result_format: str | None, search: bool = False) -> PaginatedList | dict[str, Any]:
    selected = selected_fields(fields, search)
    if result_format not in (None, "legacy", "envelope"):
        raise OmadaError("invalid resultFormat")
    if fields is not None:
        result = PaginatedList({key: row[key] for key in selected if key in row} for row in data)
        result.pagination = dict(data.pagination)
        data = result
        data.pagination["selectedFields"] = selected
    if result_format == "envelope":
        return {"items": list(data), "count": len(data), **data.pagination}
    return data
