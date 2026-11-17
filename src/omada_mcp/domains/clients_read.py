"""Read domain module: clients_read."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..client import OmadaClient, OmadaError, RequestBudgetExceeded
from ._client_projection import _CLIENT_SCHEMA as _CLIENT_SCHEMA
from ._client_projection import _SEARCH_CLIENT_SCHEMA as _SEARCH_CLIENT_SCHEMA
from ._client_projection import project_client
from ._common import PaginatedList
from ._tool_model import (
    _coerce_vlan,
    _site,
    normalize_mac,
)

_MAX_CLIENT_PAGES = 20



def _paginate_client_rows_with_meta(
    client: OmadaClient,
    site: Any,
    endpoint: str,
    *,
    limit: int = 0,
    match: Callable[[dict[str, Any]], bool] | None = None,
    max_pages: int = _MAX_CLIENT_PAGES,
    page_budget: list[int] | None = None,
    deduplicate: bool = True,
    scan_counter: list[int] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Page a single client endpoint, deduping by normalised MAC with pagination metadata."""
    collected: list[dict[str, Any]] = []
    seen = set()
    separator = "&" if "?" in endpoint else "?"
    pages_fetched = 0
    total_int: int | None = None
    exhausted_loop = max_pages == 0
    stopped_duplicate = False
    limited = False
    fingerprints: set[str] = set()
    rows_scanned = 0
    budget_exhausted = False
    malformed = False
    source_changed = False
    macless_count = 0
    for page in range(1, max_pages + 1):
        if page_budget is not None:
            if page_budget[0] <= 0:
                budget_exhausted = True
                break
            page_budget[0] -= 1
        try:
            payload = client.api(
                f"sites/{site.site_id}/{endpoint}"
                f"{separator}currentPage={page}&currentPageSize=100"
            )
        except RequestBudgetExceeded:
            budget_exhausted = True
            break
        pages_fetched += 1
        if payload.get("errorCode") != 0:
            raise OmadaError(
                f"client query failed: {payload.get('msg', 'unknown')}",
                code=payload.get("errorCode"),
                hint="clients needs Admin; insight/clients accepts any role",
                endpoint=f"sites/{{id}}/{endpoint}",
            )
        result = payload.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("data"), list):
            malformed = True
            break
        rows = result["data"]
        if any(not isinstance(row, dict) for row in rows):
            malformed = True
            break
        total_raw = result.get("totalRows")
        if isinstance(total_raw, int) and not isinstance(total_raw, bool) and total_raw >= 0:
            if total_int is not None and total_int != total_raw:
                source_changed = True
                break
            total_int = total_raw
        from ._client_query import _fingerprint
        fingerprint = _fingerprint(rows) if rows else ""
        if not rows or fingerprint in fingerprints:
            stopped_duplicate = bool(rows)
            break
        fingerprints.add(fingerprint)
        rows_scanned += len(rows)
        if scan_counter is not None:
            scan_counter[0] += len(rows)
        for row in rows:
            mac = normalize_mac(row.get("mac", ""))
            if deduplicate and mac and mac in seen:
                continue
            if mac:
                seen.add(mac)
            else:
                macless_count += 1
            collected.append(row)
            if match is not None and match(project_client(row)):
                return [row], {"complete": False, "found": True, "pagesFetched": pages_fetched}
        if limit and total_int is not None and len(collected) >= limit and len(collected) < total_int:
            limited = True
            break
        if total_int is not None:
            if len(collected) >= total_int:
                break
        elif len(rows) < 100:
            break
        if page == max_pages:
            exhausted_loop = True

    truncated = False
    reason: str | None = None
    if malformed or source_changed:
        truncated = True
        reason = "controller client page malformed or totalRows changed"
    elif budget_exhausted:
        truncated = True
        reason = "client query scan budget exhausted"
    elif limited:
        truncated = True
        reason = f"results capped at limit={limit}"
    elif stopped_duplicate:
        truncated = True
        reason = "controller repeated a client page"
    elif exhausted_loop and (total_int is None or len(collected) < total_int):
        truncated = True
        reason = f"client pagination reached maxPages={_MAX_CLIENT_PAGES}"
    elif total_int is not None and len(seen) + macless_count != total_int:
        truncated = True
        reason = f"controller returned {len(collected)} of {total_int} totalRows"

    return collected, {
        "pagesFetched": pages_fetched,
        "maxPages": max_pages,
        "totalRows": total_int if total_int is not None else len(collected),
        "truncated": truncated,
        "truncationReason": reason,
        "complete": not truncated,
        "totalRowsExact": not truncated and (total_int is None or len(seen) + macless_count == total_int),
        "totalRowsSource": "controller" if total_int is not None else "observed",
        "rowsScanned": rows_scanned,
        **({"sourceTotalRows": total_int} if total_int is not None else {}),
    }


def _paginate_client_rows(client: OmadaClient, site: Any, endpoint: str) -> list[dict[str, Any]]:
    """Page a single client endpoint, deduping by normalised MAC."""
    rows, _ = _paginate_client_rows_with_meta(client, site, endpoint)
    return rows


def _fetch_client_rows_with_meta(client: OmadaClient, site: Any, *, limit: int = 0,
                                 match: Callable[[dict[str, Any]], bool] | None = None
                                 ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    first_error: OmadaError | None = None
    page_budget = [_MAX_CLIENT_PAGES]
    scan_counter = [0]
    for endpoint in ("clients?filters.active=true", "insight/clients"):
        try:
            rows, meta = _paginate_client_rows_with_meta(client, site, endpoint, limit=limit,
                                                         match=match, page_budget=page_budget,
                                                         scan_counter=scan_counter)
            meta["pagesFetched"] = _MAX_CLIENT_PAGES - page_budget[0]
            meta["rowsScanned"] = scan_counter[0]
            meta["source"] = "insight/clients" if endpoint.startswith("insight") else "clients"
            return rows, meta
        except OmadaError as exc:
            if first_error is None:
                first_error = exc
            continue
    if first_error is not None:
        raise first_error
    return [], {"pagesFetched": 0, "maxPages": _MAX_CLIENT_PAGES, "totalRows": 0, "truncated": False, "truncationReason": None}


def _fetch_client_rows(client: OmadaClient, site: Any) -> list[dict[str, Any]]:
    """Client rows from the richest endpoint this account may use.

    ``clients?filters.active=true`` carries ``ssid``, ``ip``, ``apName`` and
    ``signalLevel``. ``insight/clients`` is the role-safe fallback, but on
    6.2.10.x it omits all four, which left list_clients and friends with blank
    columns while the controller held the data (issue #1).
    """
    rows, _ = _fetch_client_rows_with_meta(client, site)
    return rows


def _fetch_clients(client: OmadaClient, limit: int = 500) -> PaginatedList:
    site = _site(client)
    collected: list[dict[str, Any]] = []
    seen = set()
    with client.request_budget(24) as budget:
        raw_rows, page_meta = _fetch_client_rows_with_meta(client, site, limit=limit)
        page_meta["controllerRequests"] = budget.used
    all_projected: list[dict[str, Any]] = []
    for row in raw_rows:
        mac = normalize_mac(row.get("mac", ""))
        if mac and mac in seen:
            continue
        if mac:
            seen.add(mac)
        all_projected.append(project_client(row))

    if limit and len(all_projected) > limit:
        collected = all_projected[:limit]
        truncated = True
        reason: str | None = f"results capped at limit={limit}"
    else:
        collected = all_projected
        truncated = bool(page_meta.get("truncated", False))
        reason = page_meta.get("truncationReason")

    total_rows = max(len(all_projected), int(page_meta.get("totalRows") or len(all_projected)))
    result = PaginatedList(
        collected,
        truncated=truncated,
        total_rows=total_rows,
        pages_fetched=page_meta.get("pagesFetched"),
        max_pages=page_meta.get("maxPages"),
        limit=limit or None,
        truncation_reason=reason,
    )
    for key in ("complete", "totalRowsExact", "totalRowsSource", "sourceTotalRows",
                "rowsScanned", "controllerRequests", "source"):
        if key in page_meta:
            result.pagination[key] = page_meta[key]
    return result


def _list_clients(client: OmadaClient, limit: int | None = None, **options: Any) -> Any:
    return _client_list(client, "list_clients", limit, options)


def _client_list(client: OmadaClient, tool: str, limit: int | None, options: dict[str, Any]) -> Any:
    from ._client_query import format_legacy, query_clients, selected_fields
    selected_fields(options.get("fields"), False)
    if options.get("pageSize") is not None or options.get("cursor") is not None:
        filters = {"wireless": True} if tool == "list_wifi_clients" else (
            {"wireless": False} if tool == "list_wired_clients" else {})
        return query_clients(client, tool, limit=limit, filters=filters, **options)
    actual_limit = 500 if limit is None else limit
    client.authenticate()
    if tool == "list_clients":
        data = _fetch_clients(client, limit=actual_limit)
    elif tool == "list_wifi_clients":
        data = _list_wifi_clients_legacy(client, actual_limit)
    else:
        data = _list_wired_clients_legacy(client, actual_limit)
    return format_legacy(data, fields=options.get("fields"), result_format=options.get("resultFormat"))


def _list_wifi_clients_legacy(client: OmadaClient, limit: int = 500) -> PaginatedList:
    return _list_by_wireless_legacy(client, True, limit)


def _list_wired_clients_legacy(client: OmadaClient, limit: int = 500) -> PaginatedList:
    return _list_by_wireless_legacy(client, False, limit)


def _list_by_wireless_legacy(client: OmadaClient, wireless: bool, limit: int) -> PaginatedList:
    with client.request_budget(24) as budget:
        rows, meta = _fetch_client_rows_with_meta(client, _site(client))
    missing = any("wireless" not in row for row in rows)
    matched = [project_client(row) for row in rows
               if "wireless" in row and bool(row["wireless"]) == wireless]
    capped = matched[:limit] if limit else matched
    hit_limit = bool(limit and len(matched) > limit)
    upstream_truncated = bool(meta.get("truncated")) or missing
    truncated = hit_limit or upstream_truncated
    reason = (
        f"results capped at limit={limit}"
        if hit_limit
        else "field_unavailable" if missing else meta.get("truncationReason")
    )
    data = PaginatedList(
        capped,
        truncated=truncated,
        total_rows=len(matched) if not upstream_truncated else None,
        pages_fetched=meta.get("pagesFetched"),
        max_pages=meta.get("maxPages"),
        limit=limit or None,
        truncation_reason=reason,
    )
    data.pagination.update(complete=not upstream_truncated, totalRowsExact=not upstream_truncated,
                           totalRowsSource="matched", controllerRequests=budget.used,
                           rowsScanned=meta.get("rowsScanned", 0), source=meta.get("source"),
                           warnings=["Some rows omit wireless; filtered totals are incomplete."] if missing else [])
    return data


def _get_client(client: OmadaClient, mac: str) -> dict[str, Any]:
    wanted = normalize_mac(mac)
    needle = str(mac).strip().lower()
    def match(entry: dict[str, Any]) -> bool:
        if wanted and normalize_mac(entry.get("mac", "")) == wanted:
            return True
        return bool(needle and needle in (
            str(entry.get("name", "")).lower(),
            str(entry.get("hostName", "")).lower(),
            str(entry.get("ip", "")).lower(),
        ))
    with client.request_budget(24):
        rows, meta = _fetch_client_rows_with_meta(client, _site(client), match=match)
    if meta.get("found"):
        return project_client(rows[0])
    compact_mac = "".join(ch for ch in str(mac) if ch.isalnum())
    is_mac = len(compact_mac) == 12 and all(ch.lower() in "0123456789abcdef" for ch in compact_mac)
    if not is_mac and any(
        "name" not in row or "hostName" not in row or not ("ip" in row or "ipSetting" in row)
        for row in rows
    ):
        meta["complete"] = False
    if not meta.get("complete"):
        raise OmadaError("client lookup incomplete; cannot determine whether the client exists",
                         hint="use paged list_clients and continue with nextCursor")
    raise OmadaError(
        f"no client matches {mac!r}",
        hint="list clients first; the argument accepts a MAC, hostname or IP address",
    )


def _search_clients_legacy(
    client: OmadaClient, query: str | None = None, active: bool | None = None,
    wireless: bool | None = None, guest: bool | None = None, vlan: Any | None = None,
    ssid: str | None = None, limit: int = 500,
) -> PaginatedList:
    from ._client_query import _available, matches, project_search_client
    from ._client_search import collect_search_rows

    raw_rows, meta = collect_search_rows(client, _site(client), active)
    filters = dict(query=query, active=active, wireless=wireless, guest=guest,
                   vlan=_coerce_vlan(vlan), ssid=ssid)
    results = []
    missing = False
    for row in raw_rows:
        projected = project_search_client(row)
        hit, unavailable = matches(projected, _available(row), filters)
        missing = missing or unavailable
        if hit:
            results.append(projected)
    complete = bool(meta["complete"]) and not missing
    hit_limit = bool(limit and len(results) > limit)
    reason = (f"results capped at limit={limit}" if hit_limit else
              "field_unavailable" if missing else meta.get("truncationReason"))
    data = PaginatedList(results[:limit] if limit else results,
                         truncated=not complete or hit_limit,
                         total_rows=len(results) if complete else None,
                         pages_fetched=meta["pagesFetched"], max_pages=meta["maxPages"],
                         limit=limit or None, truncation_reason=reason)
    data.pagination.update({key: value for key, value in meta.items()
                            if key not in {"totalRows", "truncated", "truncationReason"}})
    data.pagination.update(complete=complete, totalRowsExact=complete,
                           totalRowsSource="matched" if complete else "observed")
    if missing:
        data.pagination["warnings"].append("Some rows omit required filter fields; totals are incomplete.")
    return data


def _list_wifi_clients(client: OmadaClient, limit: int | None = None, **options: Any) -> Any:
    return _client_list(client, "list_wifi_clients", limit, options)


def _list_wired_clients(client: OmadaClient, limit: int | None = None, **options: Any) -> Any:
    return _client_list(client, "list_wired_clients", limit, options)


def _search_clients(client: OmadaClient, query: str | None = None, active: bool | None = None,
                    wireless: bool | None = None, guest: bool | None = None,
                    vlan: Any | None = None, ssid: str | None = None,
                    limit: int | None = None, **options: Any) -> Any:
    from ._client_query import format_legacy, query_clients, selected_fields
    selected_fields(options.get("fields"), True)
    filters: dict[str, Any] = dict(query=query, active=active, wireless=wireless, guest=guest,
                   vlan=_coerce_vlan(vlan), ssid=ssid)
    if options.get("pageSize") is not None or options.get("cursor") is not None:
        return query_clients(client, "search_clients", limit=limit, filters=filters, **options)
    data = _search_clients_legacy(client, limit=500 if limit is None else limit, **filters)
    return format_legacy(data, fields=options.get("fields"),
                         result_format=options.get("resultFormat"), search=True)
