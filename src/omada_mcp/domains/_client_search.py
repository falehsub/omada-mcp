"""Bounded raw-row collection for the legacy filtered client search."""

from __future__ import annotations

from typing import Any

from ..client import OmadaClient, OmadaError
from ._tool_model import normalize_mac

MAX_SEARCH_PAGES = 20
MAX_SEARCH_REQUESTS = 24
_FALLBACK_CODES = frozenset((-1007, -41011, -1600))


def collect_search_rows(
    client: OmadaClient,
    site: Any,
    active: bool | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Collect legacy search sources with honest completeness metadata.

    For an unfiltered search, inactive rows are inserted first and active rows
    replace matching values without changing their original position. The
    rich endpoint is abandoned in full if it returns one of the known
    permission/unsupported errors; the Viewer-safe insight source then supplies
    the complete fallback traversal, subject to the same shared budgets.
    """
    # Import lazily: clients_read uses this collector from its legacy adapter.
    from .clients_read import _paginate_client_rows_with_meta

    if active is None:
        sources = [
            ("clients?filters.active=false", False),
            ("clients?filters.active=true", True),
        ]
    else:
        flag = "true" if active else "false"
        sources = [(f"clients?filters.active={flag}", active)]

    page_budget = [MAX_SEARCH_PAGES]
    scan_counter = [0]
    rows_by_mac: dict[str, dict[str, Any]] = {}
    rows_without_mac: list[dict[str, Any]] = []
    source_metas: list[dict[str, Any]] = []
    warnings: list[str] = []
    source_name = "clients"
    fallback = False

    with client.request_budget(MAX_SEARCH_REQUESTS) as budget:
        try:
            for endpoint, is_active_source in sources:
                rows, meta = _paginate_client_rows_with_meta(
                    client,
                    site,
                    endpoint,
                    max_pages=page_budget[0],
                    page_budget=page_budget,
                    deduplicate=active is not None,
                    scan_counter=scan_counter,
                )
                source_metas.append(meta)
                for row in rows:
                    mac = normalize_mac(row.get("mac", ""))
                    if active is None:
                        # The legacy merge drops rows without MACs. Assignment
                        # replaces an inactive value while preserving position.
                        if not mac:
                            continue
                        if mac not in rows_by_mac or is_active_source:
                            rows_by_mac[mac] = row
                    elif mac:
                        # Explicit active filters preserve the first observed
                        # row for each MAC, as the original collector did.
                        rows_by_mac.setdefault(mac, row)
                    else:
                        rows_without_mac.append(row)
                if not meta.get("complete", not meta.get("truncated", False)):
                    break
        except OmadaError as exc:
            if exc.code not in _FALLBACK_CODES:
                raise
            fallback = True
            source_name = "insight/clients"
            warnings.append(
                "Rich client source unavailable; using Viewer-safe insight/clients."
            )

        if fallback:
            # Do not mix rich-source rows into a Viewer-safe fallback result.
            rows_by_mac.clear()
            rows_without_mac.clear()

        if fallback and page_budget[0] > 0:
            rows, fallback_meta = _paginate_client_rows_with_meta(
                client,
                site,
                "insight/clients",
                max_pages=page_budget[0],
                page_budget=page_budget,
                scan_counter=scan_counter,
            )
            source_metas = [fallback_meta]
            for row in rows:
                mac = normalize_mac(row.get("mac", ""))
                if mac:
                    rows_by_mac.setdefault(mac, row)
                else:
                    rows_without_mac.append(row)
                    warnings.append("An insight row has no MAC; identity deduplication is unavailable.")
        elif fallback:
            source_metas = [{
                "complete": False,
                "truncated": True,
                "truncationReason": "client query scan budget exhausted before fallback",
                "pagesFetched": 0,
                "rowsScanned": 0,
            }]

        collected = list(rows_by_mac.values()) + rows_without_mac
        all_complete = (
            not fallback
            and len(source_metas) == len(sources)
            and all(meta.get("complete", not meta.get("truncated", False)) for meta in source_metas)
        ) or (
            fallback
            and len(source_metas) == 1
            and source_metas[0].get("complete", not source_metas[0].get("truncated", False))
        )

        # The shared page counter advances before each collection API call,
        # including a denied/error response or a dispatch blocked by the HTTP
        # request budget.
        pages_fetched = MAX_SEARCH_PAGES - page_budget[0]
        rows_scanned = scan_counter[0]
        truncation_reason = next(
            (str(meta["truncationReason"]) for meta in source_metas
             if meta.get("truncationReason")),
            None,
        )
        result_meta: dict[str, Any] = {
            "complete": all_complete,
            "truncated": not all_complete,
            "totalRowsExact": all_complete,
            "pagesFetched": pages_fetched,
            "maxPages": MAX_SEARCH_PAGES,
            "controllerRequests": budget.used,
            "rowsScanned": rows_scanned,
            "source": source_name,
            "warnings": warnings,
        }
        if all_complete:
            result_meta["totalRows"] = len(collected)
        elif truncation_reason:
            result_meta["truncationReason"] = truncation_reason
        if len(source_metas) == 1 and source_metas[0].get("sourceTotalRows") is not None:
            result_meta["sourceTotalRows"] = source_metas[0]["sourceTotalRows"]

    return collected, result_meta
