"""Read domain module: clients_read."""

from __future__ import annotations

from typing import Any

from ..client import OmadaClient, OmadaError
from ._common import PaginatedList, as_mapping
from ._tool_model import (
    _as_int,
    _as_num_or_none,
    _coerce_vlan,
    _iso,
    _pick,
    _site,
    as_int_or_none,
    normalize_mac,
)
from ._write_fetchers import _fetch_clients_filtered, _fetch_insight_clients

_MAX_CLIENT_PAGES = 20


def project_client(client: dict[str, Any]) -> dict[str, Any]:
    """Client projection, including the fields an admin actually asks for."""
    wireless = bool(client.get("wireless"))
    return {
        "mac": str(client.get("mac") or ""),
        "name": str(_pick(client, "name", "hostName", default="") or ""),
        "hostName": str(client.get("hostName") or ""),
        "ip": str(client.get("ip") or as_mapping(client.get("ipSetting")).get("ip") or ""),
        "wireless": wireless,
        "guest": bool(client.get("guest")),
        "active": bool(client.get("active", True)),
        "ssid": str(client.get("ssid") or ""),
        "apName": str(_pick(client, "apName", "switchName", default="") or ""),
        "networkName": str(_pick(client, "networkName", "network", default="") or ""),
        "vlan": _as_int(_pick(client, "vid", "vlan", default=0), 0),
        "download": _as_int(_pick(client, "download", "trafficDown", default=0), 0),
        "upload": _as_int(_pick(client, "upload", "trafficUp", default=0), 0),
        "duration": _as_int(_pick(client, "duration", "uptime", default=0), 0),
        "lastSeen": _iso(client.get("lastSeen")),
        "signal": _pick(client, "signalLevel", "rssi", default=None),
        "rssi": _as_num_or_none(client.get("rssi")),
        "signalLevel": _as_num_or_none(client.get("signalLevel")),
        "snr": _as_num_or_none(client.get("snr")),
        "txRate": as_int_or_none(client.get("txRate")),
        "rxRate": as_int_or_none(client.get("rxRate")),
        "uptime": as_int_or_none(client.get("uptime")),
        "connectType": str(client.get("connectType") or ""),
        "radioId": as_int_or_none(client.get("radioId")),
        "channel": as_int_or_none(client.get("channel")),
    }


def _paginate_client_rows_with_meta(
    client: OmadaClient,
    site: Any,
    endpoint: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Page a single client endpoint, deduping by normalised MAC with pagination metadata."""
    collected: list[dict[str, Any]] = []
    seen = set()
    previous_rows = None
    separator = "&" if "?" in endpoint else "?"
    pages_fetched = 0
    total_int: int | None = None
    exhausted_loop = False
    stopped_duplicate = False
    for page in range(1, _MAX_CLIENT_PAGES + 1):
        payload = client.api(
            f"sites/{site.site_id}/{endpoint}"
            f"{separator}currentPage={page}&currentPageSize=100"
        )
        pages_fetched += 1
        if payload.get("errorCode") != 0:
            raise OmadaError(
                f"client query failed: {payload.get('msg', 'unknown')}",
                code=payload.get("errorCode"),
                hint="clients needs Admin; insight/clients accepts any role",
                endpoint=f"sites/{{id}}/{endpoint}",
            )
        result = payload.get("result") or {}
        rows = result.get("data") or []
        total_raw = result.get("totalRows")
        if total_raw is not None:
            total_int = int(total_raw)
        if not rows or rows == previous_rows:
            stopped_duplicate = bool(rows)
            break
        previous_rows = rows
        for row in rows:
            mac = normalize_mac(row.get("mac", ""))
            if mac and mac in seen:
                continue
            if mac:
                seen.add(mac)
            collected.append(row)
        if total_int is not None:
            if len(collected) >= total_int:
                break
        elif len(rows) < 100:
            break
        if page == _MAX_CLIENT_PAGES:
            exhausted_loop = True

    truncated = False
    reason: str | None = None
    if exhausted_loop and (total_int is None or len(collected) < total_int):
        truncated = True
        reason = f"client pagination reached maxPages={_MAX_CLIENT_PAGES}"
    elif total_int is not None and len(collected) < total_int and not stopped_duplicate:
        truncated = True
        reason = f"controller returned {len(collected)} of {total_int} totalRows"

    return collected, {
        "pagesFetched": pages_fetched,
        "maxPages": _MAX_CLIENT_PAGES,
        "totalRows": total_int if total_int is not None else len(collected),
        "truncated": truncated,
        "truncationReason": reason,
    }


def _paginate_client_rows(client: OmadaClient, site: Any, endpoint: str) -> list[dict[str, Any]]:
    """Page a single client endpoint, deduping by normalised MAC."""
    rows, _ = _paginate_client_rows_with_meta(client, site, endpoint)
    return rows


def _fetch_client_rows_with_meta(client: OmadaClient, site: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    first_error: OmadaError | None = None
    for endpoint in ("clients?filters.active=true", "insight/clients"):
        try:
            return _paginate_client_rows_with_meta(client, site, endpoint)
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
    raw_rows, page_meta = _fetch_client_rows_with_meta(client, site)
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
    return PaginatedList(
        collected,
        truncated=truncated,
        total_rows=total_rows,
        pages_fetched=page_meta.get("pagesFetched"),
        max_pages=page_meta.get("maxPages"),
        limit=limit or None,
        truncation_reason=reason,
    )


def _list_clients(client: OmadaClient, limit: int = 500) -> PaginatedList:
    client.authenticate()
    return _fetch_clients(client, limit=limit)


def _list_wifi_clients(client: OmadaClient, limit: int = 500) -> PaginatedList:
    all_clients = _list_clients(client, limit=0)
    matched = [c for c in all_clients if c.get("wireless")]
    capped = matched[:limit] if limit else matched
    hit_limit = bool(limit and len(matched) > limit)
    upstream_truncated = all_clients.truncated
    truncated = hit_limit or upstream_truncated
    reason = (
        f"results capped at limit={limit}"
        if hit_limit
        else all_clients.pagination.get("truncationReason")
    )
    return PaginatedList(
        capped,
        truncated=truncated,
        total_rows=len(matched) if not upstream_truncated else None,
        pages_fetched=all_clients.pagination.get("pagesFetched"),
        max_pages=all_clients.pagination.get("maxPages"),
        limit=limit or None,
        truncation_reason=reason,
    )


def _list_wired_clients(client: OmadaClient, limit: int = 500) -> PaginatedList:
    all_clients = _list_clients(client, limit=0)
    matched = [c for c in all_clients if not c.get("wireless")]
    capped = matched[:limit] if limit else matched
    hit_limit = bool(limit and len(matched) > limit)
    upstream_truncated = all_clients.truncated
    truncated = hit_limit or upstream_truncated
    reason = (
        f"results capped at limit={limit}"
        if hit_limit
        else all_clients.pagination.get("truncationReason")
    )
    return PaginatedList(
        capped,
        truncated=truncated,
        total_rows=len(matched) if not upstream_truncated else None,
        pages_fetched=all_clients.pagination.get("pagesFetched"),
        max_pages=all_clients.pagination.get("maxPages"),
        limit=limit or None,
        truncation_reason=reason,
    )


def _get_client(client: OmadaClient, mac: str) -> dict[str, Any]:
    wanted = normalize_mac(mac)
    needle = str(mac).strip().lower()
    for entry in _fetch_clients(client, limit=0):
        if normalize_mac(entry.get("mac", "")) == wanted:
            return entry
        if needle and needle in (
            str(entry.get("name", "")).lower(),
            str(entry.get("hostName", "")).lower(),
            str(entry.get("ip", "")).lower(),
        ):
            return entry
    raise OmadaError(
        f"no client matches {mac!r}",
        hint="list clients first; the argument accepts a MAC, hostname or IP address",
    )


def _search_clients(
    client: OmadaClient,
    query: str | None = None,
    active: bool | None = None,
    wireless: bool | None = None,
    guest: bool | None = None,
    vlan: Any | None = None,
    ssid: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    site = _site(client)
    vlan = _coerce_vlan(vlan)
    ssid_needle = str(ssid).strip().lower() if ssid is not None else None
    if ssid_needle == "":
        ssid_needle = None
    try:
        raw_rows = _fetch_clients_filtered(client, site, active=active)
    except OmadaError as exc:
        if exc.code in (-1007, -41011, -1600):
            raw_rows = _fetch_insight_clients(client, site)
        else:
            raise

    deduped: dict[str, dict[str, Any]] = {}
    ordered_without_mac: list[dict[str, Any]] = []
    for row in raw_rows:
        norm = normalize_mac(row.get("mac", ""))
        if not norm:
            ordered_without_mac.append(row)
            continue
        prev = deduped.get(norm)
        if prev is None or (bool(row.get("active", True)) and not bool(prev.get("active", True))):
            deduped[norm] = row

    q_norm = str(query or "").strip().lower()
    q_mac = normalize_mac(q_norm) if q_norm else ""
    results: list[dict[str, Any]] = []
    for row in list(deduped.values()) + ordered_without_mac:
        proj = project_client(row)
        if "blocked" in row:
            proj["blocked"] = bool(row.get("blocked"))
        ip_setting = row.get("ipSetting")
        if isinstance(ip_setting, dict) and ip_setting.get("useFixedAddr"):
            proj["fixedIp"] = str(ip_setting.get("ip") or "")
            if ip_setting.get("netId"):
                proj["fixedNetId"] = str(ip_setting.get("netId") or "")
        if active is not None and proj["active"] != bool(active):
            continue
        if wireless is not None and proj["wireless"] != bool(wireless):
            continue
        if guest is not None and proj["guest"] != bool(guest):
            continue
        if vlan is not None and _as_int(proj.get("vlan"), -1) != vlan:
            continue
        if ssid_needle is not None:
            have = str(proj.get("ssid") or "").strip().lower()
            if not have or (have != ssid_needle and ssid_needle not in have):
                continue
        if q_norm:
            mac_val = proj["mac"].lower()
            mac_norm = normalize_mac(mac_val)
            haystack = (
                mac_val,
                mac_norm,
                proj["name"].lower(),
                proj["hostName"].lower(),
                proj["ip"].lower(),
                proj["ssid"].lower(),
                proj["networkName"].lower(),
            )
            if not any(q_norm in field or (q_mac and q_mac in field) for field in haystack):
                continue
        results.append(proj)
    total_matching = len(results)
    if limit and len(results) > limit:
        capped = results[:limit]
        truncated = True
        reason: str | None = f"results capped at limit={limit}"
    else:
        capped = results
        truncated = False
        reason = None
    return PaginatedList(
        capped,
        truncated=truncated,
        total_rows=total_matching,
        limit=limit or None,
        truncation_reason=reason,
    )


_CLIENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "hostName": {"type": "string"},
        "ip": {"type": "string"},
        "wireless": {"type": "boolean"},
        "guest": {"type": "boolean"},
        "active": {"type": "boolean"},
        "ssid": {"type": "string"},
        "apName": {"type": "string"},
        "networkName": {"type": "string"},
        "vlan": {"type": "integer"},
        "download": {"type": "integer"},
        "upload": {"type": "integer"},
        "duration": {"type": "integer"},
        "lastSeen": {"type": "string"},
        "signal": {"type": ["integer", "number", "null"]},
        "rssi": {"type": ["integer", "number", "null"]},
        "signalLevel": {"type": ["integer", "number", "null"]},
        "snr": {"type": ["integer", "number", "null"]},
        "txRate": {"type": ["integer", "null"]},
        "rxRate": {"type": ["integer", "null"]},
        "uptime": {"type": ["integer", "null"]},
        "connectType": {"type": "string"},
        "radioId": {"type": ["integer", "null"]},
        "channel": {"type": ["integer", "null"]},
    },
    "required": [
        "mac", "name", "hostName", "ip", "wireless", "guest", "active",
        "ssid", "apName", "networkName", "vlan", "download", "upload",
        "duration", "lastSeen", "signal",
    ],
}


_SEARCH_CLIENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        **_CLIENT_SCHEMA["properties"],
        "blocked": {"type": "boolean"},
        "fixedIp": {"type": "string"},
        "fixedNetId": {"type": "string"},
    },
    "required": list(_CLIENT_SCHEMA["required"]),
}

