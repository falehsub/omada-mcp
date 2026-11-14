"""Read domain module: routing_dns_read."""

from __future__ import annotations

from typing import Any

from .._projections import project_controller_row
from ..client import OmadaClient
from ._common import try_paginate
from ._tool_model import _as_int, _site
from ._write_fetchers import _fetch_port_forwards, _fetch_static_routes


def _project_port_forward(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row.get("id") or ""),
        "name": str(row.get("name") or ""),
        "status": bool(row.get("status", False)),
        "externalPort": str(row.get("externalPort") or ""),
        "forwardIp": str(row.get("forwardIp") or ""),
        "forwardPort": str(row.get("forwardPort") or ""),
        "protocol": row.get("protocol") if row.get("protocol") is not None else "all",
        "from": row.get("from"),
        "limitedAddresses": [str(x) for x in (row.get("limitedAddresses") or [])],
        "interfaceWanPortId": [str(x) for x in (row.get("interfaceWanPortId") or [])],
        "dmz": bool(row.get("dMZ", row.get("dmz", False))),
    }


def _project_static_route(row: dict[str, Any]) -> dict[str, Any]:
    dests = row.get("destinations")
    if isinstance(dests, str):
        dest_list = [dests] if dests else []
    elif isinstance(dests, list):
        dest_list = [str(x) for x in dests]
    else:
        single = row.get("destination")
        dest_list = [str(single)] if single else []
    return {
        "id": str(row.get("id") or ""),
        "name": str(row.get("name") or ""),
        "status": bool(row.get("status", False)),
        "routeType": _as_int(row.get("routeType"), 0) if row.get("routeType") is not None else None,
        "destinations": dest_list,
        "nextHopIp": str(row.get("nextHopIp") or row.get("nextHop") or ""),
        "interfaceId": str(row.get("interfaceId") or ""),
        "metric": _as_int(row.get("metric"), 0) if row.get("metric") is not None else None,
    }


def _list_port_forwards(client: OmadaClient) -> list[dict[str, Any]]:
    site = _site(client)
    return [_project_port_forward(row) for row in _fetch_port_forwards(client, site)]


def _list_static_routes(client: OmadaClient) -> list[dict[str, Any]]:
    site = _site(client)
    return [_project_static_route(row) for row in _fetch_static_routes(client, site)]


def _list_policy_routes(client: OmadaClient) -> dict[str, Any]:
    site = _site(client)
    warnings: list[str] = []
    rows, _, ok = try_paginate(
        client, f"sites/{site.site_id}/setting/transmission/policyRoutings",
        warnings, label="policy routes",
    )
    cleaned = [project_controller_row("policyRoutes", r) for r in rows] if ok else []
    return {
        "items": cleaned,
        "count": len(cleaned),
        "supported": ok,
        "warnings": warnings,
    }


def _list_lan_dns_rules(client: OmadaClient) -> dict[str, Any]:
    site = _site(client)
    warnings: list[str] = []
    rows, _, ok = try_paginate(
        client, f"sites/{site.site_id}/setting/lan/dns",
        warnings, label="LAN DNS rules",
    )
    cleaned = [project_controller_row("lanDnsRules", r) for r in rows] if ok else []
    return {
        "items": cleaned,
        "count": len(cleaned),
        "supported": ok,
        "warnings": warnings,
    }


_PORT_FORWARD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "status": {"type": "boolean"},
        "externalPort": {"type": "string"},
        "forwardIp": {"type": "string"},
        "forwardPort": {"type": "string"},
        "protocol": {"type": ["integer", "string"]},
        "from": {"type": ["integer", "string", "null"]},
        "limitedAddresses": {"type": "array", "items": {"type": "string"}},
        "interfaceWanPortId": {"type": "array", "items": {"type": "string"}},
        "dmz": {"type": "boolean"},
    },
    "required": ["id", "name", "status", "externalPort", "forwardIp", "forwardPort"],
}


_STATIC_ROUTE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "status": {"type": "boolean"},
        "routeType": {"type": ["integer", "null"]},
        "destinations": {"type": "array", "items": {"type": "string"}},
        "nextHopIp": {"type": "string"},
        "interfaceId": {"type": "string"},
        "metric": {"type": ["integer", "null"]},
    },
    "required": ["id", "name", "status", "destinations", "nextHopIp"],
}

