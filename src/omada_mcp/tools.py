"""MCP tool definitions for omada-mcp.

Every tool is a thin, whitelisting projection over the controller's JSON. Two
product rules drive the design:

1. **Whitelist fields, never echo objects.** The WLAN object carries the SSID
   pre-shared key (``securityKey``), the site object carries the device account
   and the client object carries location data. Tools return an explicit field
   set and report ``hasPresharedKey: true`` instead of the key itself.
2. **Declare intent.** Each tool ships MCP annotations
   (``readOnlyHint`` / ``destructiveHint`` / ``idempotentHint`` /
   ``openWorldHint``) so hosts can gate or auto-approve calls without guessing.

v1.0 exposes eight read-only tools. ``OMADA_READ_ONLY=true`` is enforced by the
dispatcher for any tool that is not declared read-only, so adding a write tool in
a later release cannot silently bypass the safety switch.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .client import OmadaClient, OmadaError, SiteInfo

__all__ = [
    "TOOLS",
    "TOOL_MAP",
    "Tool",
    "get_tool",
    "normalize_mac",
    "tool_descriptors",
]

_MAX_CLIENT_PAGES = 20


def normalize_mac(value: str) -> str:
    """Normalise ``AABBCCDDEEFF`` / ``AA-BB-CC-DD-EE-FF`` / ``aa:bb:..`` to colons."""
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).lower()
    if len(cleaned) == 12 and all(ch in "0123456789abcdef" for ch in cleaned):
        return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    return str(value or "").strip().lower()


def _iso(ms: Any) -> str:
    """Epoch-milliseconds to a UTC ISO-8601 string (empty when absent)."""
    try:
        stamp = float(ms)
    except (TypeError, ValueError):
        return ""
    if not stamp:
        return ""
    try:
        return datetime.datetime.fromtimestamp(stamp / 1000.0, datetime.timezone.utc) \
            .isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return str(ms)


def _pick(source: Dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in source and source[name] not in (None, ""):
            return source[name]
    return default


# -- projections -------------------------------------------------------------

_DEVICE_FIELDS: Tuple[Tuple[str, Tuple[str, ...], Any], ...] = (
    ("mac", ("mac",), ""),
    ("name", ("name",), ""),
    ("type", ("type",), ""),
    ("model", ("showModel", "model"), ""),
    ("ip", ("ip",), ""),
    ("firmware", ("firmwareVersion",), ""),
    ("uptime", ("uptime", "uptimeLong"), ""),
    ("clientCount", ("clientNum",), 0),
    ("status", ("statusCategory",), -1),
)


def project_device(device: Dict[str, Any]) -> Dict[str, Any]:
    return {out: _pick(device, *src, default=default) for out, src, default in _DEVICE_FIELDS}


def project_client(client: Dict[str, Any]) -> Dict[str, Any]:
    """Client projection, including the fields an admin actually asks for."""
    wireless = bool(client.get("wireless"))
    return {
        "mac": client.get("mac", ""),
        "name": _pick(client, "name", "hostName", default=""),
        "hostName": client.get("hostName", ""),
        "ip": client.get("ip", ""),
        "wireless": wireless,
        "guest": bool(client.get("guest")),
        "active": bool(client.get("active", True)),
        "ssid": client.get("ssid", ""),
        "apName": _pick(client, "apName", "switchName", default=""),
        "networkName": _pick(client, "networkName", "network", default=""),
        "vlan": _pick(client, "vid", "vlan", default=0),
        "download": client.get("download", 0),
        "upload": client.get("upload", 0),
        "duration": client.get("duration", 0),
        "lastSeen": _iso(client.get("lastSeen")),
        "signal": _pick(client, "signalLevel", "rssi", default=None),
    }


#: Fields safe to expose from a WLAN object. ``securityKey`` is deliberately
#: absent: it is the literal SSID passphrase in plaintext.
_WLAN_FIELDS: Tuple[str, ...] = (
    "id", "name", "ssid", "band", "enabled", "guest", "security", "vlanId",
    "networkName", "hideSsid", "macFilterEnable", "rateLimitEnable",
)


def project_wlan(wlan: Dict[str, Any]) -> Dict[str, Any]:
    projected = {key: wlan[key] for key in _WLAN_FIELDS if key in wlan}
    projected["hasPresharedKey"] = bool(wlan.get("securityKey"))
    return projected


# -- tool handlers -----------------------------------------------------------

def _site(client: OmadaClient) -> SiteInfo:
    """Authenticate if needed and return the resolved site (never ``None``)."""
    client.authenticate()
    site = client.site
    if site is None:  # pragma: no cover - authenticate() guarantees a site
        raise OmadaError("site resolution failed", hint="run `omada-mcp --doctor`")
    return site


def _list_devices(client: OmadaClient) -> List[Dict[str, Any]]:
    site = _site(client)
    result = client.api(f"sites/{site.site_id}/devices?currentPage=1&currentPageSize=50")
    if result.get("errorCode") != 0:
        raise OmadaError(f"devices query failed: {result.get('msg', 'unknown')}",
                         code=result.get("errorCode"), endpoint="sites/{id}/devices")
    rows = result.get("result")
    if isinstance(rows, dict):  # some 5.x builds wrap the list
        rows = rows.get("data", [])
    return [project_device(row) for row in (rows or [])]


def _fetch_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    site = _site(client)
    collected: List[Dict[str, Any]] = []
    seen = set()
    for page in range(1, _MAX_CLIENT_PAGES + 1):
        payload = client.api(
            f"sites/{site.site_id}/insight/clients"
            f"?currentPage={page}&currentPageSize=100"
        )
        if payload.get("errorCode") != 0:
            raise OmadaError(
                f"client query failed: {payload.get('msg', 'unknown')}",
                code=payload.get("errorCode"),
                hint="insight/clients needs any role; clients/{mac} needs Admin",
                endpoint="sites/{id}/insight/clients",
            )
        result = payload.get("result") or {}
        rows = result.get("data") or []
        if not rows:
            break
        for row in rows:
            mac = normalize_mac(row.get("mac", ""))
            if mac and mac in seen:
                continue
            seen.add(mac)
            collected.append(project_client(row))
            if limit and len(collected) >= limit:
                return collected
        total = int(result.get("totalRows") or 0)
        if len(collected) >= total:
            break
    return collected


def _list_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    client.authenticate()
    return _fetch_clients(client, limit=limit)


def _list_wifi_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    return [c for c in _list_clients(client, limit=limit) if c.get("wireless")]


def _list_wired_clients(client: OmadaClient, limit: int = 500) -> List[Dict[str, Any]]:
    return [c for c in _list_clients(client, limit=limit) if not c.get("wireless")]


def _get_device(client: OmadaClient, mac: str) -> Dict[str, Any]:
    wanted = normalize_mac(mac)
    for device in _list_devices(client):
        if normalize_mac(device.get("mac", "")) == wanted or \
                str(device.get("name", "")).lower() == str(mac).strip().lower():
            return device
    raise OmadaError(
        f"no device matches {mac!r}",
        hint="list devices first; the argument accepts a MAC or the device name",
    )


def _get_client(client: OmadaClient, mac: str) -> Dict[str, Any]:
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


def _list_wlans(client: OmadaClient) -> List[Dict[str, Any]]:
    site = _site(client)
    result = client.api(f"sites/{site.site_id}/setting/wlans")
    if result.get("errorCode") != 0:
        raise OmadaError(f"WLAN query failed: {result.get('msg', 'unknown')}",
                         code=result.get("errorCode"), endpoint="sites/{id}/setting/wlans")
    payload = result.get("result") or {}
    rows = payload.get("data") if isinstance(payload, dict) else payload
    return [project_wlan(row) for row in (rows or [])]


def _get_site_info(client: OmadaClient) -> Dict[str, Any]:
    site = _site(client)
    result = client.api(f"sites/{site.site_id}")
    detail = result.get("result") if result.get("errorCode") == 0 else {}
    detail = detail if isinstance(detail, dict) else {}
    devices = _list_devices(client)
    clients = _fetch_clients(client, limit=0)
    wireless = sum(1 for c in clients if c.get("wireless"))
    return {
        "name": detail.get("name") or site.name,
        "id": detail.get("id") or site.site_id,
        "sitesVisible": site.total,
        "wanConnected": bool(detail.get("wan", False)),
        "lanConnected": bool(detail.get("lan", False)),
        "wlanConnected": bool(detail.get("wlan", False)),
        "deviceCount": len(devices),
        "clientCount": len(clients),
        "wifiClientCount": wireless,
        "wiredClientCount": len(clients) - wireless,
        "controllerVersion": getattr(client.auth_info, "controller_version", None),
        "siteUrl": f"{client.config.base_url}/{client.controller_id}/api/v2/sites/{site.site_id}",
    }


# -- registry ----------------------------------------------------------------

@dataclass(frozen=True)
class Tool:
    """A tool plus the MCP annotations that describe its side effects."""

    name: str
    title: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[..., Any]
    read_only: bool = True
    destructive: bool = False
    idempotent: bool = True
    open_world: bool = True

    def descriptor(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": self.open_world,
            },
        }


_EMPTY: Dict[str, Any] = {"type": "object", "properties": {}}
_LIMIT_PROP = {
    "type": "integer",
    "minimum": 1,
    "maximum": 5000,
    "default": 500,
    "description": "Maximum number of clients to return (default 500, max 5000)",
}

TOOLS: Tuple[Tool, ...] = (
    Tool(
        name="list_devices",
        title="List Omada devices",
        description=("List all managed network devices (APs, switches, gateways) on the site "
                    "with MAC, model, firmware, IP, uptime and client count."),
        input_schema=_EMPTY,
        handler=_list_devices,
    ),
    Tool(
        name="list_clients",
        title="List clients",
        description=("List connected clients (WiFi and wired) with MAC, IP, SSID, AP, VLAN, "
                    "traffic counters, session duration and last-seen time."),
        input_schema={"type": "object", "properties": {"limit": _LIMIT_PROP}},
        handler=_list_clients,
    ),
    Tool(
        name="list_wifi_clients",
        title="List WiFi clients",
        description="List only wireless clients, same fields as list_clients.",
        input_schema={"type": "object", "properties": {"limit": _LIMIT_PROP}},
        handler=_list_wifi_clients,
    ),
    Tool(
        name="list_wired_clients",
        title="List wired clients",
        description="List only wired clients, same fields as list_clients.",
        input_schema={"type": "object", "properties": {"limit": _LIMIT_PROP}},
        handler=_list_wired_clients,
    ),
    Tool(
        name="get_device",
        title="Get device",
        description="Get one device by MAC address or device name.",
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string",
                        "description": "Device MAC (any format) or device name"},
            },
            "required": ["mac"],
        },
        handler=_get_device,
    ),
    Tool(
        name="get_client",
        title="Get client",
        description="Get one client by MAC address, hostname or IP address.",
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string",
                        "description": "Client MAC (any format), hostname or IP address"},
            },
            "required": ["mac"],
        },
        handler=_get_client,
    ),
    Tool(
        name="list_wlans",
        title="List WLANs",
        description=("List configured WLANs/SSIDs with band, VLAN, security type and guest "
                    "flag. Pre-shared keys are never returned; a boolean "
                    "hasPresharedKey reports whether one is set."),
        input_schema=_EMPTY,
        handler=_list_wlans,
    ),
    Tool(
        name="get_site_info",
        title="Get site summary",
        description=("Site summary: name, id, WAN/LAN/WLAN state, device and client counts, "
                    "controller version."),
        input_schema=_EMPTY,
        handler=_get_site_info,
    ),
)

TOOL_MAP: Dict[str, Tool] = {tool.name: tool for tool in TOOLS}


def get_tool(name: str) -> Optional[Tool]:
    return TOOL_MAP.get(str(name or ""))


def tool_descriptors() -> List[Dict[str, Any]]:
    return [tool.descriptor() for tool in TOOLS]
