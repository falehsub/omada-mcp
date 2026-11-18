"""Whitelisted client projections shared by legacy and incremental reads."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._common import as_mapping
from ._tool_model import _as_int, _as_num_or_none, _iso, _pick, as_int_or_none


def client_flag(value: Any) -> bool | None:
    """Read a boolean without treating arbitrary values as true or false."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        return {"0": False, "false": False, "1": True, "true": True}.get(value.strip().lower())
    return None


def client_vlan(client: Mapping[str, Any]) -> int | None:
    for key in ("vid", "vlan"):
        value = client.get(key)
        if isinstance(value, str):
            value = value.strip()
            if not value.isascii() or not value.isdecimal():
                continue
            value = value.lstrip("0") or "0"
            if len(value) > 4:
                continue
            value = int(value)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 4094:
            return value
    return None


def client_text(*values: Any) -> str | None:
    """Choose the first valid nonempty alias, preserving an explicit empty value."""
    text = None
    for value in values:
        if isinstance(value, str):
            if value:
                return value
            text = value
    return text


def project_client(client: dict[str, Any]) -> dict[str, Any]:
    """Client projection, including the fields an admin actually asks for."""
    return {
        "mac": client_text(client.get("mac")) or "",
        "name": client_text(client.get("name"), client.get("hostName")) or "",
        "hostName": client_text(client.get("hostName")) or "",
        "ip": client_text(client.get("ip"), as_mapping(client.get("ipSetting")).get("ip")) or "",
        "wireless": client_flag(client.get("wireless")) is True,
        "guest": client_flag(client.get("guest")) is True,
        "active": client_flag(client.get("active")),
        "ssid": client_text(client.get("ssid")) or "",
        "apName": client_text(client.get("apName"), client.get("switchName")) or "",
        "networkName": client_text(client.get("networkName"), client.get("network")) or "",
        "vlan": client_vlan(client) or 0,
        "download": _as_int(_pick(client, "download", "trafficDown", default=0), 0),
        "upload": _as_int(_pick(client, "upload", "trafficUp", default=0), 0),
        "duration": _as_int(_pick(client, "duration", "uptime", default=0), 0),
        "lastSeen": _iso(client.get("lastSeen")),
        "signal": _as_num_or_none(_pick(client, "signalLevel", "rssi", default=None)),
        "rssi": _as_num_or_none(client.get("rssi")),
        "signalLevel": _as_num_or_none(client.get("signalLevel")),
        "snr": _as_num_or_none(client.get("snr")),
        "txRate": as_int_or_none(client.get("txRate")),
        "rxRate": as_int_or_none(client.get("rxRate")),
        "uptime": as_int_or_none(client.get("uptime")),
        "connectType": client_text(client.get("connectType")) or "",
        "radioId": as_int_or_none(client.get("radioId")),
        "channel": as_int_or_none(client.get("channel")),
    }


_CLIENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mac": {"type": "string"},
        "name": {"type": "string"},
        "hostName": {"type": "string"},
        "ip": {"type": "string"},
        "wireless": {"type": "boolean"},
        "guest": {"type": "boolean"},
        "active": {"type": ["boolean", "null"]},
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
