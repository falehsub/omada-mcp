"""Whitelisted client projections shared by legacy and incremental reads."""
from __future__ import annotations

from typing import Any

from ._common import as_mapping
from ._tool_model import _as_int, _as_num_or_none, _iso, _pick, as_int_or_none


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
        "signal": _as_num_or_none(_pick(client, "signalLevel", "rssi", default=None)),
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
