"""Read domain module: _tool_model."""

from __future__ import annotations

import datetime
import re
from collections.abc import Callable
from copy import deepcopy as _deepcopy
from dataclasses import dataclass
from typing import Any

from ..client import OmadaClient, OmadaError, SiteInfo
from ._common import as_float as _as_float

_TOOL_CATEGORIES: dict[str, str] = {
    # core
    "list_devices": "core",
    "list_clients": "core",
    "list_wifi_clients": "core",
    "list_wired_clients": "core",
    "get_device": "core",
    "get_client": "core",
    "list_wlans": "core",
    "get_site_info": "core",
    "explain_error": "core",
    "get_config_snapshot": "core",
    "search_clients": "core",
    "list_lan_networks": "core",
    "list_dhcp_reservations": "core",
    "set_client_fixed_ip": "core",
    "release_client_fixed_ip": "core",
    "upsert_dhcp_reservation": "core",
    "delete_dhcp_reservation": "core",
    "create_lan_network": "core",
    "update_lan_network": "core",
    "delete_lan_network": "core",
    "set_vlan_dhcp_pools": "core",
    "set_vlan_isolation": "core",
    "set_client_blocked": "core",
    "reconnect_client": "core",
    "update_client": "core",
    "update_device": "core",
    "reboot_device": "core",
    "set_client_rate_limit": "core",
    # diagnostics
    "network_audit": "diagnostics",
    "list_logs": "diagnostics",
    "get_topology": "diagnostics",
    "get_wan_status": "diagnostics",
    "diagnose_client": "diagnostics",
    "diagnose_wan": "diagnostics",
    # switch
    "get_switch_ports": "switch",
    "list_port_profiles": "switch",
    "update_switch_port": "switch",
    "cycle_poe_port": "switch",
    "upsert_port_profile": "switch",
    "delete_port_profile": "switch",
    # wifi
    "get_ap_radios": "wifi",
    "get_rf_scan": "wifi",
    "list_wlan_groups": "wifi",
    "create_ssid": "wifi",
    "update_ssid": "wifi",
    "delete_ssid": "wifi",
    "update_ap_radio": "wifi",
    "start_rf_scan": "wifi",
    "assign_ap_wlan_group": "wifi",
    "set_client_lock_to_ap": "wifi",
    # routing
    "list_port_forwards": "routing",
    "list_static_routes": "routing",
    "get_network_services": "routing",
    "list_vpn_tunnels": "routing",
    "list_policy_routes": "routing",
    "list_lan_dns_rules": "routing",
    "upsert_port_forward": "routing",
    "delete_port_forward": "routing",
    "upsert_static_route": "routing",
    "delete_static_route": "routing",
    "upsert_mdns_rule": "routing",
    "delete_mdns_rule": "routing",
    "set_upnp": "routing",
    "upsert_policy_route": "routing",
    "delete_policy_route": "routing",
    "upsert_lan_dns_rule": "routing",
    "delete_lan_dns_rule": "routing",
    # security
    "list_acls": "security",
    "list_ip_groups": "security",
    "get_security_status": "security",
    "create_ip_group": "security",
    "replace_ip_group": "security",
    "delete_ip_group": "security",
    "create_gateway_acl": "security",
    "update_gateway_acl": "security",
    "delete_gateway_acl": "security",
    "set_acl_rule_status": "security",
    "create_switch_acl": "security",
    "create_eap_acl": "security",
    # rollback
    "rollback_from_snapshot": "rollback",
}


_SLIM_WRITE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "applied": {"type": "boolean"},
        "dryRun": {"type": "boolean"},
        "verified": {"type": "boolean"},
        "target": {"type": "string"},
    },
    "required": ["applied", "dryRun", "verified", "target"],
}


def _list_output_schema(item_schema: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "items": {"type": "array", "items": item_schema},
            "count": {"type": "integer", "minimum": 0},
        },
        "required": ["items", "count"],
    }


def _slim_prop_type(prop_schema: Any) -> dict[str, Any]:
    if not isinstance(prop_schema, dict):
        return {}
    t = prop_schema.get("type")
    if t is not None:
        return {"type": t}
    return {}


def _slim_output_schema(schema: dict[str, Any], *, read_only: bool) -> dict[str, Any]:
    """Collapse deep nested trees while preserving MCP 2025-06-18 required invariants."""
    if not read_only:
        return _deepcopy(_SLIM_WRITE_OUTPUT_SCHEMA)
    req = list(schema.get("required") or [])
    props = schema.get("properties") or {}
    if set(req) == {"items", "count"} and "items" in props:
        return {
            "type": "object",
            "properties": {
                "items": {"type": "array", "items": {"type": "object"}},
                "count": {"type": "integer"},
            },
            "required": ["items", "count"],
        }
    slim_props = {k: _slim_prop_type(props[k]) for k in req if k in props}
    if not slim_props:
        for k, v in list(props.items())[:1]:
            slim_props[k] = _slim_prop_type(v)
    return {"type": "object", "properties": slim_props, "required": req}


_ABBREV_DOT_RE = re.compile(r"(?:^|\W)(?:e\.g|i\.e|etc|vs)$", re.IGNORECASE)


_CODE_HINT_QUOTED_RE = re.compile(r"'[^']+'")


_CODE_HINT_DIGIT_MAP_RE = re.compile(r"\b\d+=")


_CODE_HINT_TOKEN_RE = re.compile(r"\b(?:code|codes|hex|bitmask)\b", re.IGNORECASE)


_SLIM_CODE_HINT_REWRITES: dict[str, str] = {
    "Maximum number of clients to return (default 500, max 5000)": "Max clients (1-5000, default 500)",
    "Maximum log entries to return (default 100, max 1000)": "Max log entries (1-1000, default 100)",
    "Lookback window in hours (default 24; 0 for all available history)": "Lookback hours (0 = all history)",
    "Numeric Omada errorCode to explain (e.g. -1600, -33726)": "Omada errorCode (e.g. -1600, -33726)",
    "Optional VLAN ID, netId, or network name filter": "VLAN ID, netId, or network name",
    "Optional filter: 'ip' (0), 'port' (1), 'mac' (2), or 'all'": "'ip'(0), 'port'(1), 'mac'(2), or 'all'",
    "Bands: ['2g', '5g'] (or '6g'), comma string, or Omada bitmask (default ['2g', '5g'])": "['2g','5g','6g'], CSV, or bitmask",
    "'disable' (3), 'capable' (2), or 'mandatory' (1)": "'disable'(3), 'capable'(2), 'mandatory'(1)",
    "'all', 'tcp', 'udp', or Omada protocol integer": "'all', 'tcp', 'udp', or protocol int",
    "LED setting: 'off' (0), 'on' (1), or 'site' (2)": "'off' (0), 'on' (1), or 'site' (2)",
    "'auto', '10m', '100m', '1000m', '2500m', '10g' or code": "auto/10m/100m/1000m/2500m/10g or code",
    "Width: 'auto', '20', '40', '80', '160', '320' (or 20MHz..320MHz)": "'auto'|'20'|'40'|'80'|'160'|'320' (or MHz)",
    "'low' (0), 'medium' (1), 'high' (2), 'custom' (3), 'auto' (4)": "0=low, 1=med, 2=high, 3=custom, 4=auto",
    "Custom dBm TX power when txPowerLevel='custom'": "Custom dBm when txPowerLevel='custom'",
    "'all_ports' (0), 'custom_ports' (1), 'all_switches' (2), 'vlan' (3)": "0=all_ports,1=custom,2=switches,3=vlan",
}


def _needs_code_hint(prop: dict[str, Any]) -> bool:
    """Return True when an input property relies on numeric/string codes without an enum."""
    items = prop.get("items")
    if "enum" in prop or (isinstance(items, dict) and "enum" in items):
        return False
    ptype = prop.get("type")
    if ptype == "integer" or (isinstance(ptype, list) and "integer" in ptype):
        return True
    if isinstance(items, dict) and items.get("type") == "integer":
        return True
    if ptype == "string" or (isinstance(ptype, list) and "string" in ptype):
        desc = str(prop.get("description") or "")
        return bool(
            _CODE_HINT_DIGIT_MAP_RE.search(desc)
            or "|" in desc
            or len(_CODE_HINT_QUOTED_RE.findall(desc)) >= 3
            or _CODE_HINT_TOKEN_RE.search(desc)
        )
    return False


def _snap_words(text: str, limit: int) -> str:
    """Snap text strictly within ``limit`` characters at full word/token boundaries."""
    clean = " ".join(text.strip().split())
    if len(clean) <= limit:
        return clean
    max_body = max(1, limit - 1)
    if len(clean) > max_body and clean[max_body] == " ":
        prefix = clean[:max_body]
    else:
        window = clean[:max_body]
        space = window.rfind(" ")
        prefix = window[:space] if space > 0 else window
    prefix = prefix.rstrip(" ,;:-([{")
    if prefix.count("(") > prefix.count(")"):
        last_open = prefix.rfind("(")
        if last_open >= 24:
            prefix = prefix[:last_open].rstrip(" ,;:-")
    return prefix + "…"


def _slim_code_hint(desc: str, limit: int = 45) -> str:
    clean = " ".join(str(desc or "").strip().split())
    clean = _SLIM_CODE_HINT_REWRITES.get(clean, clean)
    if len(clean) <= limit:
        return clean
    return _snap_words(clean, limit)


def _slim_schema_node(node: Any, *, key: str | None = None) -> None:
    if not isinstance(node, dict):
        return
    if key not in ("dryRun", "confirm"):
        desc = node.get("description")
        if _needs_code_hint(node) and desc:
            node["description"] = _slim_code_hint(desc, 45)
        else:
            node.pop("description", None)
    props = node.get("properties")
    if isinstance(props, dict):
        for child_key, child in props.items():
            _slim_schema_node(child, key=child_key)
    items = node.get("items")
    if isinstance(items, dict):
        items.pop("description", None)
        _slim_schema_node(items)


def _slim_input_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Preserve exact parameter constraints, enums, and <=45-char code hints."""
    out = _deepcopy(schema)
    props = out.get("properties")
    if isinstance(props, dict):
        for key, prop in props.items():
            _slim_schema_node(prop, key=key)
    return out


def _slim_description(text: str, limit: int = 110) -> str:
    """Shorten a tool description cleanly at complete sentence or full-word boundaries."""
    clean = " ".join(text.strip().split())
    if len(clean) <= limit:
        return clean
    ends: list[int] = []
    depth = 0
    n = len(clean)
    for idx, ch in enumerate(clean):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif depth == 0 and ch == "." and idx + 1 < n and clean[idx + 1] == " ":
            if _ABBREV_DOT_RE.search(clean[:idx]):
                continue
            ends.append(idx + 1)
    fitting = [end for end in ends if end <= limit]
    if fitting:
        return clean[: fitting[-1]].rstrip()
    first_sentence = clean[: ends[0]].rstrip() if ends else clean
    if len(first_sentence) <= limit:
        return first_sentence
    return _snap_words(first_sentence, limit)


@dataclass(frozen=True)
class Tool:
    """A tool plus the MCP annotations and outputSchema describing it."""

    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    handler: Callable[..., Any]
    read_only: bool = True
    destructive: bool = False
    idempotent: bool = True
    open_world: bool = True
    requires_auth: bool = True

    @property
    def category(self) -> str:
        return _TOOL_CATEGORIES.get(self.name, "core")

    def descriptor(self, schema_mode: str = "slim") -> dict[str, Any]:
        slim = str(schema_mode or "slim").strip().lower() != "full"
        desc = _slim_description(self.description) if slim else self.description
        in_schema = _slim_input_schema(self.input_schema) if slim else self.input_schema
        out_schema = (
            _slim_output_schema(self.output_schema, read_only=self.read_only)
            if slim
            else self.output_schema
        )
        return {
            "name": self.name,
            "title": self.title,
            "description": desc,
            "inputSchema": in_schema,
            "outputSchema": out_schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": self.open_world,
            },
        }


_EMPTY: dict[str, Any] = {"type": "object", "properties": {}}


_LIMIT_PROP = {
    "type": "integer",
    "minimum": 1,
    "maximum": 5000,
    "default": 500,
    "description": "Maximum number of clients to return (default 500, max 5000)",
}


_WRITE_CONTROL_PROPS: dict[str, Any] = {
    "dryRun": {
        "type": "boolean",
        "default": True,
        "description": "Preview without applying (default true)",
    },
    "confirm": {
        "type": "string",
        "description": "Required '<tool>:<target>' when dryRun=false",
    },
}


_SUPPORTED_ITEMS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "items": {"type": "array", "items": {"type": "object"}},
        "count": {"type": "integer", "minimum": 0},
        "supported": {"type": "boolean"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["items", "count", "supported", "warnings"],
}


_DIAGNOSTIC_FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "code": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
        "detail": {"type": "string"},
    },
    "required": ["code", "severity", "detail"],
}


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


def _pick(source: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in source and source[name] not in (None, ""):
            return source[name]
    return default


def _as_int(value: Any, default: int = 0) -> int:
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_num_or_none(value: Any) -> Any | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return _as_float(value)


def as_int_or_none(val: Any) -> int | None:
    if val is None or isinstance(val, bool):
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _site(client: OmadaClient) -> SiteInfo:
    """Authenticate if needed and return the resolved site (never ``None``)."""
    client.authenticate()
    site = client.site
    if site is None:  # pragma: no cover - authenticate() guarantees a site
        raise OmadaError("site resolution failed", hint="run `omada-mcp --doctor`")
    return site


def _coerce_vlan(value: Any) -> int | None:
    """Validate a caller-supplied VLAN id, refusing the ambiguous cases."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise OmadaError("vlan must be an integer, not a boolean")
    try:
        vlan = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise OmadaError(
            f"vlan must be an integer, got {value!r}",
            hint="pass the VLAN id, e.g. 20",
        ) from exc
    if not 0 <= vlan <= 4094:
        raise OmadaError(f"vlan {vlan} is outside the valid range 0-4094")
    return vlan

