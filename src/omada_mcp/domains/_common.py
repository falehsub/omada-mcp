"""Shared read-only constants, MAC/number coercion, redaction, and API wrappers."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from ..client import OmadaClient, OmadaError, OmadaSessionExpiredError, SiteInfo, redact_secrets

_OPTIONAL_UNAVAILABLE_CODES = frozenset({
    -1, -1001, -1005, -1007, -1600, -30129, -30130, -33004, -33005, -40001, -41011,
})

_PEM_SECRET_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)

LINK_SPEED_LABELS: dict[int, str] = {
    0: "auto",
    1: "10M",
    2: "100M",
    3: "1000M",
    4: "10000M",
    5: "2500M",
    6: "5000M",
    7: "25000M",
}

LINK_SPEED_MBPS: dict[int, int] = {
    0: 0,
    1: 10,
    2: 100,
    3: 1000,
    4: 10000,
    5: 2500,
    6: 5000,
    7: 25000,
}

DUPLEX_LABELS: dict[int, str] = {
    0: "auto",
    1: "half",
    2: "full",
}

CHANNEL_WIDTH_LABELS: dict[str, str] = {
    "2": "20MHz",
    "3": "40MHz",
    "4": "AUTO",
    "5": "80MHz",
    "6": "AUTO",
    "7": "160MHz",
    "8": "AUTO",
    "9": "240MHz",
    "10": "320MHz",
}

CHANNEL_WIDTH_AUTO_BY_BAND: dict[str, str] = {
    "2g": "4",
    "5g": "6",
    "5g2": "6",
    "6g": "8",
}

CHANNEL_WIDTH_TO_CODE: dict[str, dict[str, str]] = {
    "2g": {"20": "2", "20mhz": "2", "40": "3", "40mhz": "3", "auto": "4"},
    "5g": {"20": "2", "20mhz": "2", "40": "3", "40mhz": "3", "80": "5", "80mhz": "5",
           "160": "7", "160mhz": "7", "auto": "6"},
    "5g2": {"20": "2", "20mhz": "2", "40": "3", "40mhz": "3", "80": "5", "80mhz": "5",
            "160": "7", "160mhz": "7", "auto": "6"},
    "6g": {"20": "2", "20mhz": "2", "40": "3", "40mhz": "3", "80": "5", "80mhz": "5",
           "160": "7", "160mhz": "7", "240": "9", "240mhz": "9", "320": "10", "320mhz": "10",
           "auto": "8"},
}

TX_POWER_LEVEL_LABELS: dict[int, str] = {
    0: "low",
    1: "medium",
    2: "high",
    3: "custom",
    4: "auto",
}

TX_POWER_LEVEL_TO_CODE: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "med": 1,
    "high": 2,
    "custom": 3,
    "auto": 4,
}

PROFILE_TYPE_LABELS: dict[int, str] = {
    0: "all",
    1: "disable",
    2: "custom",
    3: "lag",
}

ACL_TYPE_MAP: dict[str, int] = {
    "gateway": 0,
    "switch": 1,
    "eap": 2,
}

ACL_TYPE_LABELS: dict[int, str] = {
    0: "gateway",
    1: "switch",
    2: "eap",
}


def normalize_mac(value: str) -> str:
    """Normalise ``AABBCCDDEEFF`` / ``AA-BB-CC-DD-EE-FF`` / ``aa:bb:..`` to colons."""
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).lower()
    if len(cleaned) == 12 and all(ch in "0123456789abcdef" for ch in cleaned):
        return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    return str(value or "").strip().lower()


def omada_mac(value: str) -> str:
    """Format a 12-hex MAC address as uppercase hyphen-delimited ``AA-BB-CC-DD-EE-FF``."""
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).upper()
    if len(cleaned) == 12 and all(ch in "0123456789ABCDEF" for ch in cleaned):
        return "-".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    return str(value or "").strip()


def as_int(value: Any, default: int = 0) -> int:
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: float | None = None) -> float | None:
    if value is None or isinstance(value, bool):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class PaginatedList(list[dict[str, Any]]):
    """``list`` subclass carrying explicit pagination and truncation metadata."""

    def __init__(
        self,
        items: Any = (),
        *,
        truncated: bool = False,
        total_rows: int | None = None,
        pages_fetched: int | None = None,
        max_pages: int | None = None,
        limit: int | None = None,
        truncation_reason: str | None = None,
    ) -> None:
        super().__init__(items)
        meta: dict[str, Any] = {
            "truncated": bool(truncated),
        }
        if total_rows is not None:
            meta["totalRows"] = int(total_rows)
        if pages_fetched is not None:
            meta["pagesFetched"] = int(pages_fetched)
        if max_pages is not None:
            meta["maxPages"] = int(max_pages)
        if limit:
            meta["limit"] = int(limit)
        if truncation_reason and truncated:
            meta["truncationReason"] = truncation_reason
        self.pagination: dict[str, Any] = meta

    @property
    def truncated(self) -> bool:
        return bool(self.pagination.get("truncated", False))


def as_mapping(value: Any) -> Mapping[str, Any]:
    """Return ``value`` if it is a mapping, else an empty dict."""
    return value if isinstance(value, Mapping) else {}


def deep_redact(value: Any) -> Any:
    """Recursively mask secret fields and embedded private-key PEM blocks."""
    cleaned = redact_secrets(value)
    if isinstance(cleaned, str):
        if _PEM_SECRET_RE.search(cleaned):
            return _PEM_SECRET_RE.sub("***REDACTED***", cleaned)
        return cleaned
    if isinstance(cleaned, list):
        return [deep_redact(item) for item in cleaned]
    if isinstance(cleaned, dict):
        out: dict[str, Any] = {}
        for k, v in cleaned.items():
            kl = str(k).lower()
            if any(tok in kl for tok in ("privatekey", "preshared", "passphrase", "secret", "password", "community")) and v not in (None, "", False, True):
                out[k] = "***REDACTED***"
                continue
            out[k] = deep_redact(v)
        return out
    return cleaned


_NON_PUBLIC_V4_NETS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def mask_ipv4_middle(ip: str) -> str:
    """Mask host octets of a non-RFC1918 WAN IP address while preserving network hint."""
    raw = str(ip or "").strip()
    if not raw or raw in ("0.0.0.0", "-"):
        return raw
    try:
        addr = ipaddress.IPv4Address(raw)
    except ipaddress.AddressValueError:
        if ":" in raw:
            parts = raw.split(":")
            return ":".join(parts[:2] + ["***"]) if len(parts) > 2 else raw
        return raw
    if any(addr in net for net in _NON_PUBLIC_V4_NETS):
        return raw
    octets = raw.split(".")
    return f"{octets[0]}.{octets[1]}.***.***"


def width_flag_to_widths(width_flag: int | None) -> list[str]:
    """Decode Omada channelInfo ``widthFlag`` bitmask into supported channel widths."""
    if width_flag is None or isinstance(width_flag, bool):
        return []
    try:
        wf = int(width_flag)
    except (TypeError, ValueError):
        return []
    widths: list[str] = []
    if (wf & 65536) != 0:
        widths.append("20MHz")
    if (wf & 393216) != 0:
        widths.append("40MHz")
    if (wf & 8388864) == 8388864:
        widths.append("80MHz")
    if (wf & 16777472) == 16777472:
        widths.append("160MHz")
    if (wf & 67109120) == 67109120:
        widths.append("240MHz")
    if (wf & 33554688) == 33554688:
        widths.append("320MHz")
    return widths


def try_api_result(
    client: OmadaClient,
    endpoint: str,
    warnings: list[str],
    *,
    label: str = "",
) -> tuple[Any | None, bool]:
    """Fetch an optional GET endpoint, converting feature/hardware absences to warnings."""
    tag = label or endpoint
    try:
        return client.api_result(endpoint), True
    except OmadaSessionExpiredError:
        raise
    except OmadaError as exc:
        if exc.code is None or exc.code in _OPTIONAL_UNAVAILABLE_CODES:
            warnings.append(f"{tag}: unavailable ({exc.code}: {exc})")
            return None, False
        raise


def try_paginate(
    client: OmadaClient,
    endpoint: str,
    warnings: list[str],
    *,
    label: str = "",
    page_size: int = 100,
    max_pages: int = 20,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, bool]:
    """Paginate an optional GET endpoint gracefully on missing hardware/features."""
    tag = label or endpoint
    try:
        rows, meta = client.paginate(endpoint, page_size=page_size, max_pages=max_pages)
        return rows, meta, True
    except OmadaSessionExpiredError:
        raise
    except OmadaError as exc:
        if exc.code is None or exc.code in _OPTIONAL_UNAVAILABLE_CODES:
            warnings.append(f"{tag}: unavailable ({exc.code}: {exc})")
            return [], None, False
        raise


def is_device_online(dev: Mapping[str, Any]) -> bool:
    status_cat = dev.get("statusCategory")
    status_val = dev.get("status")
    return (status_cat == 1) or (status_cat is None and status_val in (1, 14))


def unwrap_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [dict(r) for r in payload if isinstance(r, Mapping)]
    if isinstance(payload, Mapping):
        data = payload.get("data")
        if isinstance(data, list):
            return [dict(r) for r in data if isinstance(r, Mapping)]
    return []


def resolve_raw_device(
    client: OmadaClient,
    site: SiteInfo,
    mac_or_query: str,
    *,
    expected_type: str | None = None,
) -> dict[str, Any]:
    """Resolve a raw device dict from ``sites/{site}/devices`` by MAC or exact name."""
    raw = client.api_result(f"sites/{site.site_id}/devices")
    devices = unwrap_rows(raw)
    wanted_mac = normalize_mac(mac_or_query)
    wanted_name = str(mac_or_query or "").strip().lower()
    matched: dict[str, Any] | None = None
    for dev in devices:
        if normalize_mac(str(dev.get("mac") or "")) == wanted_mac or (
            wanted_name and str(dev.get("name") or "").strip().lower() == wanted_name
        ):
            matched = dev
            break
    if matched is None:
        raise OmadaError(
            f"no device matches {mac_or_query!r}",
            hint="list_devices first; accepts a device MAC address or exact device name",
        )
    if expected_type and str(matched.get("type") or "").lower() != expected_type.lower():
        raise OmadaError(
            f"device {matched.get('name') or matched.get('mac')} is type "
            f"{matched.get('type')!r}, expected {expected_type!r}",
            hint=f"pass the MAC or name of an adopted {expected_type}",
        )
    return matched
