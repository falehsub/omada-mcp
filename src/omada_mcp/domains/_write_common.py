"""Write domain module: _write_common."""

from __future__ import annotations

import copy
import ipaddress
import json
from collections.abc import Collection, Mapping, Sequence
from typing import Any

from ..client import OmadaClient, OmadaError, SiteInfo, redact_secrets
from ._common import deep_redact

MAX_IP_GROUP_ENTRIES = 16


CLIENT_VOLATILE_KEYS = frozenset({
    "trafficDown",
    "trafficUp",
    "downPacket",
    "upPacket",
    "uptime",
    "lastSeen",
    "activity",
    "uploadActivity",
    "rxRate",
    "txRate",
    "rssi",
    "snr",
    "signalLevel",
    "signalRank",
    "dpiStat",
    "authInfo",
    "channel",
    "active",
    "rateLimit",
    "authStatus",
})


WRITE_ENVELOPE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "applied": {"type": "boolean"},
        "dryRun": {"type": "boolean"},
        "verified": {"type": "boolean"},
        "target": {"type": "string"},
        "confirmToken": {"type": "string"},
        "before": {},
        "after": {},
        "diff": {"type": "object"},
        "snapshot": {"type": ["string", "null"]},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "rollback": {"type": ["object", "null"]},
        "steps": {"type": "array", "items": {"type": "object"}},
    },
    "required": [
        "applied",
        "dryRun",
        "verified",
        "target",
        "before",
        "after",
        "diff",
        "snapshot",
        "warnings",
        "rollback",
    ],
}


_SOURCE_DEST_TYPES: dict[str, int] = {
    "0": 0,
    "network": 0,
    "lan": 0,
    "1": 1,
    "ip_group": 1,
    "ipgroup": 1,
    "group": 1,
    "2": 2,
    "port_group": 2,
    "portgroup": 2,
}


_ACL_DISPATCH_NOTES = (
    "aclDisable on the controller list envelope is not a reliable enforcement indicator; "
    "verify enforcement behaviourally on affected clients after re-association"
)


_DEV_ENDPOINT_PREFIX: dict[str, str] = {
    "ap": "eaps",
    "eap": "eaps",
    "switch": "switches",
    "gateway": "gateways",
}


_LED_MODES: dict[str, int] = {
    "0": 0,
    "off": 0,
    "false": 0,
    "1": 1,
    "on": 1,
    "true": 1,
    "2": 2,
    "use_site": 2,
    "site": 2,
}


_SSID_BAND_BITS: dict[str, int] = {
    "2g": 1,
    "2.4g": 1,
    "2.4ghz": 1,
    "5g": 2,
    "5ghz": 2,
    "6g": 4,
    "6ghz": 4,
}


_SSID_SERVER_ONLY_KEYS = frozenset({
    "id",
    "idInt",
    "site",
    "wlanId",
    "resource",
    "index",
    "portalEnable",
})


_LINK_SPEED_TO_CODE: dict[str, int] = {
    "auto": 0,
    "0": 0,
    "10m": 1,
    "10mbps": 1,
    "10": 1,
    "1": 1,
    "100m": 2,
    "100mbps": 2,
    "100": 2,
    "2": 2,
    "1g": 3,
    "1000m": 3,
    "1gbps": 3,
    "3": 3,
    "2.5g": 4,
    "2500m": 4,
    "4": 4,
    "10g": 5,
    "10000m": 5,
    "5": 5,
    "5g": 6,
    "6": 6,
    "25g": 7,
    "7": 7,
    "100g": 8,
    "8": 8,
}


_DUPLEX_TO_CODE: dict[str, int] = {
    "auto": 0,
    "0": 0,
    "half": 1,
    "1": 1,
    "full": 2,
    "2": 2,
}


_PORT_PROFILE_POE_TO_CODE: dict[str, int] = {
    "off": 0,
    "disable": 0,
    "disabled": 0,
    "0": 0,
    "on": 1,
    "enable": 1,
    "enabled": 1,
    "1": 1,
    "keep": 2,
    "keep_settings": 2,
    "2": 2,
}


_SWITCH_ACL_BINDING_MAP: dict[str, int] = {
    "all_ports": 0,
    "0": 0,
    "custom_ports": 1,
    "1": 1,
    "all_vlans": 2,
    "all_switches": 2,
    "2": 2,
    "custom_vlans": 3,
    "custom_switches": 3,
    "vlan": 3,
    "3": 3,
}


_LAN_DNS_TYPE_MAP: dict[str, int] = {
    "ip": 0,
    "a": 0,
    "aaaa": 0,
    "0": 0,
    "cname": 1,
    "1": 1,
    "forward": 2,
    "fwd": 2,
    "2": 2,
}


_BAND_TO_RADIO_ID: dict[str, int] = {
    "2g": 0,
    "5g": 1,
    "5g1": 1,
    "5g2": 2,
    "6g": 3,
}


_NON_REVERSIBLE_SNAPSHOT_TOOLS = frozenset({
    "reboot_device",
    "reconnect_client",
    "cycle_poe_port",
    "start_rf_scan",
})


def _normalize_mac(value: str) -> str:
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).lower()
    if len(cleaned) == 12 and all(ch in "0123456789abcdef" for ch in cleaned):
        return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    return str(value or "").strip().lower()


def _site(client: OmadaClient) -> SiteInfo:
    client.authenticate()
    site = client.site
    if site is None:  # pragma: no cover - authenticate() guarantees a site
        raise OmadaError("site resolution failed", hint="run `omada-mcp --doctor`")
    return site


def _unwrap_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        rows = payload.get("data")
        return list(rows) if isinstance(rows, list) else []
    if isinstance(payload, list):
        return list(payload)
    return []


def _require_confirm(tool_name: str, target_id: str, dry_run: bool, confirm: str | None) -> str:
    expected = f"{tool_name}:{target_id}"
    if dry_run:
        return expected
    supplied = str(confirm or "").strip()
    if supplied != expected:
        raise OmadaError(
            f"confirmation mismatch for {tool_name}: dryRun=false requires confirm='{tool_name}:<target-id>'",
            hint="run this tool with dryRun=true first to inspect the diff and obtain confirmToken",
        )
    return expected


def _dry_run_result(
    *,
    tool_name: str,
    target_id: str,
    before: Any,
    after: Any,
    diff: dict[str, Any],
    warnings: list[str],
    rollback: dict[str, Any] | None,
    steps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "applied": False,
        "dryRun": True,
        "verified": False,
        "target": target_id,
        "confirmToken": f"{tool_name}:{target_id}",
        "before": deep_redact(before),
        "after": deep_redact(after),
        "diff": deep_redact(diff),
        "snapshot": None,
        "warnings": list(warnings),
        "rollback": deep_redact(rollback) if rollback is not None else None,
    }
    if steps is not None:
        out["steps"] = deep_redact(steps)
    return out


def _committed_result(
    *,
    tool_name: str,
    target_id: str,
    before: Any,
    after: Any,
    diff: dict[str, Any],
    snapshot: str | None,
    warnings: list[str],
    rollback: dict[str, Any] | None,
    steps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "applied": True,
        "dryRun": False,
        "verified": True,
        "target": target_id,
        "confirmToken": f"{tool_name}:{target_id}",
        "before": deep_redact(before),
        "after": deep_redact(after),
        "diff": deep_redact(diff),
        "snapshot": snapshot,
        "warnings": list(warnings),
        "rollback": deep_redact(rollback) if rollback is not None else None,
    }
    if steps is not None:
        out["steps"] = deep_redact(steps)
    return out


def _diff_mappings(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    ignore_keys: Collection[str] = (),
    prefix: str = "",
) -> list[str]:
    """Return sorted dotted paths where ``before`` and ``after`` differ unexpectedly."""
    ignored = set(ignore_keys)
    drifts: list[str] = []
    for key in sorted(set(before.keys()) | set(after.keys())):
        dotted = f"{prefix}.{key}" if prefix else str(key)
        if dotted in ignored:
            continue
        if key not in before or key not in after:
            drifts.append(dotted)
            continue
        bv = before[key]
        av = after[key]
        if isinstance(bv, Mapping) and isinstance(av, Mapping):
            drifts.extend(_diff_mappings(bv, av, ignore_keys=ignored, prefix=dotted))
        elif bv != av:
            drifts.append(dotted)
    return drifts


def json_summary(obj: Any) -> str:

    return json.dumps(obj, ensure_ascii=False, default=str)


def _resolve_by_id_or_name(
    items: Sequence[Mapping[str, Any]],
    needle: str,
    *,
    label: str,
    id_key: str = "id",
    name_key: str = "name",
    extra_keys: Sequence[str] = (),
) -> dict[str, Any]:
    raw = str(needle or "").strip()
    if not raw:
        raise OmadaError(f"{label} identifier must be non-empty")
    lower = raw.lower()
    exact_id = [dict(item) for item in items if str(item.get(id_key, "")).strip().lower() == lower]
    if len(exact_id) == 1:
        return exact_id[0]
    matches: list[dict[str, Any]] = []
    keys = (name_key,) + tuple(extra_keys)
    for item in items:
        for key in keys:
            val = str(item.get(key, "")).strip()
            if val and val.lower() == lower:
                matches.append(dict(item))
                break
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        ids = ", ".join(str(m.get(id_key) or m.get(name_key) or "?") for m in matches)
        raise OmadaError(f"{label} {needle!r} matched multiple entries ({ids}); specify exact id")
    raise OmadaError(f"no {label} matches {needle!r}")


def _parse_ipv4(value: str, label: str = "IP address") -> ipaddress.IPv4Address:
    text = str(value or "").strip()
    try:
        return ipaddress.IPv4Address(text)
    except ValueError as exc:
        raise OmadaError(f"invalid IPv4 {label} {value!r}: {exc}") from None


def _validate_vlan_id(vlan: Any) -> int:
    if isinstance(vlan, bool):
        raise OmadaError("vlan must be an integer between 1 and 4094")
    try:
        vid = int(vlan)
    except (TypeError, ValueError):
        raise OmadaError(f"invalid VLAN ID {vlan!r}; expected integer 1..4094") from None
    if not 1 <= vid <= 4094:
        raise OmadaError(f"VLAN ID {vid} out of range (expected 1..4094)")
    return vid


def _redact_ssid(ssid: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(ssid, Mapping):
        return None
    cleaned = redact_secrets(dict(ssid))
    psk = ssid.get("pskSetting")
    cleaned["hasPresharedKey"] = bool(
        ssid.get("securityKey")
        or (isinstance(psk, Mapping) and psk.get("securityKey"))
        or ssid.get("ppskSetting")
    )
    return cleaned


def _port_range_valid(spec: str, label: str = "port") -> str:
    text = str(spec or "").strip()
    if not text:
        raise OmadaError(f"{label} must be non-empty")
    for part in text.split(","):
        seg = part.strip()
        if not seg:
            raise OmadaError(f"{label} {spec!r} has an empty segment")
        if "-" in seg:
            bounds = seg.split("-", 1)
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
            except ValueError:
                raise OmadaError(f"invalid port range {seg!r} in {label}") from None
            if not (1 <= lo <= hi <= 65535):
                raise OmadaError(f"port range {seg!r} out of valid bounds 1..65535")
        else:
            try:
                num = int(seg)
            except ValueError:
                raise OmadaError(f"invalid port number {seg!r} in {label}") from None
            if not 1 <= num <= 65535:
                raise OmadaError(f"port {num} out of valid bounds 1..65535")
    return text


def _delete_entity(
    client: OmadaClient,
    *,
    tool_name: str,
    target_id: str,
    endpoint: str,
    before: Any,
    snapshot_payload: Any,
    fetch_all: Any,
    match_fn: Any,
    rollback: dict[str, Any] | None,
    warnings: list[str] | None,
    dry_run: bool,
    confirm: str | None,
    label: str,
) -> dict[str, Any]:
    _require_confirm(tool_name, target_id, dry_run, confirm)
    diff = {label: {"before": before, "after": None}}
    warn_list = list(warnings or [])
    if dry_run:
        return _dry_run_result(
            tool_name=tool_name,
            target_id=target_id,
            before=before,
            after=None,
            diff=diff,
            warnings=warn_list,
            rollback=rollback,
        )

    def _read_back() -> list[dict[str, Any]]:
        return list(fetch_all())

    def _verify(_before: Any, after_rows: Any) -> tuple[bool, str | None]:
        if not isinstance(after_rows, list):
            return False, f"{label} read-back did not return a list"
        still_there = next((r for r in after_rows if match_fn(r)), None)
        if still_there is not None:
            return False, f"{label} {target_id!r} still present after DELETE"
        return True, None

    def _reauth_prepare() -> tuple[bool, dict[str, Any] | None, Any]:
        rows_now = _read_back()
        gone = next((r for r in rows_now if match_fn(r)), None) is None
        return gone, None, None

    write_res = client.write(
        endpoint,
        method="DELETE",
        tool_name=tool_name,
        target=target_id,
        before=before,
        snapshot_payload=snapshot_payload,
        read_back=_read_back,
        verify_fn=_verify,
        reauth_prepare=_reauth_prepare,
        fields_changed=["deleted"],
    )
    return _committed_result(
        tool_name=tool_name,
        target_id=target_id,
        before=write_res["before"],
        after=None,
        diff=diff,
        snapshot=write_res["snapshot"],
        warnings=warn_list,
        rollback=rollback,
    )


def _match_fields(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> tuple[bool, str | None]:
    for key, exp_val in expected.items():
        if key not in actual:
            return False, f"field {key!r} missing on read-back"
        act_val = actual[key]
        if isinstance(exp_val, Mapping) and isinstance(act_val, Mapping):
            ok, reason = _match_fields(act_val, exp_val)
            if not ok:
                return False, f"{key}.{reason}"
        elif isinstance(exp_val, bool):
            if bool(act_val) != exp_val:
                return False, f"field {key!r} expected {exp_val!r}, got {act_val!r}"
        elif act_val != exp_val:
            return False, f"field {key!r} expected {exp_val!r}, got {act_val!r}"
    return True, None


def _parse_code_map(value: Any, mapping: Mapping[str, int], *, label: str) -> int:
    if isinstance(value, bool):
        raise OmadaError(f"invalid {label}: {value!r}")
    if isinstance(value, int) and str(value) in mapping:
        return mapping[str(value)]
    key = str(value or "").strip().lower()
    if key in mapping:
        return mapping[key]
    raise OmadaError(f"invalid {label}: {value!r}", hint=f"valid values: {', '.join(sorted(k for k in mapping if not k.isdigit()))}")


def _field_diff(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    keys: Sequence[str],
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for k in keys:
        bv = before.get(k)
        av = after.get(k)
        if bv != av:
            out[str(k)] = {"before": copy.deepcopy(bv), "after": copy.deepcopy(av)}
    return out

