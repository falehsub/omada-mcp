#!/usr/bin/env python3
"""Deterministic anonymizer for Omada Controller Web API v2 HTTP captures.

Scrubs MAC addresses, IPv4/IPv6 addresses, SSIDs, serial numbers, controller/site
IDs, hostnames, emails, and auth secrets/tokens while preserving referential
consistency across endpoints in a capture bundle.

Usage::

    python scripts/anonymize_capture.py raw_capture.json -o tests/fixtures/capture.json
    python scripts/anonymize_capture.py --verify-clean tests/fixtures/capture.json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

_MAC_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
)
_IPV4_CIDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/(?:3[0-2]|[12]?\d))?\b"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_QUERY_SECRET_RE = re.compile(
    r"([?&](?:token|csrf|csrfToken|password|passwd|secret)=)([^&\s\"']+)",
    re.IGNORECASE,
)
_COOKIE_HEADER_RE = re.compile(
    r"((?:TPOMADA_SESSIONID|TPEAP_SESSIONID|CSRF-TOKEN)=)([^;\s,\"']+)",
    re.IGNORECASE,
)
_HEX32_PATH_RE = re.compile(r"(/\b[0-9a-f]{32}\b(?=/api/v2/))")

_SECRET_KEYS = frozenset({
    "password",
    "passwd",
    "pwd",
    "secret",
    "securitykey",
    "passphrase",
    "psk",
    "token",
    "csrftoken",
    "csrf",
    "sessionid",
    "cookie",
    "set-cookie",
    "authorization",
    "apikey",
    "api_key",
    "privatekey",
    "preSharedKey".lower(),
    "radiussecret",
    "acctsecret",
    "pppoepassword",
})

_OMADAC_ID_KEYS = frozenset({"omadacid", "customid", "controllerid"})
_SITE_ID_KEYS = frozenset({"site", "siteid"})
_SITE_NAME_KEYS = frozenset({"sitename"})
_SERIAL_KEYS = frozenset({"sn", "serial", "serialno", "serialnumber", "devsn"})
_SSID_KEYS = frozenset({"ssid", "wlanname", "ssids"})
_MAC_NAME_KEYS = frozenset({"mac", "apmac", "switchmac", "gwmac", "chassisid", "portid"})
_DEVICE_OR_HOST_NAME_KEYS = frozenset({
    "hostname",
    "apname",
    "switchname",
    "devicename",
    "username",
    "operator",
})

_PRESERVED_IPV4 = frozenset({"0.0.0.0", "127.0.0.1", "255.255.255.255"})


def _is_subnet_mask(ip_str: str, addr: ipaddress.IPv4Address) -> bool:
    """Return True when *addr* is a contiguous IPv4 netmask like 255.255.255.0."""
    mask_int = int(addr)
    inv = ~mask_int & 0xFFFFFFFF
    return (
        mask_int != 0
        and ((inv + 1) & inv) == 0
        and ip_str.startswith(("255.", "254.", "252.", "248.", "240.", "224.", "192.", "128."))
    )


class Anonymizer:
    """Stateful deterministic scrubber for Omada controller JSON payloads."""

    def __init__(self) -> None:
        self._macs: dict[str, str] = {}
        self._ipv4_nets: dict[str, int] = {}
        self._ipv4_public: dict[str, str] = {}
        self._ipv6s: dict[str, str] = {}
        self._omadac_ids: dict[str, str] = {}
        self._site_ids: dict[str, str] = {}
        self._site_names: dict[str, str] = {}
        self._serials: dict[str, str] = {}
        self._ssids: dict[str, str] = {}
        self._hosts: dict[str, str] = {}
        self._emails: dict[str, str] = {}

    def map_mac(self, raw: str) -> str:
        sep = ":" if ":" in raw else "-"
        canon = re.sub(r"[:-]", "", raw).upper()
        if canon not in self._macs:
            idx = len(self._macs) + 1
            hi, lo = divmod(idx, 256)
            self._macs[canon] = f"00-11-22-00-{hi:02X}-{lo:02X}"
        mapped = self._macs[canon]
        return mapped.replace("-", sep)

    def map_ipv4_or_cidr(self, raw: str) -> str:
        if "/" in raw:
            addr_part, prefix_part = raw.split("/", 1)
            mapped_ip = self._map_ipv4(addr_part)
            return f"{mapped_ip}/{prefix_part}"
        return self._map_ipv4(raw)

    def _map_ipv4(self, addr_str: str) -> str:
        if addr_str in _PRESERVED_IPV4:
            return addr_str
        try:
            addr = ipaddress.IPv4Address(addr_str)
        except ValueError:
            return addr_str
        if addr.is_multicast or _is_subnet_mask(addr_str, addr):
            return addr_str
        if addr.is_private or addr.is_link_local:
            octets = addr_str.split(".")
            net_key = ".".join(octets[:3])
            if net_key not in self._ipv4_nets:
                self._ipv4_nets[net_key] = len(self._ipv4_nets) + 1
            net_idx = self._ipv4_nets[net_key]
            third = ((net_idx - 1) % 250) + 1
            second = 16 + ((net_idx - 1) // 250)
            return f"172.{second}.{third}.{octets[3]}"
        if addr_str not in self._ipv4_public:
            idx = len(self._ipv4_public) + 10
            host = ((idx - 1) % 250) + 1
            third = 100 + ((idx - 1) // 250)
            self._ipv4_public[addr_str] = f"198.51.{third}.{host}"
        return self._ipv4_public[addr_str]

    def map_ipv6(self, raw: str) -> str:
        text = raw.strip()
        prefix = ""
        addr_str = text
        if "/" in text:
            addr_str, prefix = text.split("/", 1)
        try:
            addr = ipaddress.IPv6Address(addr_str)
        except ValueError:
            return raw
        if addr.is_unspecified or addr.is_loopback:
            return raw
        canon = addr.compressed
        if canon not in self._ipv6s:
            idx = len(self._ipv6s) + 1
            self._ipv6s[canon] = f"2001:db8::1:{idx:x}"
        mapped = self._ipv6s[canon]
        return f"{mapped}/{prefix}" if prefix else mapped

    def _map_token(self, table: dict[str, str], value: str, fmt: str) -> str:
        if not value:
            return value
        if value not in table:
            table[value] = fmt.format(len(table) + 1)
        return table[value]

    def scrub_string(self, text: str) -> str:
        if not text:
            return text
        out = _QUERY_SECRET_RE.sub(r"\1REDACTED", text)
        out = _COOKIE_HEADER_RE.sub(r"\1REDACTED", out)
        out = _HEX32_PATH_RE.sub(
            lambda m: "/" + self._map_token(self._omadac_ids, m.group(1)[1:], "{:032x}"),
            out,
        )
        out = _MAC_RE.sub(lambda m: self.map_mac(m.group(0)), out)
        out = _IPV4_CIDR_RE.sub(lambda m: self.map_ipv4_or_cidr(m.group(0)), out)
        out = _EMAIL_RE.sub(
            lambda m: self._map_token(self._emails, m.group(0), "user-{:02d}@example.invalid"),
            out,
        )
        # Scrub standalone IPv6 values.
        if ":" in out and "://" not in out and not _MAC_RE.fullmatch(out):
            candidate = out.split("%", 1)[0].strip()
            try:
                ipaddress.IPv6Address(candidate.split("/", 1)[0])
                out = self.map_ipv6(candidate)
            except ValueError:
                pass
        return out

    def anonymize(self, value: Any, *, key: str = "") -> Any:
        key_l = key.lower()
        if isinstance(value, dict):
            return {
                self.scrub_string(k) if isinstance(k, str) else k: self.anonymize(v, key=str(k))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.anonymize(item, key=key) for item in value]
        if isinstance(value, str):
            if key_l in _SECRET_KEYS:
                return "REDACTED" if value else value
            if key_l in _OMADAC_ID_KEYS:
                return self._map_token(self._omadac_ids, value, "{:032x}")
            if key_l in _SITE_ID_KEYS:
                return self._map_token(self._site_ids, value, "site{}")
            if key_l in _SITE_NAME_KEYS:
                return "Default" if value == "Default" else self._map_token(self._site_names, value, "Site-{}")
            if key_l in _SERIAL_KEYS:
                return self._map_token(self._serials, value, "SN{:010d}")
            if key_l in _SSID_KEYS:
                return self._map_token(self._ssids, value, "Lab-WiFi-{}")
            if key_l in _DEVICE_OR_HOST_NAME_KEYS:
                if _MAC_RE.fullmatch(value.strip()):
                    return self.map_mac(value.strip())
                return self._map_token(self._hosts, value, "host-{:02d}")
            if key_l == "name" and value and value != "Omada Controller" and _MAC_RE.fullmatch(value.strip()):
                return self.map_mac(value.strip())
            if key_l in _MAC_NAME_KEYS and re.fullmatch(r"[0-9A-Fa-f]{12}", value.strip()):
                return re.sub(r"[:-]", "", self.map_mac(value.strip()))
            return self.scrub_string(value)
        return value


def anonymize_capture(payload: Any) -> Any:
    """Anonymize a parsed Omada HTTP capture or fixture structure."""
    return Anonymizer().anonymize(payload)


def verify_anonymized(
    payload: Any,
    path: str = "$",
    *,
    strict_private: bool = False,
) -> list[str]:
    """Return a list of potential residual secret/PII findings in *payload*."""
    findings: list[str] = []
    if isinstance(payload, dict):
        for k, v in payload.items():
            kl = k.lower()
            child_path = f"{path}.{k}"
            if isinstance(k, str):
                findings.extend(verify_anonymized(k, f"{path}.<key:{k}>", strict_private=strict_private))
            if kl in _SECRET_KEYS and isinstance(v, str) and v and v != "REDACTED":
                findings.append(f"{child_path}: non-redacted secret key")
            findings.extend(verify_anonymized(v, child_path, strict_private=strict_private))
    elif isinstance(payload, list):
        for idx, item in enumerate(payload):
            findings.extend(verify_anonymized(item, f"{path}[{idx}]", strict_private=strict_private))
    elif isinstance(payload, str):
        for match in _EMAIL_RE.finditer(payload):
            if not match.group(0).endswith("@example.invalid"):
                findings.append(f"{path}: unmasked email {match.group(0)!r}")
        for match in _MAC_RE.finditer(payload):
            canon = re.sub(r"[:-]", "", match.group(0)).upper()
            if not canon.startswith(("001122", "AABBCC")):
                findings.append(f"{path}: non-anonymized MAC {match.group(0)!r}")
        for match in _IPV4_CIDR_RE.finditer(payload):
            ip_str = match.group(0).split("/", 1)[0]
            if ip_str in _PRESERVED_IPV4:
                continue
            try:
                addr = ipaddress.IPv4Address(ip_str)
            except ValueError:
                continue
            if addr.is_multicast or _is_subnet_mask(ip_str, addr):
                continue
            if addr.is_private and not strict_private:
                continue
            if not (
                ip_str.startswith(("172.16.", "192.168.10.", "192.168.20.", "198.51.100.", "198.18.", "203.0.113."))
            ):
                findings.append(f"{path}: non-lab IPv4 {ip_str!r}")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="input JSON capture file")
    parser.add_argument("-o", "--output", type=Path, help="output JSON path (default: stdout)")
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="overwrite input file with anonymized JSON",
    )
    parser.add_argument(
        "--verify-clean",
        action="store_true",
        help="verify input file contains no residual secrets, real MACs, or non-lab IPs",
    )
    parser.add_argument(
        "--strict-private",
        action="store_true",
        help="also flag non-lab RFC1918 private IPs during --verify-clean",
    )
    args = parser.parse_args(argv)

    raw = json.loads(args.input.read_text(encoding="utf-8"))
    if args.verify_clean:
        findings = verify_anonymized(raw, strict_private=args.strict_private)
        if findings:
            for item in findings[:25]:
                print(f"FAIL: {item}", file=sys.stderr)
            return 1
        print(f"OK: {args.input} passed anonymization checks")
        return 0

    cleaned = anonymize_capture(raw)
    findings = verify_anonymized(cleaned, strict_private=True)
    if findings:
        for item in findings[:25]:
            print(f"WARN: {item}", file=sys.stderr)
    encoded = json.dumps(cleaned, indent=2, ensure_ascii=False) + "\n"
    if args.in_place:
        args.input.write_text(encoded, encoding="utf-8")
    elif args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
