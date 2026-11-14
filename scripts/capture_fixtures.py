#!/usr/bin/env python3
"""Capture read-only controller endpoints and save an anonymized fixture bundle.

Run against an explicit isolated dotenv file (never per-user discovered config):

    python scripts/capture_fixtures.py --env-file /path/to/isolated.env -o capture.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from dataclasses import replace
from pathlib import Path
from typing import Any

_SCRIPTS_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _SCRIPTS_DIR.parent
sys.path.insert(0, str(_ROOT_DIR / "src"))
sys.path.insert(0, str(_SCRIPTS_DIR))

from anonymize_capture import anonymize_capture, verify_anonymized  # noqa: E402

from omada_mcp.client import (  # noqa: E402
    OmadaClient,
    OmadaError,
    UrllibTransport,
    build_ssl_context,
)
from omada_mcp.config import load_config  # noqa: E402
from omada_mcp.domains._common import omada_mac, try_api_result, try_paginate, unwrap_rows  # noqa: E402
from omada_mcp.domains._tool_model import _site  # noqa: E402
from omada_mcp.server import configure_streams  # noqa: E402


class CaptureTransport(UrllibTransport):
    """Enforce read-only capture safety: block all writes except login."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
        timeout: float | None = None,
    ) -> tuple[int, bytes]:
        path = urllib.parse.urlsplit(url).path
        if method.upper() != "GET" and not (
            method.upper() == "POST" and path.endswith("/api/v2/login")
        ):
            raise OmadaError("fixture capture blocked a mutating request")
        return super().request(method, url, headers, data, timeout)


def capture_controller_bundle(client: OmadaClient) -> dict[str, Any]:
    """Capture a scrubbed, read-only controller + hardware payload bundle."""
    auth = client.authenticate()
    site = _site(client)
    warnings: list[str] = []

    bundle: dict[str, Any] = {
        "captureMeta": {
            "controllerVer": auth.controller_version,
            "controllerFamily": auth.controller_family,
            "sessionCookie": auth.session_cookie,
        },
        "siteInfo": try_api_result(client, f"sites/{site.site_id}", warnings, label="site")[0],
        "devices": unwrap_rows(try_api_result(client, f"sites/{site.site_id}/devices", warnings, label="devices")[0]),
        "clients": try_paginate(client, f"sites/{site.site_id}/clients?filters.active=true", warnings, label="clients")[0],
        "insightClients": try_paginate(client, f"sites/{site.site_id}/insight/clients", warnings, label="insightClients")[0],
        "lanCollection": try_paginate(client, f"sites/{site.site_id}/setting/lan/networks", warnings, label="lanCollection")[0],
        "lanInterfaces": try_paginate(client, f"sites/{site.site_id}/setting/lan/networks/interface", warnings, label="lanInterfaces")[0],
        "wlans": try_paginate(client, f"sites/{site.site_id}/setting/wlans", warnings, label="wlans")[0],
        "gatewayAcls": try_api_result(client, f"sites/{site.site_id}/setting/firewall/acls", warnings, label="gatewayAcls")[0],
        "switchAcls": try_paginate(client, f"sites/{site.site_id}/setting/firewall/acls?type=1", warnings, label="switchAcls")[0],
        "eapAcls": try_paginate(client, f"sites/{site.site_id}/setting/firewall/acls?type=2", warnings, label="eapAcls")[0],
        "groups": try_paginate(client, f"sites/{site.site_id}/setting/profiles/groups", warnings, label="groups")[0],
        "portProfiles": try_paginate(client, f"sites/{site.site_id}/setting/lan/profiles", warnings, label="portProfiles")[0],
        "policyRoutes": try_paginate(client, f"sites/{site.site_id}/setting/transmission/policyRoutings", warnings, label="policyRoutes")[0],
        "lanDnsRules": try_paginate(client, f"sites/{site.site_id}/setting/lan/dns", warnings, label="lanDnsRules")[0],
        "topology": try_api_result(client, f"sites/{site.site_id}/topology-v2", warnings, label="topology")[0],
        "wanStatus": try_api_result(client, f"sites/{site.site_id}/setting/wanlanstatus", warnings, label="wanStatus")[0],
        "deviceDetails": {},
        "switchPorts": {},
        "apChannels": {},
        "apRfScans": {},
        "warnings": warnings,
    }

    for dev in bundle["devices"]:
        mac = str(dev.get("mac") or "")
        dtype = str(dev.get("type") or "").lower()
        if not mac:
            continue
        omac = omada_mac(mac)
        if dtype == "switch":
            bundle["deviceDetails"][mac] = try_api_result(client, f"sites/{site.site_id}/switches/{omac}", warnings, label=f"switch {mac}")[0]
            bundle["switchPorts"][mac] = try_api_result(client, f"sites/{site.site_id}/switches/{omac}/ports", warnings, label=f"ports {mac}")[0]
        elif dtype == "ap":
            bundle["deviceDetails"][mac] = try_api_result(client, f"sites/{site.site_id}/eaps/{omac}", warnings, label=f"eap {mac}")[0]
            bundle["apChannels"][mac] = try_api_result(client, f"sites/{site.site_id}/eaps/{omac}/channel-info", warnings, label=f"channels {mac}")[0]
            bundle["apRfScans"][mac] = try_api_result(client, f"sites/{site.site_id}/eaps/{omac}/rfscan", warnings, label=f"rfscan {mac}")[0]
        elif dtype == "gateway":
            bundle["deviceDetails"][mac] = try_api_result(client, f"sites/{site.site_id}/gateways/{omac}", warnings, label=f"gateway {mac}")[0]

    anonymized = anonymize_capture(bundle)
    assert isinstance(anonymized, dict)
    return anonymized


def main(argv: list[str] | None = None) -> int:
    configure_streams()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True, help="explicit isolated lab dotenv file")
    parser.add_argument("-o", "--output", type=Path, help="output JSON file (default: stdout)")
    args = parser.parse_args(argv)

    env = dict(os.environ, OMADA_ENV_FILE=args.env_file, OMADA_READ_ONLY="true", OMADA_WRITE_TOOLS="")
    config = load_config(environ=env)
    config = replace(config, min_interval=max(0.25, config.min_interval))
    transport = CaptureTransport(
        build_ssl_context(config),
        timeout=config.timeout,
        use_system_proxy=config.use_system_proxy,
    )
    client = OmadaClient(config, transport=transport, log_fn=lambda _: None)
    try:
        captured = capture_controller_bundle(client)
    finally:
        client.close()

    findings = verify_anonymized(captured, strict_private=True)
    if findings:
        for item in findings[:25]:
            print(f"FAIL: {item}", file=sys.stderr)
        return 1

    encoded = json.dumps(captured, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
