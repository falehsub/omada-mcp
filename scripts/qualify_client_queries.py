"""Qualify client query options against an explicitly selected loopback lab.

Only GET and session login are allowed by the transport. Never discovers a
developer's controller configuration. Reports contain counts, not client data.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from read_selftest import ReadOnlyTransport  # noqa: E402

from omada_mcp.client import OmadaClient, build_ssl_context  # noqa: E402
from omada_mcp.config import load_config  # noqa: E402
from omada_mcp.server import Server  # noqa: E402


def qualify(env_file: str) -> dict:
    env = {key: value for key, value in os.environ.items() if not key.startswith("OMADA_")}
    env.update(OMADA_ENV_FILE=str(Path(env_file).resolve()), OMADA_READ_ONLY="true",
               OMADA_WRITE_TOOLS="", OMADA_ALLOW_CROSS_SITE="false")
    config = load_config(environ=env)
    host = urlsplit(config.base_url).hostname or ""
    if host != "localhost" and not ipaddress.ip_address(host).is_loopback:
        raise ValueError("qualification requires a disposable loopback controller")
    config = replace(config, min_interval=max(0.25, config.min_interval))
    transport = ReadOnlyTransport(build_ssl_context(config), timeout=config.timeout,
                                  use_system_proxy=False)
    client = OmadaClient(config, transport=transport, log_fn=lambda _: None)
    checks: list[dict[str, Any]] = []
    try:
        client.authenticate()
        server = Server(config, client=client)
        for tool in ("list_clients", "list_wifi_clients", "list_wired_clients", "search_clients"):
            for mode, arguments in (
                ("legacy", {}),
                ("paged", {"pageSize": 50}),
                ("sparse-envelope", {"pageSize": 50, "fields": ["name", "ip", "wireless", "ssid"],
                                     "resultFormat": "envelope"}),
            ):
                before = client.request_count
                response = server.handle({"jsonrpc": "2.0", "id": len(checks) + 1, "method": "tools/call",
                                          "params": {"name": tool, "arguments": arguments}})
                assert response is not None
                result = response.get("result") or {}
                data = result.get("structuredContent", {})
                passed = "error" not in response and not result.get("isError", True)
                if mode == "sparse-envelope" and passed:
                    passed = len(result["content"]) == 1 and json.loads(result["content"][0]["text"]) == data
                checks.append({"tool": tool, "mode": mode, "passed": passed,
                               "count": data.get("count"), "complete": data.get("complete"),
                               "requests": client.request_count - before, "source": data.get("source")})
        return {"controllerVersion": client.auth_info.controller_version if client.auth_info else None,
                "reportedPrivilege": client.auth_info.privilege if client.auth_info else None,
                "readOnlyTransport": True, "passed": sum(row["passed"] for row in checks),
                "failed": sum(not row["passed"] for row in checks),
                "limitation": "An empty lab qualifies endpoints and envelopes, not hardware or large fleets.",
                "checks": checks}
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = qualify(args.env_file)
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return int(bool(report["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
