"""Console entry point: ``omada-mcp``.

Usage::

    omada-mcp                 # MCP server on stdio (what MCP hosts run)
    omada-mcp --doctor        # ordered self-test with fix hints
    omada-mcp --show-config   # resolved config, password masked
    omada-mcp --list-tools    # tool names + annotations as JSON (no network)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .config import ConfigError, load_config
from .doctor import run_doctor
from .server import Server
from .tools import tool_descriptors

__all__ = ["main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="omada-mcp",
        description=("MCP server for TP-Link Omada SDN controllers (Web API v2, "
                     "read-only tools, zero dependencies)"),
    )
    parser.add_argument("--version", action="version", version=f"omada-mcp {__version__}")
    parser.add_argument(
        "--doctor", action="store_true",
        help="self-test: dotenv, TLS/CA, login, controller version, site discovery, one read call",
    )
    parser.add_argument(
        "--show-config", action="store_true",
        help="print the resolved configuration with the password masked, then exit",
    )
    parser.add_argument(
        "--list-tools", action="store_true",
        help="print tool descriptors (name, schema, MCP annotations) as JSON, then exit",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.doctor:
        return run_doctor()

    if args.list_tools:
        print(json.dumps({"tools": tool_descriptors()}, indent=2, ensure_ascii=False))
        return 0

    if args.show_config:
        try:
            config = load_config()
        except ConfigError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(config.masked(), indent=2, ensure_ascii=False))
        return 0

    try:
        config = load_config()
    except ConfigError as exc:
        print(f"omada-mcp: {exc}", file=sys.stderr)
        print("Run `omada-mcp --doctor` for a guided check.", file=sys.stderr)
        return 2

    return Server(config).serve()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
