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
import os
import sys
from typing import List, Optional

from . import __version__
from .config import ConfigError, load_config, parse_bool, parse_write_tools
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
        "--json", action="store_true",
        help="with --doctor: emit machine-readable JSON output",
    )
    parser.add_argument(
        "--show-config", action="store_true",
        help="print the resolved configuration with the password masked, then exit",
    )
    parser.add_argument(
        "--list-tools", action="store_true",
        help="print active tool descriptors (name, schema, MCP annotations) as JSON, then exit",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="with --list-tools, include all write tools regardless of OMADA_WRITE_TOOLS",
    )
    return parser


def _configure_console() -> None:
    """UTF-8 stdout/stderr so a non-UTF-8 Windows console cannot raise.

    ``--doctor`` prints site names and paths, ``--list-tools`` prints JSON; both
    can contain characters outside the console code page.
    """
    import sys

    from .server import configure_streams

    configure_streams(stdin=None, stdout=sys.stdout, stderr=sys.stderr)


def main(argv: Optional[List[str]] = None) -> int:
    _configure_console()
    args = build_parser().parse_args(argv)

    if args.doctor:
        return run_doctor(json_output=args.json)

    if args.list_tools:
        if args.all:
            descriptors = tool_descriptors(include_all=True)
        else:
            try:
                read_only = parse_bool(
                    os.environ.get("OMADA_READ_ONLY"), "OMADA_READ_ONLY", False
                )
                write_tools = parse_write_tools(os.environ.get("OMADA_WRITE_TOOLS"))
            except ConfigError as exc:
                print(f"omada-mcp: configuration error: {exc}", file=sys.stderr)
                return 2
            descriptors = tool_descriptors(
                write_tools=() if read_only else write_tools
            )
        print(json.dumps({"tools": descriptors}, indent=2, ensure_ascii=False))
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
