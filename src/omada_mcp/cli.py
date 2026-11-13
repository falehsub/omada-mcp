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
from .client import OmadaError
from .config import (
    ConfigError,
    load_config,
    parse_bool,
    parse_schema_mode,
    parse_tool_categories,
    parse_write_tools,
)
from .doctor import run_doctor
from .monitor import export_metrics_once, run_watch, serve_metrics_http
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
    parser.add_argument(
        "--compact", action="store_true",
        help="with --list-tools, emit single-line compact JSON instead of indented JSON",
    )
    parser.add_argument(
        "--watch", action="store_true",
        help="poll controller read-only using one persistent session and stream JSON diffs",
    )
    parser.add_argument(
        "--export-metrics", action="store_true",
        help="emit Prometheus text metrics once (or serve HTTP with --metrics-port > 0)",
    )
    parser.add_argument(
        "--interval", type=float, default=30.0,
        help="polling interval in seconds for --watch (clamped >= 0.8s, default: 30)",
    )
    parser.add_argument(
        "--iterations", type=int, default=0,
        help="with --watch, stop after N polls (0 runs until interrupted)",
    )
    parser.add_argument(
        "--metrics-port", type=int, default=0,
        help="with --export-metrics, listen on TCP port for /metrics and /healthz",
    )
    parser.add_argument(
        "--metrics-host", type=str, default="127.0.0.1",
        help="bind host when --metrics-port > 0 (default: 127.0.0.1)",
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
        try:
            schema_mode = parse_schema_mode(os.environ.get("OMADA_SCHEMA_MODE"))
            categories = parse_tool_categories(os.environ.get("OMADA_TOOL_CATEGORIES"))
        except ConfigError as exc:
            print(f"omada-mcp: configuration error: {exc}", file=sys.stderr)
            return 2
        if args.all:
            descriptors = tool_descriptors(
                include_all=True,
                schema_mode=schema_mode,
                categories=categories,
            )
        else:
            try:
                read_only = parse_bool(
                    os.environ.get("OMADA_READ_ONLY"), "OMADA_READ_ONLY", True
                )
                write_tools = parse_write_tools(os.environ.get("OMADA_WRITE_TOOLS"))
            except ConfigError as exc:
                print(f"omada-mcp: configuration error: {exc}", file=sys.stderr)
                return 2
            descriptors = tool_descriptors(
                write_tools=() if read_only else write_tools,
                schema_mode=schema_mode,
                categories=categories,
            )
        if args.compact:
            print(json.dumps({"tools": descriptors}, separators=(",", ":"), ensure_ascii=False))
        else:
            print(json.dumps({"tools": descriptors}, indent=2, ensure_ascii=False))
        return 0

    if args.watch and args.export_metrics:
        print("omada-mcp: --watch and --export-metrics are mutually exclusive", file=sys.stderr)
        return 2
    if args.interval <= 0:
        print("omada-mcp: --interval must be positive", file=sys.stderr)
        return 2
    if args.iterations < 0:
        print("omada-mcp: --iterations must be >= 0", file=sys.stderr)
        return 2
    if args.metrics_port < 0 or args.metrics_port > 65535:
        print("omada-mcp: --metrics-port must be between 0 and 65535", file=sys.stderr)
        return 2
    if args.metrics_port > 0 and not args.export_metrics:
        print("omada-mcp: --metrics-port requires --export-metrics", file=sys.stderr)
        return 2

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

    if args.watch:
        try:
            return run_watch(config, interval=args.interval, iterations=args.iterations)
        except KeyboardInterrupt:
            return 0
        except OmadaError as exc:
            print(f"omada-mcp watch error: {exc}", file=sys.stderr)
            return 1

    if args.export_metrics:
        try:
            if args.metrics_port > 0:
                httpd = serve_metrics_http(
                    config, host=args.metrics_host, port=args.metrics_port,
                )
                print(
                    f"omada-mcp metrics listening on http://{args.metrics_host}:{httpd.server_port}/metrics",
                    file=sys.stderr,
                    flush=True,
                )
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    return 0
                finally:
                    httpd.server_close()
                return 0
            return export_metrics_once(config)
        except KeyboardInterrupt:
            return 0
        except OmadaError as exc:
            print(f"omada-mcp metrics error: {exc}", file=sys.stderr)
            return 1

    return Server(config).serve()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
