#!/usr/bin/env python3
"""Exercise client tools through an installed MCP SDK against a loopback fixture.

Run from the repository root with the optional developer environment, for example:
``.venv-dev/Scripts/python scripts/check_client_interop.py``.
The report is a local protocol/schema check, not an actual model-host or billing test.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import importlib.metadata
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TESTS = ROOT / "tests"
sys.path[:0] = [str(SRC), str(TESTS)]

from mock_controller import (  # type: ignore[import-not-found]  # noqa: E402
    MOCK_SITE_ID,
    MockController,
    MockControllerHTTPServer,
)

PROTOCOL_VERSION = "2025-06-18"


class InteropFailure(RuntimeError):
    """A named interoperability assertion failed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InteropFailure(message)


def _result_payload(result: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    _require(not result.is_error, "list_clients returned an MCP tool error")
    structured = result.structured_content
    _require(isinstance(structured, dict), "list_clients omitted structuredContent")
    content = result.content
    text_value = getattr(content[0], "text", None) if content else None
    if not isinstance(text_value, str):
        raise InteropFailure("list_clients omitted its text representation")
    try:
        parsed = json.loads(text_value)
    except (TypeError, ValueError) as exc:
        raise InteropFailure("list_clients text was not JSON") from exc
    _require(isinstance(parsed, list), "legacy client text was not an array")
    items = structured.get("items")
    _require(isinstance(items, list), "legacy structuredContent omitted items")
    _require(parsed == items, "legacy text array differed from structuredContent.items")
    return structured, items


def _child_environment(base_url: str, schema_mode: str, isolated_home: Path,
                       empty_env_file: Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in tuple(env):
        if key.upper().startswith("OMADA_"):
            env.pop(key, None)
    env.update({
        "OMADA_BASE_URL": base_url,
        "OMADA_USERNAME": "admin-writer",
        "OMADA_PASSWORD": "pw",
        "OMADA_SITE_ID": MOCK_SITE_ID,
        "OMADA_READ_ONLY": "true",
        "OMADA_SCHEMA_MODE": schema_mode,
        "OMADA_TOOL_CATALOG": "full",
        "OMADA_WRITE_TOOLS": "",
        "OMADA_MIN_INTERVAL_SECONDS": "0",
        "OMADA_TIMEOUT_SECONDS": "5",
        "OMADA_ENV_FILE": str(empty_env_file),
        "OMADA_SNAPSHOT_DIR": str(isolated_home / "snapshots"),
        "HOME": str(isolated_home),
        "USERPROFILE": str(isolated_home),
        "APPDATA": str(isolated_home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(isolated_home / "AppData" / "Local"),
        "XDG_CONFIG_HOME": str(isolated_home / ".config"),
        "XDG_DATA_HOME": str(isolated_home / ".local" / "share"),
        "PYTHONPATH": os.pathsep.join((str(SRC), env.get("PYTHONPATH", ""))).rstrip(os.pathsep),
    })
    return env


async def _initialize_pinned(session: Any, mcp_types: Any) -> Any:
    """Use SDK session plumbing while pinning its handshake to the supported version.

    MCP SDK 2.3.0's ``initialize()`` always sends its latest handshake version.
    This interoperability check therefore uses its request/adopt plumbing directly
    to exercise the server's 2025-06-18 compatibility; review this shim on SDK upgrades.
    """
    params = mcp_types.InitializeRequestParams(
        protocolVersion=PROTOCOL_VERSION,
        capabilities=session._build_capabilities(PROTOCOL_VERSION),
        clientInfo=session._client_info,
    )
    result = await session.send_request(
        mcp_types.InitializeRequest(params=params), mcp_types.InitializeResult
    )
    _require(result.protocol_version == PROTOCOL_VERSION,
             "server did not preserve MCP protocol 2025-06-18")
    session.adopt(result)
    await session.send_notification(mcp_types.InitializedNotification())
    return result


async def _exercise_mode(schema_mode: str, base_url: str, isolated_home: Path,
                         empty_env_file: Path, verbose: bool = False) -> dict[str, Any]:
    try:
        mcp_types = importlib.import_module("mcp.types")
        session_module = importlib.import_module("mcp.client.session")
        stdio_module = importlib.import_module("mcp.client.stdio")
    except ImportError as exc:
        raise InteropFailure("optional MCP SDK is unavailable; use the developer environment") from exc

    parameters = stdio_module.StdioServerParameters(
        command=sys.executable,
        args=["-m", "omada_mcp"],
        env=_child_environment(base_url, schema_mode, isolated_home, empty_env_file),
        cwd=ROOT,
        encoding="utf-8",
    )
    def progress(message: str) -> None:
        if verbose:
            print(f"[{schema_mode}] {message}", file=sys.stderr, flush=True)

    progress("starting stdio server")
    async with stdio_module.stdio_client(parameters) as (read_stream, write_stream):
        progress("stdio connected")
        async with session_module.ClientSession(read_stream, write_stream) as session:
            progress("initializing")
            initialized = await _initialize_pinned(session, mcp_types)
            progress("initialized")
            listing = await session.list_tools()
            progress("listed tools")
            by_name = {tool.name: tool for tool in listing.tools}
            _require("list_clients" in by_name, "tools/list did not expose list_clients")
            tool = by_name["list_clients"]
            _require(tool.output_schema is not None,
                     "list_clients descriptor omitted outputSchema")
            _require(tool.input_schema is not None,
                     "list_clients descriptor omitted inputSchema")

            # ClientSession.call_tool runs the SDK's output-schema validator for
            # every successful result after tools/list has cached outputSchema.
            calls: list[dict[str, Any]] = []

            full = await session.call_tool("list_clients", {"pageSize": 1})
            progress("called full projection")
            full_data, full_items = _result_payload(full)
            _require(len(full_items) == 1, "full projection page did not return one client")
            _require("name" in full_items[0] and "mac" in full_items[0],
                     "full projection omitted expected client fields")
            next_cursor = full_data.get("nextCursor")
            _require(isinstance(next_cursor, str) and bool(next_cursor),
                     "full projection page omitted its continuation cursor")
            calls.append({"case": "full_projection", "count": len(full_items),
                          "sdkOutputValidation": "passed"})

            continuation = await session.call_tool("list_clients", {"cursor": next_cursor})
            progress("called continuation")
            continuation_data, continuation_items = _result_payload(continuation)
            _require(len(continuation_items) == 1,
                     "cursor continuation did not return the retained next client")
            calls.append({"case": "continuation", "count": len(continuation_items),
                          "hasMore": bool(continuation_data.get("hasMore")),
                          "sdkOutputValidation": "passed"})

            sparse = await session.call_tool(
                "list_clients", {"pageSize": 2, "fields": ["name", "ip"]}
            )
            progress("called sparse projection")
            sparse_data, sparse_items = _result_payload(sparse)
            _require(len(sparse_items) == 2, "sparse projection returned the wrong page size")
            _require(all(set(item) == {"mac", "name", "ip"} for item in sparse_items),
                     "sparse projection returned fields outside the requested set")
            _require(sparse_data.get("selectedFields") == ["mac", "name", "ip"],
                     "sparse projection selectedFields did not match the canonical selection")
            calls.append({"case": "sparse_projection", "count": len(sparse_items),
                          "fields": ["mac", "name", "ip"],
                          "sdkOutputValidation": "passed"})

            envelope = await session.call_tool(
                "list_clients", {"pageSize": 2, "resultFormat": "envelope"}
            )
            progress("called envelope")
            _require(not envelope.is_error, "envelope call returned an MCP tool error")
            _require(isinstance(envelope.structured_content, dict),
                     "envelope omitted structuredContent")
            _require(len(envelope.content) == 1 and envelope.content[0].type == "text",
                     "envelope did not use one text block")
            envelope_text = getattr(envelope.content[0], "text", None)
            if not isinstance(envelope_text, str):
                raise InteropFailure("envelope text block was not text")
            try:
                parsed_envelope = json.loads(envelope_text)
            except (TypeError, ValueError) as exc:
                raise InteropFailure("envelope text was not JSON") from exc
            _require(parsed_envelope == envelope.structured_content,
                     "envelope text did not equal structuredContent")
            envelope_items = envelope.structured_content.get("items")
            _require(isinstance(envelope_items, list) and len(envelope_items) == 2,
                     "envelope items did not contain the requested page")
            calls.append({"case": "envelope", "count": len(envelope_items),
                          "modeledHermesAdapterEquality": True,
                          "sdkOutputValidation": "passed"})

            return {
                "schemaMode": schema_mode,
                "protocolVersion": initialized.protocol_version,
                "serverName": initialized.server_info.name,
                "toolsListed": len(listing.tools),
                "listClientsInputSchema": "present",
                "listClientsOutputSchema": "present",
                "calls": calls,
                "result": "pass",
            }


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    def progress(message: str) -> None:
        if args.verbose:
            print(f"[setup] {message}", file=sys.stderr, flush=True)

    progress("checking optional packages")
    try:
        sdk_version = importlib.metadata.version("mcp")
        jsonschema_version = importlib.metadata.version("jsonschema")
    except (ImportError, importlib.metadata.PackageNotFoundError) as exc:
        raise InteropFailure("install mcp and jsonschema in the developer environment") from exc

    with tempfile.TemporaryDirectory(prefix="omada-client-interop-") as temporary:
        progress("created isolated temporary home")
        isolated_home = Path(temporary)
        empty_env_file = isolated_home / "empty.env"
        empty_env_file.write_text("", encoding="utf-8")
        progress("created empty dotenv file")
        controller = MockController()
        progress("constructed mock controller")
        with MockControllerHTTPServer(controller) as mock_server:
            progress("started loopback mock controller")
            results = []
            for mode in ("slim", "full"):
                results.append(await asyncio.wait_for(
                    _exercise_mode(mode, mock_server.base_url, isolated_home, empty_env_file,
                                   verbose=args.verbose),
                    timeout=args.timeout,
                ))
            non_auth_mutations = [
                request for request in controller.requests
                if request["method"] != "GET" and not request["path"].endswith("/api/v2/login")
            ]
            _require(not non_auth_mutations, "interop exercise issued a non-auth mutation request")

        return {
            "sdk": "mcp",
            "sdkVersion": sdk_version,
            "jsonschemaVersion": jsonschema_version,
            "protocolVersionPinned": PROTOCOL_VERSION,
            "host": "official MCP Python SDK over stdio",
            "controller": "tests.MockController over loopback HTTP",
            "controllerMutations": len(non_auth_mutations),
            "modelHostBillingEvidence": False,
            "schemaModes": results,
            "result": "pass",
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="seconds allowed per schema mode (default: 30)")
    parser.add_argument("--verbose", action="store_true", help="write progress to stderr")
    args = parser.parse_args()
    try:
        report = asyncio.run(_run(args))
    except Exception as exc:  # keep output free of controller data and credentials
        if args.verbose:
            import traceback

            traceback.print_exception(exc, file=sys.stderr)
        print(json.dumps({"result": "fail", "failureType": type(exc).__name__,
                          "message": str(exc) if isinstance(exc, InteropFailure) else "check failed"},
                         ensure_ascii=True), file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
