"""Reproducible stdlib-only measurements for client list and lookup reads.

Run from any directory with ``python scripts/benchmark_clients.py --json``.
The fake serves only the requested page; timings are local observations, not
controller latency. The report contains aggregate sizes and never raw payloads.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
import tracemalloc
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "src", ROOT / "tests"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from client_fixtures import (  # type: ignore[import-not-found]  # noqa: E402
    SUPPORTED_ROW_COUNTS,
    FakeOmadaClient,
    SyntheticClientSource,
)
from fake_controller import make_config  # type: ignore[import-not-found]  # noqa: E402

from omada_mcp import __version__  # noqa: E402
from omada_mcp.domains._client_query import query_clients  # noqa: E402
from omada_mcp.domains.clients_read import _get_client, _list_clients  # noqa: E402
from omada_mcp.server import Server  # noqa: E402

_SPARSE_FIELDS = ["mac", "ip", "active", "wireless", "vlan"]
_ENCODING_NAME = "o200k_base"
_TOKENIZER: Any = None
_TOKENIZER_VERSION: str | None = None
_TOKENIZER_STATUS = "not-loaded"


def _commit() -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
            capture_output=True, text=True, timeout=2,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _worktree_dirty() -> bool | None:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, check=True,
            capture_output=True, text=True, timeout=2,
        )
        return bool(result.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return None


def _measure(operation: Callable[[], Any]) -> tuple[Any, float, int]:
    tracemalloc.start()
    started = time.perf_counter()
    try:
        result = operation()
        wall_seconds = time.perf_counter() - started
        _current, peak_bytes = tracemalloc.get_traced_memory()
        return result, wall_seconds, peak_bytes
    finally:
        tracemalloc.stop()


def _json_bytes(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _tokenizer() -> tuple[Any, str | None, str]:
    global _TOKENIZER, _TOKENIZER_VERSION, _TOKENIZER_STATUS
    if _TOKENIZER_STATUS != "not-loaded":
        return _TOKENIZER, _TOKENIZER_VERSION, _TOKENIZER_STATUS
    try:
        import tiktoken
    except ImportError:
        _TOKENIZER_STATUS = "not-installed"
        return None, None, _TOKENIZER_STATUS
    try:
        _TOKENIZER = tiktoken.get_encoding(_ENCODING_NAME)
    except Exception as exc:  # Optional tokenizer may be installed without its offline vocabulary.
        _TOKENIZER_STATUS = f"unavailable:{type(exc).__name__}"
        return None, None, _TOKENIZER_STATUS
    _TOKENIZER_VERSION = getattr(tiktoken, "__version__", None)
    _TOKENIZER_STATUS = "available"
    return _TOKENIZER, _TOKENIZER_VERSION, _TOKENIZER_STATUS


def _token_count(text: str) -> int | None:
    encoding, _version, _status = _tokenizer()
    return len(encoding.encode(text)) if encoding is not None else None


def benchmark_case(row_count: int, operation_name: str) -> dict[str, Any]:
    client = FakeOmadaClient(SyntheticClientSource(row_count))
    client.authenticate()  # Exclude auth setup from the measured read.
    if operation_name == "list_clients":
        value, wall_seconds, peak_bytes = _measure(lambda: _list_clients(client, limit=50))
        rows = list(value)
        pagination = value.pagination
        matched_rows = pagination.get("totalRows")
        returned_rows = len(rows)
    else:
        first_mac = SyntheticClientSource(row_count).row_at(0)["mac"] if row_count else "02:00:00:00:00:00"
        value, wall_seconds, peak_bytes = _measure(lambda: _get_client(client, first_mac))
        matched_rows = 1 if row_count else 0
        returned_rows = 1 if row_count else 0
        pagination = None

    rendered_value = list(value) if operation_name == "list_clients" else value
    return {
        "fixture_rows": row_count,
        "operation": operation_name,
        "request_count": client.request_count,
        "collection_request_count": client.collection_request_count,
        "controller_body_bytes": client.response_body_bytes,
        "rendered_bytes": _json_bytes(rendered_value),
        "matched_rows": matched_rows,
        "returned_rows": returned_rows,
        "pages_fetched": pagination.get("pagesFetched") if pagination else client.collection_request_count,
        "source_seconds": round(client.source_seconds, 9),
        "wall_seconds": round(wall_seconds, 9),
        "peak_traced_bytes": peak_bytes,
    }


def benchmark_paged_output(
    row_count: int, *, sparse: bool = False, envelope: bool = False, page_size: int | None = None,
) -> dict[str, Any]:
    client = FakeOmadaClient(SyntheticClientSource(row_count))
    client.authenticate()
    fields = _SPARSE_FIELDS if sparse else None
    if envelope:
        value, wall_seconds, peak_bytes = _measure(
            lambda: query_clients(
                client, "list_clients", pageSize=max(1, row_count),
                fields=fields, resultFormat="envelope",
            )
        )
        assert isinstance(value, dict)
    else:
        value, wall_seconds, peak_bytes = _measure(
            lambda: query_clients(
                client, "list_clients", pageSize=page_size or max(1, row_count), fields=fields,
            )
        )
        assert not isinstance(value, dict)
    items = value["items"] if isinstance(value, dict) else list(value)
    pagination = value if isinstance(value, dict) else value.pagination
    items_text = json.dumps(items, ensure_ascii=False, separators=(",", ":"), default=str)
    envelope_text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return {
        "fixture_rows": row_count,
        "format": "envelope" if envelope else "item_array",
        "selected_fields": fields or "all",
        "request_count": client.request_count,
        "controller_body_bytes": client.response_body_bytes,
        "item_array_bytes": len(items_text.encode("utf-8")),
        "item_array_tokens_o200k": _token_count(items_text),
        "envelope_bytes": len(envelope_text.encode("utf-8")) if envelope else None,
        "envelope_tokens_o200k": _token_count(envelope_text) if envelope else None,
        "returned_rows": len(items),
        "complete": pagination.get("complete"),
        "pages_fetched": pagination.get("pagesFetched"),
        "source_seconds": round(client.source_seconds, 9),
        "wall_seconds": round(wall_seconds, 9),
        "peak_traced_bytes": peak_bytes,
    }


def benchmark_server_rpc(row_count: int, *, sparse: bool, envelope: bool) -> dict[str, Any]:
    client = FakeOmadaClient(SyntheticClientSource(row_count))
    client.authenticate()
    config = make_config(read_only=True, site_id=client.site_id)
    client.config = config
    server = Server(config, client=client)
    arguments: dict[str, Any] = {"pageSize": row_count}
    if sparse:
        arguments["fields"] = _SPARSE_FIELDS
    if envelope:
        arguments["resultFormat"] = "envelope"
    request = {
        "jsonrpc": "2.0", "id": "client-efficiency",
        "method": "tools/call",
        "params": {"name": "list_clients", "arguments": arguments},
    }
    response, wall_seconds, peak_bytes = _measure(lambda: server.handle(request))
    result = response.get("result", {})
    content = result.get("content", [])
    text = str(content[0].get("text", "")) if content else ""
    structured = result.get("structuredContent")
    structured_text = json.dumps(structured, ensure_ascii=False, separators=(",", ":"), default=str)
    frame_text = json.dumps(response, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"
    text_tokens = _token_count(text)
    structured_tokens = _token_count(structured_text)
    identical_representation = text == structured_text
    if envelope:
        modeled_host_tokens = text_tokens if identical_representation else (
            text_tokens + structured_tokens if text_tokens is not None and structured_tokens is not None else None
        )
        host_model = "envelope content/structured dedupe proxy; not paid-token measurement"
    else:
        modeled_host_tokens = (
            text_tokens + structured_tokens
            if text_tokens is not None and structured_tokens is not None else None
        )
        host_model = "legacy text plus structured duplicate proxy; not paid-token measurement"
    return {
        "fixture_rows": row_count,
        "mode": "sparse_envelope" if envelope else "full_legacy",
        "rpc_wire_bytes": len(frame_text.encode("utf-8")),
        "content_block_count": len(content),
        "content_text_bytes": len(text.encode("utf-8")),
        "content_text_tokens_o200k": text_tokens,
        "structured_content_bytes": len(structured_text.encode("utf-8")),
        "structured_content_tokens_o200k": structured_tokens,
        "content_and_structured_identical": identical_representation,
        "modeled_host_tokens": modeled_host_tokens,
        "host_model": host_model,
        "request_count": client.request_count,
        "wall_seconds": round(wall_seconds, 9),
        "peak_traced_bytes": peak_bytes,
    }


def benchmark_lookup(row_count: int) -> dict[str, Any]:
    client = FakeOmadaClient(SyntheticClientSource(row_count))
    client.authenticate()
    mac = SyntheticClientSource(row_count).row_at(0)["mac"]
    value, wall_seconds, peak_bytes = _measure(lambda: _get_client(client, mac))
    return {
        "fixture_rows": row_count,
        "operation": "get_client_first_row",
        "request_count": client.request_count,
        "collection_request_count": client.collection_request_count,
        "controller_body_bytes": client.response_body_bytes,
        "rendered_bytes": _json_bytes(value),
        "matched_rows": 1,
        "returned_rows": 1,
        "source_seconds": round(client.source_seconds, 9),
        "wall_seconds": round(wall_seconds, 9),
        "peak_traced_bytes": peak_bytes,
    }


def benchmark_full_traversal(row_count: int = 10_000) -> dict[str, Any]:
    client = FakeOmadaClient(SyntheticClientSource(row_count))
    client.authenticate()
    cursor = None
    identities: set[str] = set()
    returned = 0
    calls = 0
    page_attempts = 0
    cursor_peak_entries = 0
    cursor_peak_bytes = 0
    tracemalloc.start()
    started = time.perf_counter()
    try:
        while True:
            page = query_clients(client, "list_clients", pageSize=500, cursor=cursor)
            assert not isinstance(page, dict)
            returned += len(page)
            identities.update(str(row.get("mac", "")) for row in page if row.get("mac"))
            page_attempts += page.pagination["pagesFetched"]
            calls += 1
            cursor_peak_entries = max(cursor_peak_entries, len(client.client_cursors))
            cursor_peak_bytes = max(cursor_peak_bytes, client.client_cursors.bytes_used)
            cursor = page.pagination.get("nextCursor")
            if cursor is None:
                complete = page.pagination["complete"]
                stop_reason = page.pagination["stopReason"]
                break
            if calls > 100:
                complete, stop_reason = False, "benchmark_safety_stop"
                break
        wall_seconds = time.perf_counter() - started
        _current, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return {
        "fixture_rows": row_count,
        "operation": "unique_full_traversal",
        "page_size": 500,
        "query_calls": calls,
        "native_page_attempts": page_attempts,
        "request_count": client.request_count,
        "returned_rows": returned,
        "unique_rows": len(identities),
        "cursor_store_peak_entries": cursor_peak_entries,
        "cursor_store_peak_serialized_bytes": cursor_peak_bytes,
        "cursor_store_final_entries": len(client.client_cursors),
        "cursor_store_final_serialized_bytes": client.client_cursors.bytes_used,
        "complete": complete,
        "stop_reason": stop_reason,
        "source_seconds": round(client.source_seconds, 9),
        "wall_seconds": round(wall_seconds, 9),
        "peak_traced_bytes": peak_bytes,
    }


def benchmark_viewer_continuation() -> dict[str, Any]:
    client = FakeOmadaClient(SyntheticClientSource(205, role="Viewer"))
    client.authenticate()
    first = query_clients(client, "list_clients", pageSize=100)
    assert not isinstance(first, dict)
    initial_requests = client.request_count
    initial_source = first.pagination["source"]
    next_cursor = first.pagination.get("nextCursor")
    second = query_clients(client, "list_clients", pageSize=100, cursor=next_cursor)
    assert not isinstance(second, dict)
    continuation_requests = client.request_count - initial_requests
    return {
        "initial_requests": initial_requests,
        "initial_pages_fetched": first.pagination["pagesFetched"],
        "initial_source": initial_source,
        "continuation_requests": continuation_requests,
        "continuation_source": second.pagination["source"],
        "source_pinned": initial_source == "insight/clients" == second.pagination["source"],
        "first_page_rows": len(first),
        "continuation_rows": len(second),
    }


def benchmark_schema_proxy() -> dict[str, Any]:
    from omada_mcp.tools import tool_descriptors

    descriptors = tool_descriptors(schema_mode="slim")
    read_only = [item for item in descriptors if item.get("annotations", {}).get("readOnlyHint")]
    proxy = [
        {
            "name": f"mcp__omada__{item['name']}",
            "description": item["description"],
            "parameters": item["inputSchema"],
        }
        for item in read_only
    ]
    rendered = json.dumps(proxy, ensure_ascii=False, separators=(",", ":"))
    _encoding, tokenizer_version, tokenizer_status = _tokenizer()
    token_count = _token_count(rendered)
    baseline_tokens = 3_782
    return {
        "tool_count": len(proxy),
        "format": "read_only_slim_function_proxy(mcp__omada__name,description,parameters)",
        "rendered_bytes": len(rendered.encode("utf-8")),
        "tokenizer": _ENCODING_NAME if tokenizer_version else None,
        "tokenizer_version": tokenizer_version,
        "tokenizer_status": tokenizer_status,
        "tokens": token_count,
        "same_method_baseline_tokens": baseline_tokens,
        "delta_from_same_method_baseline": (
            token_count - baseline_tokens if token_count is not None else None
        ),
        "delta_percent_from_same_method_baseline": (
            round((token_count - baseline_tokens) * 100 / baseline_tokens, 2)
            if token_count is not None else None
        ),
    }


def _deterministic_checks(report: dict[str, Any], *, require_tokens: bool = False) -> dict[str, Any]:
    measurements = report["measurements"]
    checks: dict[str, bool] = {}
    checks["paged_full_13_complete"] = measurements["paged_full"][0]["complete"] is True
    checks["paged_full_50_complete"] = measurements["paged_full"][1]["complete"] is True
    checks["sparse_13_has_five_fields"] = measurements["sparse_items"][0]["selected_fields"] == _SPARSE_FIELDS
    checks["sparse_50_has_five_fields"] = measurements["sparse_items"][1]["selected_fields"] == _SPARSE_FIELDS
    checks["get_2k_at_most_one_request"] = measurements["lookups"][0]["request_count"] <= 1
    checks["get_10k_at_most_one_request"] = measurements["lookups"][1]["request_count"] <= 1
    checks["first_page_50_from_2k_uses_one_get"] = measurements["first_page_2k_50"]["request_count"] == 1
    traversal = measurements["full_traversal_10k"]
    checks["full_traversal_10k_complete_unique"] = (
        traversal["complete"] is True and traversal["returned_rows"] == 10_000
        and traversal["unique_rows"] == 10_000
    )
    checks["cursor_entries_within_budget"] = traversal["cursor_store_peak_entries"] <= 32
    checks["cursor_serialized_bytes_within_budget"] = traversal["cursor_store_peak_serialized_bytes"] <= 8 * 1024 * 1024
    viewer = measurements["viewer_continuation"]
    checks["viewer_initial_probe_within_budget"] = viewer["initial_requests"] <= 2
    checks["viewer_continuation_reuses_source"] = (
        viewer["source_pinned"] is True and viewer["continuation_requests"] <= 1
    )
    schema = measurements["schema_function_proxy"]
    schema_tokens = schema["tokens"]
    checks["schema_function_proxy_within_budget"] = (
        schema_tokens is None or schema_tokens <= 5_200
    )
    checks["schema_function_proxy_has_55_tools"] = schema["tool_count"] == 55
    rpc = measurements["server_rpc_layers"]
    checks["rpc_envelope_content_structured_match"] = all(
        result["content_and_structured_identical"] for result in rpc["sparse_envelope"]
    )
    checks["host_envelope_dedupe_proxy_equals_text"] = all(
        result["modeled_host_tokens"] == result["content_text_tokens_o200k"]
        for result in rpc["sparse_envelope"]
    )
    checks["host_legacy_proxy_counts_both_representations"] = all(
        result["modeled_host_tokens"] is None
        if result["content_text_tokens_o200k"] is None
        or result["structured_content_tokens_o200k"] is None
        else result["modeled_host_tokens"] == (
            result["content_text_tokens_o200k"] + result["structured_content_tokens_o200k"]
        )
        for result in rpc["full_legacy"]
    )
    token_checks: dict[str, bool] = {}
    for index, expected in enumerate((600, 2_200)):
        sparse_tokens = measurements["sparse_items"][index]["item_array_tokens_o200k"]
        full_tokens = measurements["paged_full"][index]["item_array_tokens_o200k"]
        envelope_tokens = measurements["sparse_envelope"][index]["envelope_tokens_o200k"]
        token_checks[f"sparse_{(13, 50)[index]}_token_budget"] = (
            sparse_tokens is None or sparse_tokens <= expected
        )
        envelope_budget = (800, 2_500)[index]
        token_checks[f"sparse_envelope_{(13, 50)[index]}_token_budget"] = (
            envelope_tokens is None or envelope_tokens <= envelope_budget
        )
        token_checks[f"sparse_{(13, 50)[index]}_token_reduction"] = (
            sparse_tokens is None or full_tokens is None or sparse_tokens <= full_tokens * 0.3
        )
    checks.update(token_checks)
    token_values = [schema_tokens] + [
        row[key]
        for section, key in (("paged_full", "item_array_tokens_o200k"),
                             ("sparse_items", "item_array_tokens_o200k"),
                             ("sparse_envelope", "envelope_tokens_o200k"))
        for row in measurements[section]
    ]
    tokens_available = all(value is not None for value in token_values)
    checks["tokens_available"] = tokens_available or not require_tokens
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "token_checks_skipped": not tokens_available,
        "tokens_required": require_tokens,
    }


def build_report(
    row_counts: tuple[int, ...] = SUPPORTED_ROW_COUNTS,
    *, require_tokens: bool = False,
) -> dict[str, Any]:
    rows = [
        benchmark_case(size, operation)
        for size in row_counts
        for operation in ("list_clients", "get_client")
    ]
    commit = _commit()
    worktree_dirty = _worktree_dirty()
    report = {
        "benchmark": "client_reads",
        "schema_version": 1,
        "package_version": __version__,
        "commit": commit,
        "worktree_dirty": worktree_dirty,
        "measurement_source": (
            "unknown" if worktree_dirty is None else "working tree" if worktree_dirty else "committed tree"
        ),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "os": platform.platform(),
        "auth_warmup": "authenticate() called before measurement; fake has no network auth",
        "pacing": "none; fake API has no controller delay or retry pacing",
        "fixture": "deterministic synthetic rows; one page generated per request",
        "historical_baseline": {
            "label": "observed v2.3.0 full collector, before paged implementation",
            "fixture_rows": 2_000,
            "operation": "list_clients(limit=50)",
            "collection_requests": 20,
            "controller_body_bytes": 980_877,
            "peak_traced_bytes": 6_391_063,
            "returned_rows": 50,
            "measurement_note": "Reproduced from archived ffe33e1 code with the same synthetic row source on Windows/CPython 3.10.11. One tracemalloc sample; unused new fixture budget/store imports shimmed. Memory and timing observations are not gates.",
        },
        "historical_schema_proxy": {
            "label": "same-serialization v2.3.0 reference",
            "token_count_o200k": 3_782,
            "tool_count": 54,
            "format": "read_only_slim_function_proxy(mcp__omada__name,description,parameters)",
            "comparison_note": "The plan's earlier 4,108 token figure used a different serialization; compare this 3,782-token run only with the same prefixed proxy method.",
        },
        "measurements": {
            "current_entrypoints": rows,
            "paged_full": [benchmark_paged_output(size) for size in (13, 50)],
            "sparse_items": [benchmark_paged_output(size, sparse=True) for size in (13, 50)],
            "sparse_envelope": [
                benchmark_paged_output(size, sparse=True, envelope=True) for size in (13, 50)
            ],
            "first_page_2k_50": benchmark_paged_output(2_000, page_size=50),
            "server_rpc_layers": {
                "full_legacy": [
                    benchmark_server_rpc(size, sparse=False, envelope=False) for size in (13, 50)
                ],
                "sparse_envelope": [
                    benchmark_server_rpc(size, sparse=True, envelope=True) for size in (13, 50)
                ],
            },
            "lookups": [benchmark_lookup(size) for size in (2_000, 10_000)],
            "full_traversal_10k": benchmark_full_traversal(10_000),
            "viewer_continuation": benchmark_viewer_continuation(),
            "schema_function_proxy": benchmark_schema_proxy(),
        },
    }
    report["tokenizer"] = {
        "name": _ENCODING_NAME,
        "version": _tokenizer()[1],
        "status": _tokenizer()[2],
    }
    report["deterministic_checks"] = _deterministic_checks(report, require_tokens=require_tokens)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON (the default format)")
    parser.add_argument("--output", type=Path, help="also write the JSON report to this path")
    parser.add_argument("--check", action="store_true", help="exit nonzero when deterministic budgets fail")
    parser.add_argument(
        "--require-tokens", action="store_true",
        help="fail checks when the optional pinned tiktoken vocabulary is unavailable",
    )
    parser.add_argument(
        "--sizes", type=int, nargs="+", choices=SUPPORTED_ROW_COUNTS,
        default=list(SUPPORTED_ROW_COUNTS), help="fixture sizes to measure",
    )
    args = parser.parse_args(argv)
    report = build_report(tuple(args.sizes), require_tokens=args.require_tokens)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    sys.stdout.write(rendered)
    return 1 if args.check and not report["deterministic_checks"]["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
