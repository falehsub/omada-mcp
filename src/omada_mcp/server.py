"""MCP stdio server: newline-delimited JSON-RPC 2.0.

Design decisions that differ from a naive bridge:

* **``initialize`` never touches the controller.** Credentials, TLS and site
  resolution are validated by ``omada-mcp --doctor``; a wrong password must not
  stop the host from starting the server and listing tools.
* **Authentication is lazy** and happens on the first ``tools/call``; the login
  is cached for the life of the process and replayed transparently when the
  controller's server-side session dies.
* **``OMADA_READ_ONLY=true`` fails closed**: anything that is not a declared
  read-only tool is refused with ``-32003`` before the tool lookup, so a write
  tool added in a future release cannot bypass the switch by accident.
* **stdout carries JSON-RPC only.** All diagnostics go to stderr.
"""

from __future__ import annotations

import json
import traceback
from collections.abc import Iterable
from typing import Any, TextIO

from . import __version__
from .client import OmadaClient, OmadaError, log
from .config import Config
from .schema_validation import SchemaValidationError, validate_tool_arguments
from .tools import TOOL_MAP, Tool, get_tool, tool_descriptors

__all__ = ["PROTOCOL_VERSIONS", "DEFAULT_PROTOCOL_VERSION", "Server",
           "configure_streams"]

#: Newest first. The first entry is used when the client asks for something
#: unsupported (e.g. an HTTP-era or a future draft revision).
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2025-01-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

SERVER_NAME = "omada-mcp"

INSTRUCTIONS = (
    "Read-only access by default to a TP-Link Omada SDN controller through its Web API v2. "
    "Thirty-three read-only tools are always available, including get_config_snapshot, network_audit, "
    "get_switch_ports, get_ap_radios, get_wan_status, get_topology, diagnose_client, diagnose_wan, "
    "get_site_info, list_devices / list_clients, get_device / get_client, and explain_error. "
    "Optional write tools remain hidden and disabled unless both OMADA_READ_ONLY=false and "
    "OMADA_WRITE_TOOLS explicitly allowlist them. Timestamps are UTC ISO-8601. Error messages "
    "include the controller's numeric errorCode and a fix hint."
)


def configure_streams(stdin: TextIO | None = None,
                      stdout: TextIO | None = None,
                      stderr: TextIO | None = None) -> None:
    """Force UTF-8 and LF line endings on the stdio streams.

    Two Windows-specific failures this prevents:

    * **Encoding.** The console default code page (cp1252, cp1256, cp437, ...)
      cannot encode an SSID or device name that is not in that code page, so
      ``json.dumps(..., ensure_ascii=False)`` raises ``UnicodeEncodeError`` in
      the middle of a session. UTF-8 with ``errors="replace"`` cannot raise.
    * **Newlines.** Text mode translates ``"\n"`` to ``"\r\n"`` on Windows.
      Some strict MCP clients split frames on ``"\n"`` and choke on the ``\r``;
      ``newline="\n"`` writes exactly one byte per frame.

    ``stdin`` gets ``newline=""`` so universal-newline translation does not
    rewrite ``\r\n`` in the middle of an incoming frame (the frame reader
    tolerates both styles anyway).
    """
    import sys

    targets = ((stdin if stdin is not None else sys.stdin, ""),
               (stdout if stdout is not None else sys.stdout, "\n"),
               (stderr if stderr is not None else sys.stderr, "\n"))
    for stream, newline in targets:
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # StringIO and other test doubles
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace", newline=newline)
        except (AttributeError, OSError, ValueError):
            continue


class RpcError(Exception):
    """A JSON-RPC level failure (as opposed to a tool execution failure)."""

    def __init__(self, code: int, message: str, hint: str | None = None,
                 data: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint
        self.extra = data or {}

    def payload(self) -> dict[str, Any]:
        data: dict[str, Any] = dict(self.extra)
        if self.hint:
            data["hint"] = self.hint
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if data:
            error["data"] = data
        return error


class Server:
    """One MCP connection: owns a single :class:`OmadaClient`."""

    def __init__(self, config: Config, client: OmadaClient | None = None,
                 out: TextIO | None = None):
        self.config = config
        self.client = client or OmadaClient(config)
        self.out = out
        self.protocol_version = DEFAULT_PROTOCOL_VERSION
        self.initialized = False

    # -- lifecycle ------------------------------------------------------------

    def serve(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
        """Read JSON-RPC from ``stdin`` until EOF, writing replies to ``stdout``."""
        import sys

        stdin = stdin or sys.stdin
        self.out = stdout or sys.stdout
        configure_streams(stdin, self.out)
        log(f"omada-mcp {__version__} ready on stdio "
            f"(read_only={self.config.read_only}, site={self.config.site_id or self.config.site_name or 'first'})")
        try:
            for message in self._read_messages(stdin):
                response = self.handle(message)
                if response is not None:
                    self._write(response)
            return 0
        finally:
            close_fn = getattr(self.client, "close", None)
            if callable(close_fn):
                close_fn()

    def _write(self, payload: dict[str, Any]) -> None:
        assert self.out is not None
        self.out.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.out.flush()

    #: Upper bound on one buffered, still-incomplete JSON value. Guards against a
    #: client that streams an unterminated value forever (memory growth).
    MAX_FRAME_CHARS = 8 * 1024 * 1024

    @classmethod
    def _read_messages(cls, stream: TextIO) -> Iterable[Any]:
        """Yield every JSON value, tolerating multiple values per line.

        A value split across lines is buffered until it completes, but a real
        syntax error (the decoder fails *before* the end of the buffered text)
        is reported once as ``None`` (-> ``-32700``) and the rest of that line
        is discarded. Without this a single garbage line would poison the
        buffer and every later request would be swallowed silently.
        """
        decoder = json.JSONDecoder()
        buffer = ""
        while True:
            chunk = stream.readline(cls.MAX_FRAME_CHARS + 1)
            if len(buffer) + len(chunk) > cls.MAX_FRAME_CHARS:
                # Drain an oversized physical line in bounded chunks, then recover.
                while chunk and not chunk.endswith("\n"):
                    chunk = stream.readline(cls.MAX_FRAME_CHARS + 1)
                buffer = ""
                yield None
                continue
            if not chunk:  # EOF: flush anything still buffered
                tail = buffer.strip()
                if tail:
                    try:
                        yield json.loads(tail)
                    except json.JSONDecodeError:
                        yield None
                return
            buffer += chunk
            while True:
                stripped = buffer.lstrip()
                if not stripped:
                    buffer = ""
                    break
                try:
                    value, end = decoder.raw_decode(stripped)
                except json.JSONDecodeError as exc:
                    content_end = len(stripped.rstrip())
                    if exc.pos < content_end:
                        # Genuine syntax error: report it, drop the bad line.
                        yield None
                        newline = stripped.find("\n", exc.pos)
                        buffer = "" if newline < 0 else stripped[newline + 1:]
                        continue
                    if len(stripped) > cls.MAX_FRAME_CHARS:
                        yield None
                        buffer = ""
                        break
                    # Incomplete value: wait for more input.
                    buffer = stripped
                    break
                yield value
                buffer = stripped[end:]

    # -- dispatch -------------------------------------------------------------

    def handle(self, message: Any) -> dict[str, Any] | None:
        if message is None:
            return self._error(None, -32700, "parse error: not valid JSON")
        if not isinstance(message, dict):
            return self._error(None, -32600, "invalid request: expected a JSON object")

        msg_id = message.get("id")
        if "id" in message and (isinstance(msg_id, bool) or not isinstance(msg_id, (str, int))):
            return self._error(None, -32600, "invalid request: id must be a string or integer")
        if message.get("jsonrpc") != "2.0":
            return self._error(msg_id, -32600, "invalid request: jsonrpc must be '2.0'")
        method = message.get("method")
        params = message.get("params", {})

        if not isinstance(method, str):
            # A response object (has result/error) is not ours to handle.
            if "result" in message or "error" in message:
                return None
            return self._error(msg_id, -32600, "invalid request: missing method")

        # Notifications are one-way. Never dispatch tools without a request ID.
        if "id" not in message:
            return None

        try:
            if not isinstance(params, dict):
                raise RpcError(-32602, "invalid params: expected an object")
            result = self._call_method(method, params)
        except RpcError as exc:
            return self._error(msg_id, exc.code, exc.message, exc.hint, exc.extra)
        except OmadaError as exc:
            return self._error(msg_id, -32002, str(exc.message),
                               exc.hint, {"errorCode": exc.code} if exc.code else None)
        except Exception as exc:  # pragma: no cover - defensive
            log("internal error:\n" + traceback.format_exc())
            return self._error(msg_id, -32603, f"internal error: {exc}")

        if result is None and msg_id is None:
            return None
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _error(self, msg_id: Any, code: int, message: str,
               hint: str | None = None, data: dict[str, Any] | None = None) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        merged = dict(data or {})
        if hint:
            merged["hint"] = hint
        if merged:
            error["data"] = merged
        return {"jsonrpc": "2.0", "id": msg_id, "error": error}

    def _call_method(self, method: str, params: dict[str, Any]) -> Any:
        if method == "initialize":
            return self._initialize(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": tool_descriptors(config=self.config)}
        if method == "tools/call":
            return self._tools_call(params)
        if method in ("resources/list",):
            return {"resources": []}
        if method in ("resources/templates/list",):
            return {"resourceTemplates": []}
        if method == "prompts/list":
            return {"prompts": []}
        if method == "logging/setLevel":
            return {}
        if method in ("resources/read", "prompts/get"):
            raise RpcError(-32602, f"{method}: no resources or prompts are exposed")
        raise RpcError(-32601, f"method not found: {method}",
                       hint="supported methods: initialize, ping, tools/list, tools/call")

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = str(params.get("protocolVersion") or "").strip()
        self.protocol_version = requested if requested in PROTOCOL_VERSIONS \
            else DEFAULT_PROTOCOL_VERSION
        self.initialized = True
        active_writes = list(self.config.write_tools) if not self.config.read_only else []
        title = (
            "TP-Link Omada SDN (read + allowlisted write)"
            if active_writes
            else "TP-Link Omada SDN (read-only)"
        )
        instructions = INSTRUCTIONS
        if active_writes:
            instructions = (
                f"{INSTRUCTIONS} Active write allowlist: {', '.join(active_writes)}. "
                "Every write tool defaults to dryRun=true; applying requires dryRun=false "
                "with confirm='<tool>:<target-id>' from the dry-run preview."
            )
        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": SERVER_NAME,
                "title": title,
                "version": __version__,
            },
            "instructions": instructions,
        }

    # -- tools ----------------------------------------------------------------

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = str(params.get("name") or "").strip()
        raw_arguments = params.get("arguments")
        if raw_arguments is None:
            arguments: dict[str, Any] = {}
        elif isinstance(raw_arguments, dict):
            arguments = dict(raw_arguments)
        else:
            raise RpcError(-32602, "invalid params: arguments must be an object")
        if not name:
            raise RpcError(-32602, "invalid params: tool name is required")

        spec: Tool | None = get_tool(name)

        # Fail closed: in read-only mode anything not declared read-only is
        # refused before argument validation or controller I/O.
        read_only_names = sorted(t.name for t in TOOL_MAP.values() if t.read_only)
        if self.config.read_only and (spec is None or not spec.read_only):
            raise RpcError(
                -32003,
                f"OMADA_READ_ONLY=true refuses the non-read-only tool {name!r}",
                hint=("set OMADA_READ_ONLY=false and allowlist the tool in "
                      "OMADA_WRITE_TOOLS to enable write operations; read-only tools: "
                      + ", ".join(read_only_names)),
                data={"tool": name, "readOnly": True},
            )

        if spec is None:
            available = [d["name"] for d in tool_descriptors(config=self.config)]
            raise RpcError(
                -32601,
                f"unknown tool: {name}",
                hint="call tools/list; available: " + ", ".join(available),
            )

        # Second gate: even with OMADA_READ_ONLY=false, every write tool stays
        # refused unless explicitly named in OMADA_WRITE_TOOLS.
        if not spec.read_only and name not in self.config.write_tools:
            raise RpcError(
                -32003,
                f"OMADA_WRITE_TOOLS refuses write tool {name!r}",
                hint=(f"add {name!r} to OMADA_WRITE_TOOLS to allowlist it "
                      "(currently active write tools: "
                      + (", ".join(self.config.write_tools) or "none") + ")"),
                data={"tool": name, "writeTools": list(self.config.write_tools)},
            )

        self._check_arguments(spec, arguments)

        # Authentication problems are protocol-level, not tool results: the host
        # should surface them as a failed call, not as data the model can reason
        # over as if it were an answer.
        if spec.requires_auth:
            try:
                self.client.authenticate()
            except OmadaError as exc:
                raise RpcError(-32002, str(exc.message), exc.hint,
                               {"errorCode": exc.code} if exc.code else None) from None

        try:
            data = spec.handler(self.client, **arguments)
        except OmadaError as exc:
            # Tool execution failures are reported in-band per MCP.
            text = str(exc)
            return {
                "content": [{"type": "text", "text": f"{spec.name} failed: {text}"}],
                "isError": True,
            }

        if getattr(self.config, "compact_output", True):
            rendered = json.dumps(data, separators=(",", ":"), ensure_ascii=False, default=str)
        else:
            rendered = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": rendered}],
            "isError": False,
        }
        if isinstance(data, dict):
            result["structuredContent"] = data
        elif isinstance(data, list) and all(isinstance(item, dict) for item in data):
            # Keep structuredContent an object, as the spec requires.
            structured: dict[str, Any] = {"items": data, "count": len(data)}
            page_meta = getattr(data, "pagination", None)
            if isinstance(page_meta, dict):
                structured.update(page_meta)
                if page_meta.get("truncated"):
                    reason = page_meta.get("truncationReason") or "result set truncated"
                    total_rows = page_meta.get("totalRows")
                    detail = (
                        f" ({len(data)} of {total_rows} rows)"
                        if total_rows is not None
                        else f" ({len(data)} rows)"
                    )
                    result["content"].append({
                        "type": "text",
                        "text": f"Note: {reason}{detail}. Pass a higher limit or narrow filters to inspect remaining entries.",
                    })
            result["structuredContent"] = structured
        return result

    @staticmethod
    def _check_arguments(spec: Tool, arguments: dict[str, Any]) -> None:
        try:
            validate_tool_arguments(spec, arguments)
        except SchemaValidationError as exc:
            raise RpcError(-32602, exc.message, hint=exc.hint) from None
