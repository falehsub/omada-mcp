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
from typing import Any, Dict, Iterable, List, Optional, TextIO

from . import __version__
from .client import OmadaClient, OmadaError, log
from .config import Config
from .tools import TOOL_MAP, Tool, get_tool, tool_descriptors

__all__ = ["PROTOCOL_VERSIONS", "DEFAULT_PROTOCOL_VERSION", "Server",
           "configure_streams"]

#: Newest first. The first entry is used when the client asks for something
#: unsupported (e.g. an HTTP-era or a future draft revision).
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2025-01-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

SERVER_NAME = "omada-mcp"

INSTRUCTIONS = (
    "Read-only access to a TP-Link Omada SDN controller through its Web API v2. "
    "All ten tools are read-only and idempotent. Prefer network_audit or get_site_info "
    "for an overview, list_devices / list_clients for detail, get_device or get_client "
    "for one object, and explain_error to decode any Omada errorCode. Timestamps are UTC "
    "ISO-8601. Error messages include the controller's numeric errorCode and a fix hint."
)


def configure_streams(stdin: Optional[TextIO] = None,
                      stdout: Optional[TextIO] = None,
                      stderr: Optional[TextIO] = None) -> None:
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

    def __init__(self, code: int, message: str, hint: Optional[str] = None,
                 data: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint
        self.extra = data or {}

    def payload(self) -> Dict[str, Any]:
        data: Dict[str, Any] = dict(self.extra)
        if self.hint:
            data["hint"] = self.hint
        error: Dict[str, Any] = {"code": self.code, "message": self.message}
        if data:
            error["data"] = data
        return error


class Server:
    """One MCP connection: owns a single :class:`OmadaClient`."""

    def __init__(self, config: Config, client: Optional[OmadaClient] = None,
                 out: Optional[TextIO] = None):
        self.config = config
        self.client = client or OmadaClient(config)
        self.out = out
        self.protocol_version = DEFAULT_PROTOCOL_VERSION
        self.initialized = False

    # -- lifecycle ------------------------------------------------------------

    def serve(self, stdin: Optional[TextIO] = None, stdout: Optional[TextIO] = None) -> int:
        """Read JSON-RPC from ``stdin`` until EOF, writing replies to ``stdout``."""
        import sys

        stdin = stdin or sys.stdin
        self.out = stdout or sys.stdout
        configure_streams(stdin, self.out)
        log(f"omada-mcp {__version__} ready on stdio "
            f"(read_only={self.config.read_only}, site={self.config.site_id or self.config.site_name or 'first'})")
        for message in self._read_messages(stdin):
            response = self.handle(message)
            if response is not None:
                self._write(response)
        return 0

    def _write(self, payload: Dict[str, Any]) -> None:
        assert self.out is not None
        self.out.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.out.flush()

    @staticmethod
    def _read_messages(stream: TextIO) -> Iterable[Any]:
        """Yield every JSON value, tolerating multiple values per line."""
        decoder = json.JSONDecoder()
        buffer = ""
        while True:
            chunk = stream.readline()
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
                except json.JSONDecodeError:
                    # Incomplete value: wait for more input.
                    buffer = stripped
                    break
                yield value
                buffer = stripped[end:]

    # -- dispatch -------------------------------------------------------------

    def handle(self, message: Any) -> Optional[Dict[str, Any]]:
        if message is None:
            return self._error(None, -32700, "parse error: not valid JSON")
        if not isinstance(message, dict):
            return self._error(None, -32600, "invalid request: expected a JSON object")

        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        if not isinstance(method, str):
            # A response object (has result/error) is not ours to handle.
            if "result" in message or "error" in message:
                return None
            return self._error(msg_id, -32600, "invalid request: missing method")

        if msg_id is None and method.startswith("notifications/"):
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
               hint: Optional[str] = None, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        error: Dict[str, Any] = {"code": code, "message": message}
        merged = dict(data or {})
        if hint:
            merged["hint"] = hint
        if merged:
            error["data"] = merged
        return {"jsonrpc": "2.0", "id": msg_id, "error": error}

    def _call_method(self, method: str, params: Dict[str, Any]) -> Any:
        if method == "initialize":
            return self._initialize(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": tool_descriptors()}
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

    def _initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        requested = str(params.get("protocolVersion") or "").strip()
        self.protocol_version = requested if requested in PROTOCOL_VERSIONS \
            else DEFAULT_PROTOCOL_VERSION
        self.initialized = True
        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": SERVER_NAME,
                "title": "TP-Link Omada SDN (read-only)",
                "version": __version__,
            },
            "instructions": INSTRUCTIONS,
        }

    # -- tools ----------------------------------------------------------------

    def _tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        name = str(params.get("name") or "").strip()
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise RpcError(-32602, "invalid params: arguments must be an object")
        if not name:
            raise RpcError(-32602, "invalid params: tool name is required")

        spec: Optional[Tool] = get_tool(name)

        # Fail closed: in read-only mode anything not declared read-only is
        # refused, including names this build does not know.
        if self.config.read_only and (spec is None or not spec.read_only):
            raise RpcError(
                -32003,
                f"OMADA_READ_ONLY=true refuses the non-read-only tool {name!r}",
                hint=("unset OMADA_READ_ONLY (or set it to false) to allow write "
                      "operations; read-only tools: "
                      + ", ".join(sorted(TOOL_MAP))),
                data={"tool": name, "readOnly": True},
            )

        if spec is None:
            raise RpcError(
                -32601,
                f"unknown tool: {name}",
                hint="call tools/list; available: " + ", ".join(sorted(TOOL_MAP)),
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

        rendered = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        result: Dict[str, Any] = {
            "content": [{"type": "text", "text": rendered}],
            "isError": False,
        }
        if isinstance(data, dict):
            result["structuredContent"] = data
        elif isinstance(data, list) and all(isinstance(item, dict) for item in data):
            # Keep structuredContent an object, as the spec requires.
            result["structuredContent"] = {"items": data, "count": len(data)}
        return result

    @staticmethod
    def _check_arguments(spec: Tool, arguments: Dict[str, Any]) -> None:
        schema = spec.input_schema or {}
        required = schema.get("required") or []
        missing = [key for key in required if arguments.get(key) in (None, "")]
        if missing:
            raise RpcError(
                -32602,
                f"{spec.name}: missing required argument(s): {', '.join(missing)}",
                hint="inputSchema: " + json.dumps(schema.get("properties") or {}),
            )
        limit = arguments.get("limit")
        if limit is not None and "limit" in (schema.get("properties") or {}):
            try:
                arguments["limit"] = max(1, min(5000, int(limit)))
            except (TypeError, ValueError):
                raise RpcError(-32602, "limit must be an integer between 1 and 5000") from None
        code = arguments.get("code")
        if code is not None and "code" in (schema.get("properties") or {}):
            if isinstance(code, bool):
                raise RpcError(-32602, "code must be an integer")
            try:
                arguments["code"] = int(code)
            except (TypeError, ValueError):
                raise RpcError(-32602, "code must be an integer") from None
