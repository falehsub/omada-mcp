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
    "Read-only access by default to a TP-Link Omada SDN controller through its Web API v2. "
    "Thirty-three read-only tools are always available, including get_config_snapshot, network_audit, "
    "get_switch_ports, get_ap_radios, get_wan_status, get_topology, diagnose_client, diagnose_wan, "
    "get_site_info, list_devices / list_clients, get_device / get_client, and explain_error. "
    "Optional write tools remain hidden and disabled unless both OMADA_READ_ONLY=false and "
    "OMADA_WRITE_TOOLS explicitly allowlist them. Timestamps are UTC ISO-8601. Error messages "
    "include the controller's numeric errorCode and a fix hint."
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

    def _initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
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

    def _tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        name = str(params.get("name") or "").strip()
        raw_arguments = params.get("arguments")
        if raw_arguments is None:
            arguments: Dict[str, Any] = {}
        elif isinstance(raw_arguments, dict):
            arguments = dict(raw_arguments)
        else:
            raise RpcError(-32602, "invalid params: arguments must be an object")
        if not name:
            raise RpcError(-32602, "invalid params: tool name is required")

        spec: Optional[Tool] = get_tool(name)

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
        props = schema.get("properties") or {}

        unknown = sorted(k for k in arguments if k not in props)
        if unknown:
            camel_lookup = {
                "".join(ch for ch in prop.lower() if ch.isalnum()): prop
                for prop in props
            }
            fixes = []
            for k in unknown:
                norm_k = "".join(ch for ch in k.lower() if ch.isalnum())
                if norm_k in camel_lookup:
                    fixes.append(f"use {camel_lookup[norm_k]!r} instead of {k!r}")
            hint = "; ".join(fixes) if fixes else "allowed arguments: " + ", ".join(sorted(props))
            raise RpcError(
                -32602,
                f"{spec.name}: unexpected argument(s): {', '.join(unknown)}",
                hint=hint,
            )

        if not spec.read_only and "dryRun" in props and "dryRun" not in arguments:
            arguments["dryRun"] = True

        required = schema.get("required") or []
        missing = [
            key for key in required
            if key not in arguments or arguments[key] is None or arguments[key] == ""
        ]
        if missing:
            raise RpcError(
                -32602,
                f"{spec.name}: missing required argument(s): {', '.join(missing)}",
                hint="inputSchema: " + json.dumps(props),
            )

        for key, val in list(arguments.items()):
            prop_schema = props.get(key) or {}
            ptype = prop_schema.get("type")
            if val is None:
                if ptype == "boolean" or key in required:
                    raise RpcError(-32602, f"{spec.name}: {key} must not be null")
                continue

            if key == "limit":
                if isinstance(val, bool):
                    raise RpcError(-32602, "limit must be an integer between 1 and 5000")
                try:
                    arguments["limit"] = max(1, min(5000, int(val)))
                except (TypeError, ValueError):
                    raise RpcError(-32602, "limit must be an integer between 1 and 5000") from None
                continue

            if key == "code":
                if isinstance(val, bool):
                    raise RpcError(-32602, "code must be an integer")
                try:
                    arguments["code"] = int(val)
                except (TypeError, ValueError):
                    raise RpcError(-32602, "code must be an integer") from None
                continue

            if ptype == "boolean":
                if not isinstance(val, bool):
                    raise RpcError(
                        -32602,
                        f"{spec.name}: {key} must be a boolean",
                        hint=f"pass JSON true or false for {key} (not a string)",
                    )
            elif ptype == "integer":
                if isinstance(val, bool) or not isinstance(val, int):
                    raise RpcError(-32602, f"{spec.name}: {key} must be an integer")
            elif ptype == "number":
                if isinstance(val, bool) or not isinstance(val, (int, float)):
                    raise RpcError(-32602, f"{spec.name}: {key} must be a number")
            elif ptype == "string":
                if not isinstance(val, str):
                    raise RpcError(-32602, f"{spec.name}: {key} must be a string")
            elif ptype == "array":
                if not isinstance(val, list):
                    raise RpcError(-32602, f"{spec.name}: {key} must be an array")
                item_type = (prop_schema.get("items") or {}).get("type")
                if item_type == "integer" and any(isinstance(x, bool) or not isinstance(x, int) for x in val):
                    raise RpcError(-32602, f"{spec.name}: {key} items must be integers")
                if item_type == "string" and any(not isinstance(x, str) for x in val):
                    raise RpcError(-32602, f"{spec.name}: {key} items must be strings")
                if item_type == "object" and any(not isinstance(x, dict) for x in val):
                    raise RpcError(-32602, f"{spec.name}: {key} items must be objects")
            elif ptype == "object":
                if not isinstance(val, dict):
                    raise RpcError(-32602, f"{spec.name}: {key} must be an object")
            elif isinstance(ptype, list):
                allowed_primitives = set(ptype)
                ok = (
                    ("string" in allowed_primitives and isinstance(val, str))
                    or ("integer" in allowed_primitives and isinstance(val, int) and not isinstance(val, bool))
                    or ("boolean" in allowed_primitives and isinstance(val, bool))
                    or ("array" in allowed_primitives and isinstance(val, list))
                    or ("object" in allowed_primitives and isinstance(val, dict))
                )
                if not ok:
                    raise RpcError(
                        -32602,
                        f"{spec.name}: {key} must match type {' or '.join(ptype)}",
                    )

        if not spec.read_only and arguments.get("dryRun") is False:
            conf = arguments.get("confirm")
            if not isinstance(conf, str) or not conf.strip():
                raise RpcError(
                    -32602,
                    f"{spec.name}: confirm is required when dryRun is false",
                    hint="run with dryRun=true first to inspect the diff and obtain confirmToken",
                )
