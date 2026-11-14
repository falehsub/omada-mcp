"""Configuration resolution for omada-mcp.

No third-party dependencies: the ``.env`` reader is a small, documented subset of
the format (``KEY=VALUE``, optional ``export`` prefix, single/double quotes,
``#`` comments) so the package keeps a zero-dependency install.

Resolution order, highest priority first:

1. process environment (``export OMADA_BASE_URL=...``)
2. ``OMADA_ENV_FILE`` -- an explicit path to a dotenv file
3. ``./.env`` -- relative to the current working directory
4. ``%APPDATA%\\omada-mcp\\.env`` (Windows only)
5. ``$XDG_CONFIG_HOME/omada-mcp/.env`` or ``~/.config/omada-mcp/.env``

Values loaded from a file never override a variable that is already set in the
environment, so a shell override always wins.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "Config",
    "ConfigError",
    "DEFAULT_ENV_FILENAME",
    "DEFAULT_HTTPS_PORT",
    "DEFAULT_HTTP_PORT",
    "DEFAULT_WRITE_MIN_INTERVAL",
    "WRITE_TOOL_NAMES",
    "candidate_env_files",
    "default_snapshot_dir",
    "load_config",
    "normalize_base_url",
    "parse_bool",
    "parse_env_file",
    "parse_env_text",
    "parse_management_cidrs",
    "parse_write_tools",
]

#: Evaluated once at import; tests patch it to exercise the Windows branch.
_IS_WINDOWS = os.name == "nt"

DEFAULT_ENV_FILENAME = ".env"
DEFAULT_HTTPS_PORT = 8043
DEFAULT_HTTP_PORT = 8088
DEFAULT_TIMEOUT = 30.0
DEFAULT_MIN_INTERVAL = 0.05
DEFAULT_WRITE_MIN_INTERVAL = 1.0

#: Exact allowlistable write tool names (kept in sync with tools.TOOLS).
WRITE_TOOL_NAMES: tuple[str, ...] = (
    "set_client_fixed_ip",
    "release_client_fixed_ip",
    "upsert_dhcp_reservation",
    "delete_dhcp_reservation",
    "set_vlan_dhcp_pools",
    "set_vlan_isolation",
    "create_lan_network",
    "update_lan_network",
    "delete_lan_network",
    "create_ip_group",
    "replace_ip_group",
    "delete_ip_group",
    "create_gateway_acl",
    "update_gateway_acl",
    "delete_gateway_acl",
    "set_acl_rule_status",
    "create_ssid",
    "update_ssid",
    "delete_ssid",
    "upsert_port_forward",
    "delete_port_forward",
    "upsert_static_route",
    "delete_static_route",
    "upsert_mdns_rule",
    "delete_mdns_rule",
    "set_upnp",
    "set_client_blocked",
    "reconnect_client",
    "update_client",
    "update_device",
    "reboot_device",
    "rollback_from_snapshot",
    "update_switch_port",
    "cycle_poe_port",
    "upsert_port_profile",
    "delete_port_profile",
    "update_ap_radio",
    "start_rf_scan",
    "assign_ap_wlan_group",
    "upsert_policy_route",
    "delete_policy_route",
    "upsert_lan_dns_rule",
    "delete_lan_dns_rule",
    "create_switch_acl",
    "create_eap_acl",
    "set_client_lock_to_ap",
    "set_client_rate_limit",
)

_READ_ONLY_TOOL_NAMES = frozenset({
    "list_devices",
    "list_clients",
    "list_wifi_clients",
    "list_wired_clients",
    "search_clients",
    "get_device",
    "get_client",
    "list_wlans",
    "list_lan_networks",
    "list_dhcp_reservations",
    "list_acls",
    "list_ip_groups",
    "list_port_forwards",
    "list_static_routes",
    "get_network_services",
    "list_logs",
    "get_site_info",
    "network_audit",
    "explain_error",
    "get_config_snapshot",
    "get_switch_ports",
    "get_ap_radios",
    "get_rf_scan",
    "get_wan_status",
    "list_vpn_tunnels",
    "get_topology",
    "get_security_status",
    "diagnose_client",
    "diagnose_wan",
    "list_port_profiles",
    "list_wlan_groups",
    "list_policy_routes",
    "list_lan_dns_rules",
})

_TRUE = {"1", "true", "yes", "on", "y", "t"}
_FALSE = {"0", "false", "no", "off", "n", "f"}

_ASSIGN_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


class ConfigError(RuntimeError):
    """Raised when configuration is missing or malformed.

    Every raise carries an actionable ``hint`` so ``--doctor`` and the CLI can
    print the exact fix instead of a traceback.
    """

    def __init__(self, message: str, hint: str | None = None, key: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.key = key

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.message} (fix: {self.hint})" if self.hint else self.message


@dataclass
class Config:
    """Validated runtime configuration."""

    base_url: str
    username: str
    password: str = field(repr=False)
    site_id: str | None = None
    site_name: str | None = None
    ca_bundle: Path | None = None
    verify_ssl: bool = True
    strict_x509: bool = True
    tls_server_name: str | None = None
    read_only: bool = True
    write_tools: tuple[str, ...] = ()
    snapshot_dir: Path | None = None
    snapshot_origin: str = "default"
    write_min_interval: float = DEFAULT_WRITE_MIN_INTERVAL
    management_cidrs: tuple[str, ...] = ()
    use_system_proxy: bool = False
    timeout: float = DEFAULT_TIMEOUT
    min_interval: float = DEFAULT_MIN_INTERVAL
    schema_mode: str = "slim"
    tool_categories: tuple[str, ...] = ()
    compact_output: bool = True
    env_file: Path | None = None
    env_origin: str = "environment"
    sources: dict[str, str] = field(default_factory=dict)

    # -- presentation helpers -------------------------------------------------

    def masked(self) -> dict[str, object]:
        """Config as a dict safe to print: never exposes the password."""
        return {
            "base_url": self.base_url,
            "username": self.username,
            "password": f"set ({len(self.password)} chars)" if self.password else "missing",
            "site_id": self.site_id,
            "site_name": self.site_name,
            "ca_bundle": str(self.ca_bundle) if self.ca_bundle else None,
            "verify_ssl": self.verify_ssl,
            "strict_x509": self.strict_x509,
            "tls_server_name": self.tls_server_name,
            "read_only": self.read_only,
            "write_tools": list(self.write_tools),
            "snapshot_dir": str(self.snapshot_dir) if self.snapshot_dir else None,
            "write_min_interval": self.write_min_interval,
            "management_cidrs": list(self.management_cidrs),
            "use_system_proxy": self.use_system_proxy,
            "timeout": self.timeout,
            "min_interval": self.min_interval,
            "env_file": str(self.env_file) if self.env_file else None,
            "env_origin": self.env_origin,
        }


def parse_write_tools(raw: str | None) -> tuple[str, ...]:
    """Parse ``OMADA_WRITE_TOOLS`` as an explicit comma-separated allowlist.

    Wildcards (``*``, ``?``, ``[``) and ``all`` are refused so writes are always
    explicitly enumerated by exact tool name.
    """
    text = (raw or "").strip()
    if not text:
        return ()
    valid = set(WRITE_TOOL_NAMES)
    seen = set()
    tools: list[str] = []
    for part in text.split(","):
        name = part.strip()
        if not name:
            raise ConfigError(
                f"OMADA_WRITE_TOOLS={raw!r} contains an empty entry",
                hint="use a comma-separated list of exact write tool names, e.g. "
                     + ", ".join(WRITE_TOOL_NAMES[:2]),
                key="OMADA_WRITE_TOOLS",
            )
        lowered = name.lower()
        if lowered == "all" or any(ch in name for ch in ("*", "?", "[")):
            raise ConfigError(
                f"OMADA_WRITE_TOOLS={name!r} uses a wildcard or 'all', which is forbidden",
                hint="list exact write tool names only: " + ", ".join(WRITE_TOOL_NAMES),
                key="OMADA_WRITE_TOOLS",
            )
        if name in _READ_ONLY_TOOL_NAMES:
            raise ConfigError(
                f"OMADA_WRITE_TOOLS={name!r} is a read-only tool, not a write tool",
                hint="read-only tools are always available; valid write tools: "
                     + ", ".join(WRITE_TOOL_NAMES),
                key="OMADA_WRITE_TOOLS",
            )
        if name not in valid:
            raise ConfigError(
                f"OMADA_WRITE_TOOLS contains unknown write tool {name!r}",
                hint="valid write tools: " + ", ".join(WRITE_TOOL_NAMES),
                key="OMADA_WRITE_TOOLS",
            )
        if name not in seen:
            seen.add(name)
            tools.append(name)
    return tuple(tools)


def parse_management_cidrs(raw: str | None) -> tuple[str, ...]:
    """Parse ``OMADA_MANAGEMENT_CIDRS`` into canonical IPv4 network strings."""
    text = (raw or "").strip()
    if not text:
        return ()
    cidrs: list[str] = []
    for part in text.split(","):
        item = part.strip()
        if not item:
            continue
        try:
            net = ipaddress.IPv4Network(item, strict=False)
        except ValueError as exc:
            raise ConfigError(
                f"OMADA_MANAGEMENT_CIDRS has invalid IPv4/CIDR {item!r}: {exc}",
                hint="use comma-separated IPv4 addresses or CIDRs (e.g. 192.168.1.50,192.168.1.0/24)",
                key="OMADA_MANAGEMENT_CIDRS",
            ) from None
        canon = str(net)
        if canon not in cidrs:
            cidrs.append(canon)
    return tuple(cidrs)


def default_snapshot_dir(environ: Mapping[str, str] | None = None) -> Path:
    """Default per-user snapshot directory (``~/.local/state/omada-mcp/snapshots``)."""
    env = os.environ if environ is None else environ
    state_home = (env.get("XDG_STATE_HOME") or "").strip()
    if state_home:
        return Path(state_home).expanduser() / "omada-mcp" / "snapshots"
    if environ is not None:
        home = (env.get("HOME") or env.get("USERPROFILE") or "").strip()
        if home:
            return Path(home).expanduser() / ".local" / "state" / "omada-mcp" / "snapshots"
        if _IS_WINDOWS:
            local_app = (env.get("LOCALAPPDATA") or "").strip()
            if local_app:
                return Path(local_app) / "omada-mcp" / "snapshots"
        return Path("/nonexistent-xdg-state-home") / "omada-mcp" / "snapshots"
    return Path.home() / ".local" / "state" / "omada-mcp" / "snapshots"


VALID_SCHEMA_MODES: tuple[str, ...] = ("slim", "full")
VALID_TOOL_CATEGORIES: tuple[str, ...] = (
    "core", "diagnostics", "switch", "wifi", "routing", "security", "rollback",
)


def parse_schema_mode(raw: str | None) -> str:
    """Parse ``OMADA_SCHEMA_MODE`` (``slim`` [default] or ``full``)."""
    text = (raw or "").strip().lower()
    if not text:
        return "slim"
    if text in VALID_SCHEMA_MODES:
        return text
    raise ConfigError(
        f"OMADA_SCHEMA_MODE={raw!r} must be 'slim' or 'full'",
        hint="use OMADA_SCHEMA_MODE=slim (default) or OMADA_SCHEMA_MODE=full",
        key="OMADA_SCHEMA_MODE",
    )


def parse_tool_categories(raw: str | None) -> tuple[str, ...]:
    """Parse ``OMADA_TOOL_CATEGORIES`` comma-separated filter list."""
    if not raw or not str(raw).strip():
        return ()
    seen: set[str] = set()
    parsed: list[str] = []
    for part in str(raw).split(","):
        item = part.strip().lower()
        if not item:
            continue
        if item not in VALID_TOOL_CATEGORIES:
            raise ConfigError(
                f"OMADA_TOOL_CATEGORIES contains unknown category {item!r}",
                hint=f"valid categories: {', '.join(VALID_TOOL_CATEGORIES)}",
                key="OMADA_TOOL_CATEGORIES",
            )
        if item not in seen:
            seen.add(item)
            parsed.append(item)
    return tuple(parsed)


def parse_bool(raw: object, key: str, default: bool = False) -> bool:
    """Parse a human-written boolean, raising a ConfigError with the bad value."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return default
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ConfigError(
        f"{key}={raw!r} is not a boolean",
        hint=f"use {key}=true or {key}=false",
        key=key,
    )


def _strip_inline_comment(value: str) -> str:
    """Drop a trailing ``# comment`` only when the value is unquoted."""
    if value and value[0] in ("'", '"'):
        return value
    out = []
    prev = " "
    for ch in value:
        if ch == "#" and prev in (" ", "\t"):
            break
        out.append(ch)
        prev = ch
    return "".join(out).strip()


def _unquote(value: str) -> str:
    value = _strip_inline_comment(value.strip())
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        inner = value[1:-1]
        if value[0] == '"':
            inner = inner.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")
        return inner
    if value.startswith('"') or value.startswith("'"):
        # Unterminated quote: be forgiving but strip the opener.
        return value[1:]
    return value


def parse_env_text(text: str) -> dict[str, str]:
    """Parse dotenv text into a dict (last assignment wins)."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        match = _ASSIGN_RE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        values[key] = _unquote(value)
    return values


def parse_env_file(path: os.PathLike | str) -> dict[str, str]:
    """Parse a dotenv file; missing or unreadable files yield ``{}``.

    ``utf-8-sig`` strips a leading BOM: Windows PowerShell 5.1
    (``Set-Content -Encoding utf8``) and older Notepad write one, which would
    otherwise turn the first key into ``\\ufeffOMADA_BASE_URL`` and surface as
    a misleading "missing OMADA_BASE_URL" error.
    """
    try:
        with open(path, encoding="utf-8-sig") as handle:
            return parse_env_text(handle.read())
    except (OSError, UnicodeDecodeError):
        return {}


def _xdg_config_home(environ: Mapping[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    explicit = env.get("XDG_CONFIG_HOME")
    if explicit:
        return Path(explicit).expanduser()
    if environ is not None:
        home = (env.get("HOME") or env.get("USERPROFILE") or "").strip()
        if home:
            return Path(home).expanduser() / ".config"
        # An explicitly isolated environ without HOME/XDG_CONFIG_HOME must not
        # fall back to the host user's real ~/.config directory.
        return Path("/nonexistent-xdg-config-home")
    return Path.home() / ".config"


def _appdata_dir(environ: Mapping[str, str] | None = None) -> Path | None:
    """``%APPDATA%`` on Windows, else ``None``.

    Kept separate from :func:`candidate_env_files` so the Windows branch is
    testable on any OS by patching ``_IS_WINDOWS``.
    """
    env = os.environ if environ is None else environ
    raw = (env.get("APPDATA") or "").strip()
    if not raw:
        return None
    return Path(raw)


def candidate_env_files(
    cwd: os.PathLike | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> list[tuple[str, Path]]:
    """Ordered ``(origin, path)`` candidates, highest priority first.

    On Windows ``%APPDATA%\\omada-mcp\\.env`` comes before the POSIX-style
    ``~/.config/omada-mcp/.env``, because ``%APPDATA%`` is where a Windows user
    expects a per-user config to live; the POSIX path stays as a fallback so a
    checkout shared with WSL keeps working.
    """
    env = os.environ if environ is None else environ
    candidates: list[tuple[str, Path]] = []
    explicit = env.get("OMADA_ENV_FILE")
    if explicit:
        candidates.append(("OMADA_ENV_FILE", Path(explicit).expanduser()))
    base = Path(cwd) if cwd is not None else Path.cwd()
    candidates.append(("cwd/.env", base / DEFAULT_ENV_FILENAME))
    if _IS_WINDOWS:
        appdata = _appdata_dir(env)
        if appdata is not None:
            candidates.append(("%APPDATA%/omada-mcp/.env",
                               appdata / "omada-mcp" / DEFAULT_ENV_FILENAME))
    candidates.append(("~/.config/omada-mcp/.env",
                       _xdg_config_home(env) / "omada-mcp" / DEFAULT_ENV_FILENAME))
    return candidates


def normalize_base_url(raw: str) -> str:
    """Return a canonical controller base URL without a trailing slash.

    A missing scheme is assumed to be ``https`` and a missing port falls back to
    the controller defaults (8043 for https, 8088 for http) so that
    ``OMADA_BASE_URL=omada.lan`` works.
    """
    text = (raw or "").strip()
    if not text:
        raise ConfigError("OMADA_BASE_URL is empty",
                          hint="set OMADA_BASE_URL=https://<controller-host>:8043",
                          key="OMADA_BASE_URL")
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urllib.parse.urlsplit(text)
        parsed_port = parts.port
    except ValueError:
        raise ConfigError(
            "OMADA_BASE_URL has an invalid host or port",
            hint="use https://<controller-host>:8043 with a port between 1 and 65535",
            key="OMADA_BASE_URL",
        ) from None
    if parsed_port == 0:
        raise ConfigError("OMADA_BASE_URL port must be between 1 and 65535", key="OMADA_BASE_URL")
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ConfigError(
            f"OMADA_BASE_URL has unsupported scheme {scheme!r}",
            hint="use https://<controller-host>:8043 (the controller's web port)",
            key="OMADA_BASE_URL",
        )
    host = parts.hostname
    if not host:
        raise ConfigError(f"OMADA_BASE_URL={raw!r} has no host part",
                          hint="use https://<controller-host>:8043",
                          key="OMADA_BASE_URL")
    port = parsed_port or (DEFAULT_HTTPS_PORT if scheme == "https" else DEFAULT_HTTP_PORT)
    netloc = f"[{host}]" if ":" in host else host
    netloc = f"{netloc}:{port}"
    if parts.username or parts.password:
        raise ConfigError(
            "OMADA_BASE_URL must not embed credentials",
            hint="put the account in OMADA_USERNAME / OMADA_PASSWORD instead",
            key="OMADA_BASE_URL",
        )
    path = parts.path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


_ORIGIN_LABELS: dict[str, str] = {
    "OMADA_ENV_FILE": "OMADA_ENV_FILE",
    "cwd/.env": "cwd",
    "%APPDATA%/omada-mcp/.env": "appdata",
    "~/.config/omada-mcp/.env": "xdg",
}


def _origin_label(origin: str | None) -> str:
    if not origin:
        return "environment"
    return _ORIGIN_LABELS.get(origin, "environment")


def _merged_environment(
    environ: Mapping[str, str],
    cwd: os.PathLike | str | None = None,
) -> tuple[dict[str, str], dict[str, str], Path | None, str]:
    """Merge dotenv values with the process environment.

    Returns ``(values, sources, env_file, env_origin)`` where ``sources`` maps each
    key to a human-readable origin and ``env_origin`` is a path-free label
    (``OMADA_ENV_FILE``, ``cwd``, ``appdata``, ``xdg``, or ``environment``).
    """
    values: dict[str, str] = {}
    sources: dict[str, str] = {}
    env_file: Path | None = None
    env_origin = "environment"

    for origin, path in candidate_env_files(cwd, environ):
        if not path.is_file():
            if origin == "OMADA_ENV_FILE":
                raise ConfigError(
                    f"OMADA_ENV_FILE points to a missing file: {path}",
                    hint="create that file or unset OMADA_ENV_FILE to use ./.env",
                    key="OMADA_ENV_FILE",
                )
            continue
        file_values = parse_env_file(path)
        if file_values:
            env_file = path
            env_origin = _origin_label(origin)
            for key, value in file_values.items():
                if key not in values:
                    values[key] = value
                    sources[key] = str(path)
        if origin == "OMADA_ENV_FILE":
            break  # an explicit file is authoritative for dotenv lookup

    for key, value in environ.items():
        if key.startswith("OMADA_"):
            values[key] = value
            sources[key] = "environment"
    return values, sources, env_file, env_origin


def load_config(
    environ: Mapping[str, str] | None = None,
    cwd: os.PathLike | str | None = None,
) -> Config:
    """Build a validated :class:`Config` from the environment and dotenv files."""
    environ = dict(os.environ if environ is None else environ)
    values, sources, env_file, env_origin = _merged_environment(environ, cwd)

    missing = [key for key in ("OMADA_BASE_URL", "OMADA_USERNAME", "OMADA_PASSWORD")
               if not (values.get(key) or "").strip()]
    if missing:
        where = str(env_file) if env_file else str(Path(cwd or Path.cwd()) / DEFAULT_ENV_FILENAME)
        raise ConfigError(
            "missing required variable(s): " + ", ".join(missing),
            hint=(f"add them to {where}, or export them, or point OMADA_ENV_FILE at your "
                  "dotenv file"),
            key=missing[0],
        )

    ca_raw = (values.get("OMADA_CA_BUNDLE") or "").strip()
    ca_bundle: Path | None = None
    if ca_raw:
        ca_bundle = Path(ca_raw).expanduser()
        if not ca_bundle.is_file():
            raise ConfigError(
                f"OMADA_CA_BUNDLE does not exist: {ca_bundle}",
                hint=("point OMADA_CA_BUNDLE at a PEM bundle containing the controller's "
                      "CA (or export it from the controller UI), or set "
                      "OMADA_VERIFY_SSL=false"),
                key="OMADA_CA_BUNDLE",
            )

    try:
        timeout = float(values.get("OMADA_TIMEOUT_SECONDS") or DEFAULT_TIMEOUT)
        min_interval = float(values.get("OMADA_MIN_INTERVAL_SECONDS") or DEFAULT_MIN_INTERVAL)
        write_min_interval = float(
            values.get("OMADA_WRITE_INTERVAL_SECONDS") or DEFAULT_WRITE_MIN_INTERVAL
        )
    except ValueError as exc:
        raise ConfigError(
            f"invalid numeric value: {exc}",
            hint=("OMADA_TIMEOUT_SECONDS / OMADA_MIN_INTERVAL_SECONDS / "
                  "OMADA_WRITE_INTERVAL_SECONDS must be numbers"),
        ) from None
    for key, value, positive in (
        ("OMADA_TIMEOUT_SECONDS", timeout, True),
        ("OMADA_MIN_INTERVAL_SECONDS", min_interval, False),
        ("OMADA_WRITE_INTERVAL_SECONDS", write_min_interval, False),
    ):
        if not math.isfinite(value) or value < 0 or (positive and value == 0):
            bound = "greater than zero" if positive else "non-negative"
            raise ConfigError(
                f"{key} must be finite and {bound}",
                hint=f"set {key} to a finite {'positive' if positive else 'non-negative'} number",
                key=key,
            )

    site_id = (values.get("OMADA_SITE_ID") or "").strip() or None
    site_name = (values.get("OMADA_SITE_NAME") or "").strip() or None
    tls_server_name = (values.get("OMADA_TLS_SERVER_NAME") or "").strip() or None
    write_tools = parse_write_tools(values.get("OMADA_WRITE_TOOLS"))
    management_cidrs = parse_management_cidrs(values.get("OMADA_MANAGEMENT_CIDRS"))

    snap_raw = (values.get("OMADA_SNAPSHOT_DIR") or "").strip()
    if snap_raw:
        snapshot_dir = Path(snap_raw).expanduser()
        snapshot_origin = "OMADA_SNAPSHOT_DIR"
    else:
        snapshot_dir = default_snapshot_dir(environ)
        snapshot_origin = "default"

    return Config(
        base_url=normalize_base_url(values["OMADA_BASE_URL"]),
        username=values["OMADA_USERNAME"].strip(),
        password=values["OMADA_PASSWORD"],
        site_id=site_id,
        site_name=site_name,
        ca_bundle=ca_bundle,
        verify_ssl=parse_bool(values.get("OMADA_VERIFY_SSL"), "OMADA_VERIFY_SSL", True),
        strict_x509=parse_bool(values.get("OMADA_STRICT_X509"), "OMADA_STRICT_X509", True),
        tls_server_name=tls_server_name,
        read_only=parse_bool(values.get("OMADA_READ_ONLY"), "OMADA_READ_ONLY", True),
        write_tools=write_tools,
        snapshot_dir=snapshot_dir,
        snapshot_origin=snapshot_origin,
        write_min_interval=write_min_interval,
        management_cidrs=management_cidrs,
        use_system_proxy=parse_bool(values.get("OMADA_USE_SYSTEM_PROXY"),
                                    "OMADA_USE_SYSTEM_PROXY", False),
        timeout=timeout,
        min_interval=min_interval,
        schema_mode=parse_schema_mode(values.get("OMADA_SCHEMA_MODE")),
        tool_categories=parse_tool_categories(values.get("OMADA_TOOL_CATEGORIES")),
        compact_output=parse_bool(values.get("OMADA_COMPACT_OUTPUT"),
                                  "OMADA_COMPACT_OUTPUT", True),
        env_file=env_file,
        env_origin=env_origin,
        sources=sources,
    )
