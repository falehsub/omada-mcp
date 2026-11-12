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

import os
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

__all__ = [
    "Config",
    "ConfigError",
    "DEFAULT_ENV_FILENAME",
    "DEFAULT_HTTPS_PORT",
    "DEFAULT_HTTP_PORT",
    "candidate_env_files",
    "load_config",
    "normalize_base_url",
    "parse_bool",
    "parse_env_file",
    "parse_env_text",
]

#: Evaluated once at import; tests patch it to exercise the Windows branch.
_IS_WINDOWS = os.name == "nt"

DEFAULT_ENV_FILENAME = ".env"
DEFAULT_HTTPS_PORT = 8043
DEFAULT_HTTP_PORT = 8088
DEFAULT_TIMEOUT = 30.0
DEFAULT_MIN_INTERVAL = 0.25

_TRUE = {"1", "true", "yes", "on", "y", "t"}
_FALSE = {"0", "false", "no", "off", "n", "f"}

_ASSIGN_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


class ConfigError(RuntimeError):
    """Raised when configuration is missing or malformed.

    Every raise carries an actionable ``hint`` so ``--doctor`` and the CLI can
    print the exact fix instead of a traceback.
    """

    def __init__(self, message: str, hint: Optional[str] = None, key: Optional[str] = None):
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
    site_id: Optional[str] = None
    site_name: Optional[str] = None
    ca_bundle: Optional[Path] = None
    verify_ssl: bool = True
    strict_x509: bool = True
    read_only: bool = False
    use_system_proxy: bool = False
    timeout: float = DEFAULT_TIMEOUT
    min_interval: float = DEFAULT_MIN_INTERVAL
    env_file: Optional[Path] = None
    sources: Dict[str, str] = field(default_factory=dict)

    # -- presentation helpers -------------------------------------------------

    def masked(self) -> Dict[str, object]:
        """Config as a dict safe to print: never exposes the password."""
        return {
            "base_url": self.base_url,
            "username": self.username,
            "password": "set (%d chars)" % len(self.password) if self.password else "missing",
            "site_id": self.site_id,
            "site_name": self.site_name,
            "ca_bundle": str(self.ca_bundle) if self.ca_bundle else None,
            "verify_ssl": self.verify_ssl,
            "strict_x509": self.strict_x509,
            "read_only": self.read_only,
            "use_system_proxy": self.use_system_proxy,
            "timeout": self.timeout,
            "min_interval": self.min_interval,
            "env_file": str(self.env_file) if self.env_file else None,
        }


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


def parse_env_text(text: str) -> Dict[str, str]:
    """Parse dotenv text into a dict (last assignment wins)."""
    values: Dict[str, str] = {}
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


def parse_env_file(path: os.PathLike | str) -> Dict[str, str]:
    """Parse a dotenv file; missing or unreadable files yield ``{}``."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return parse_env_text(handle.read())
    except (OSError, UnicodeDecodeError):
        return {}


def _xdg_config_home(environ: Optional[Mapping[str, str]] = None) -> Path:
    env = os.environ if environ is None else environ
    explicit = env.get("XDG_CONFIG_HOME")
    if explicit:
        return Path(explicit).expanduser()
    return Path.home() / ".config"


def _appdata_dir(environ: Optional[Mapping[str, str]] = None) -> Optional[Path]:
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
    cwd: Optional[os.PathLike | str] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> List[Tuple[str, Path]]:
    """Ordered ``(origin, path)`` candidates, highest priority first.

    On Windows ``%APPDATA%\\omada-mcp\\.env`` comes before the POSIX-style
    ``~/.config/omada-mcp/.env``, because ``%APPDATA%`` is where a Windows user
    expects a per-user config to live; the POSIX path stays as a fallback so a
    checkout shared with WSL keeps working.
    """
    env = os.environ if environ is None else environ
    candidates: List[Tuple[str, Path]] = []
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
    parts = urllib.parse.urlsplit(text)
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
    port = parts.port or (DEFAULT_HTTPS_PORT if scheme == "https" else DEFAULT_HTTP_PORT)
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


def _merged_environment(
    environ: Mapping[str, str],
    cwd: Optional[os.PathLike | str] = None,
) -> Tuple[Dict[str, str], Dict[str, str], Optional[Path]]:
    """Merge dotenv values with the process environment.

    Returns ``(values, sources, env_file)`` where ``sources`` maps each key to a
    human-readable origin used by ``--doctor``.
    """
    values: Dict[str, str] = {}
    sources: Dict[str, str] = {}
    env_file: Optional[Path] = None

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
    return values, sources, env_file


def load_config(
    environ: Optional[Mapping[str, str]] = None,
    cwd: Optional[os.PathLike | str] = None,
) -> Config:
    """Build a validated :class:`Config` from the environment and dotenv files."""
    environ = dict(os.environ if environ is None else environ)
    values, sources, env_file = _merged_environment(environ, cwd)

    missing = [key for key in ("OMADA_BASE_URL", "OMADA_USERNAME", "OMADA_PASSWORD")
               if not (values.get(key) or "").strip()]
    if missing:
        where = str(env_file) if env_file else str(Path(cwd or Path.cwd()) / DEFAULT_ENV_FILENAME)
        raise ConfigError(
            "missing required variable(s): " + ", ".join(missing),
            hint=("add them to %s, or export them, or point OMADA_ENV_FILE at your "
                  "dotenv file" % where),
            key=missing[0],
        )

    ca_raw = (values.get("OMADA_CA_BUNDLE") or "").strip()
    ca_bundle: Optional[Path] = None
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
    except ValueError as exc:
        raise ConfigError(
            f"invalid numeric value: {exc}",
            hint="OMADA_TIMEOUT_SECONDS / OMADA_MIN_INTERVAL_SECONDS must be numbers",
        ) from None

    site_id = (values.get("OMADA_SITE_ID") or "").strip() or None
    site_name = (values.get("OMADA_SITE_NAME") or "").strip() or None

    return Config(
        base_url=normalize_base_url(values["OMADA_BASE_URL"]),
        username=values["OMADA_USERNAME"].strip(),
        password=values["OMADA_PASSWORD"],
        site_id=site_id,
        site_name=site_name,
        ca_bundle=ca_bundle,
        verify_ssl=parse_bool(values.get("OMADA_VERIFY_SSL"), "OMADA_VERIFY_SSL", True),
        strict_x509=parse_bool(values.get("OMADA_STRICT_X509"), "OMADA_STRICT_X509", True),
        read_only=parse_bool(values.get("OMADA_READ_ONLY"), "OMADA_READ_ONLY", False),
        use_system_proxy=parse_bool(values.get("OMADA_USE_SYSTEM_PROXY"),
                                    "OMADA_USE_SYSTEM_PROXY", False),
        timeout=timeout,
        min_interval=min_interval,
        env_file=env_file,
        sources=sources,
    )
