"""HTTP/1.1 pooled keep-alive transport, TLS context, and controller classification."""

from __future__ import annotations

import contextlib
import http.client
import http.cookiejar
import re
import select
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from .config import Config
from .errors import OmadaError

__all__ = [
    "AuthInfo",
    "SESSION_COOKIE_NAMES",
    "SiteInfo",
    "UrllibTransport",
    "build_ssl_context",
    "classify_controller_family",
]

#: Session cookies issued by Omada controllers across v5.x and v6.x builds.
SESSION_COOKIE_NAMES: tuple[str, ...] = ("TPOMADA_SESSIONID", "TPEAP_SESSIONID")

#: Controllers report the account role three different ways depending on build:
#: ``roleName`` (6.2+), an integer ``privilege`` (5.x), or a ``privilege`` object
#: carrying only the site scope (6.2 with a local account). All three are folded
#: into one readable label plus an optional scope string.
_PRIVILEGE_LABELS = {0: "viewer", 1: "admin", 2: "owner"}


@dataclass(frozen=True)
class SiteInfo:
    """Resolved site: the controller's internal hex id plus its display name."""

    site_id: str
    name: str
    index: int = 0
    total: int = 1
    requested: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.site_id,
            "name": self.name,
            "index": self.index,
            "total": self.total,
            "requested": self.requested,
        }


@dataclass(frozen=True)
class AuthInfo:
    """Non-secret facts about a successful login."""

    controller_id: str
    controller_version: str
    username: str
    user_id: str | None = None
    privilege: str | None = None
    site_scope: str | None = None
    controller_family: str = "unknown"
    session_cookie: str | None = None


def _describe_privilege(user_result: dict[str, Any]) -> tuple[str | None, str | None]:
    """Fold the three role shapes the controller uses into ``(role, scope)``."""
    if not isinstance(user_result, dict):
        return None, None
    raw = user_result.get("privilege")
    scope: str | None = None
    if isinstance(raw, dict):
        sites = raw.get("sites") or []
        if raw.get("all"):
            scope = "all sites"
        elif sites:
            scope = f"{len(sites)} site(s)"
    role: Any = user_result.get("roleName")
    if not role and isinstance(raw, int):
        role = _PRIVILEGE_LABELS.get(raw, f"level {raw}")
    if not role and isinstance(raw, str) and raw:
        role = raw
    if not role:
        fallback = user_result.get("role") or user_result.get("roleId") or user_result.get("type")
        if fallback not in (None, ""):
            role = f"type {fallback}"
    return (str(role) if role is not None else None), scope


def classify_controller_family(
    info: Mapping[str, Any],
    session_cookie: str | None = None,
) -> str:
    """Classify controller family such as ``software-6.x`` or ``hardware-5.x``."""
    hardware_flag = info.get("hardware")
    model_hint = " ".join(
        str(info.get(k) or "")
        for k in ("model", "deviceModel", "omadacCategory", "controllerType")
    ).lower()
    if (
        hardware_flag is True
        or isinstance(hardware_flag, dict)
        or any(tag in model_hint for tag in ("oc200", "oc300", "oc400", "hardware"))
    ):
        kind = "hardware"
    else:
        kind = "software"

    version_str = str(info.get("controllerVer") or info.get("version") or "").strip()
    match = re.match(r"^(\d+)", version_str)
    if match:
        ver_family = f"{match.group(1)}.x"
    elif session_cookie == "TPEAP_SESSIONID":
        ver_family = "5.x"
    else:
        ver_family = "unknown"

    if ver_family == "unknown":
        return f"{kind}-unknown" if kind == "hardware" else "unknown"
    return f"{kind}-{ver_family}"


class _CookieResponseAdapter:
    """Minimal ``urllib`` response adapter for ``http.cookiejar.CookieJar``."""

    def __init__(self, headers: Any) -> None:
        self._headers = headers

    def info(self) -> Any:
        return self._headers


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return redirects to the API layer without forwarding authentication headers."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    """HTTP transport over pooled HTTP/1.1 keep-alive connections and ``CookieJar``.

    System proxies are **disabled by default**. On Windows, :mod:`urllib` picks
    up the WinINET/registry proxy configuration; routing a controller call
    through a corporate proxy produces confusing timeouts for an address that is
    one hop away. Set ``OMADA_USE_SYSTEM_PROXY=true`` when the proxy is genuinely
    required (an out-of-band management route, for example); when a matching
    system proxy applies, requests fall back to :attr:`opener`.
    """

    def __init__(self, ssl_context: ssl.SSLContext, timeout: float = 30.0,
                 use_system_proxy: bool = False):
        self.cookie_jar = http.cookiejar.CookieJar()
        self.proxy_handler = urllib.request.ProxyHandler() if use_system_proxy \
            else urllib.request.ProxyHandler({})
        self.proxy_mode = "system" if use_system_proxy else "disabled"
        self.opener = urllib.request.build_opener(
            self.proxy_handler,
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl_context),
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
        )
        self.timeout = timeout
        self._ssl_context = ssl_context
        self._use_system_proxy = bool(use_system_proxy)
        self._conn_lock = threading.RLock()
        self._pool: dict[tuple[str, str, int], http.client.HTTPConnection] = {}
        self.connections_created = 0
        self.requests_reused = 0

    def _should_use_opener(self, scheme: str, host: str, port: int | None) -> bool:
        if not self._use_system_proxy:
            return False
        proxies = getattr(self.proxy_handler, "proxies", None) or {}
        if scheme not in proxies and "all" not in proxies:
            return False
        netloc = f"[{host}]" if ":" in host else host
        if port is not None:
            netloc = f"{netloc}:{port}"
        try:
            return not urllib.request.proxy_bypass(netloc)
        except OSError:
            return True

    def _new_connection(
        self, scheme: str, host: str, port: int, timeout: float,
    ) -> http.client.HTTPConnection:
        if scheme == "https":
            return http.client.HTTPSConnection(
                host, port, timeout=timeout, context=self._ssl_context,
            )
        return http.client.HTTPConnection(host, port, timeout=timeout)

    def _drop_conn(
        self, key: tuple[str, str, int], conn: http.client.HTTPConnection | None,
    ) -> None:
        if self._pool.get(key) is conn:
            self._pool.pop(key, None)
        if conn is not None:
            with contextlib.suppress(Exception):  # best-effort socket cleanup
                conn.close()

    @staticmethod
    def _is_socket_readable_eof(sock: Any) -> bool:
        """Detect an already-closed idle socket strictly pre-send via non-blocking select."""
        if sock is None:
            return False
        try:
            fd = sock.fileno()
        except Exception:  # noqa: BLE001
            return False
        if not isinstance(fd, int) or fd < 0:
            return False
        try:
            readable, _, _ = select.select([sock], [], [], 0.0)
            return bool(readable)
        except (OSError, ValueError, TypeError):
            return False

    def close(self) -> None:
        """Close all pooled keep-alive connections."""
        with self._conn_lock:
            for conn in list(self._pool.values()):
                with contextlib.suppress(Exception):
                    conn.close()
            self._pool.clear()

    def _request_via_opener(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        data: bytes | None,
        req_timeout: float,
    ) -> tuple[int, bytes]:
        req = urllib.request.Request(url, method=method, data=data)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            response = self.opener.open(req, timeout=req_timeout)
            return int(response.getcode() or 200), response.read()
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read()

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
        timeout: float | None = None,
    ) -> tuple[int, bytes]:
        """Perform one request, returning ``(status, body)``.

        HTTP error statuses are returned rather than raised: the controller
        frequently answers 4xx/5xx with a useful JSON ``errorCode`` payload.
        """
        req_timeout = timeout or self.timeout
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme.lower()
        host = parts.hostname or ""
        if scheme not in ("http", "https") or not host or self._should_use_opener(scheme, host, parts.port):
            return self._request_via_opener(method, url, headers, data, req_timeout)

        port = parts.port or (443 if scheme == "https" else 80)
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        key = (scheme, host, port)
        method_upper = method.upper()
        idempotent = method_upper in ("GET", "HEAD", "OPTIONS")

        with self._conn_lock:
            for attempt in range(2):
                conn = self._pool.get(key)
                reused = conn is not None
                if conn is not None and self._is_socket_readable_eof(getattr(conn, "sock", None)):
                    # Idle keep-alive socket already closed by peer; recycle strictly pre-send.
                    self._drop_conn(key, conn)
                    conn = None
                    reused = False
                if conn is None:
                    conn = self._new_connection(scheme, host, port, req_timeout)
                    self._pool[key] = conn
                    self.connections_created += 1
                else:
                    conn.timeout = req_timeout

                # Pre-send connect step: safe to reopen once on failure for any method.
                try:
                    if getattr(conn, "sock", None) is None:
                        conn.connect()
                except (
                    http.client.HTTPException,
                    ConnectionResetError,
                    BrokenPipeError,
                    OSError,
                ):
                    self._drop_conn(key, conn)
                    if reused and attempt == 0:
                        continue
                    raise

                cookie_req = urllib.request.Request(url, method=method_upper)
                self.cookie_jar.add_cookie_header(cookie_req)
                send_headers: dict[str, str] = dict(headers or {})
                header_lower = {k.lower() for k in send_headers}
                if "connection" not in header_lower:
                    send_headers["Connection"] = "keep-alive"
                for ck, cv in cookie_req.header_items():
                    if ck.lower() not in header_lower:
                        send_headers[ck] = cv

                try:
                    conn.request(method_upper, target, body=data, headers=send_headers)
                    resp = conn.getresponse()
                    raw_body = resp.read()
                except (
                    http.client.RemoteDisconnected,
                    http.client.BadStatusLine,
                    ConnectionResetError,
                    BrokenPipeError,
                    ssl.SSLEOFError,
                ):
                    self._drop_conn(key, conn)
                    if idempotent and attempt == 0:
                        continue
                    if not idempotent:
                        raise OmadaError(
                            f"connection closed after sending non-idempotent {method_upper} {parts.path or '/'}",
                            hint="verify controller state before retrying; write was not replayed automatically",
                            endpoint=parts.path or "/",
                        ) from None
                    raise
                except (http.client.HTTPException, OSError):
                    self._drop_conn(key, conn)
                    raise

                if reused:
                    self.requests_reused += 1
                headers_obj = getattr(resp, "headers", None)
                if headers_obj is None:
                    headers_obj = getattr(resp, "msg", None)
                if headers_obj is not None:
                    self.cookie_jar.extract_cookies(
                        cast(http.client.HTTPResponse, _CookieResponseAdapter(headers_obj)),
                        cookie_req,
                    )
                if getattr(resp, "will_close", False):
                    self._drop_conn(key, conn)
                return int(resp.status), raw_body

        raise RuntimeError("unreachable retry exhaustion in UrllibTransport.request")


def build_ssl_context(config: Config) -> ssl.SSLContext:
    """Create the TLS context implied by ``OMADA_VERIFY_SSL`` / ``OMADA_CA_BUNDLE``.

    ``OMADA_STRICT_X509=false`` clears :data:`ssl.VERIFY_X509_STRICT`, which
    Python 3.13+ enables by default and which rejects otherwise-working
    controller certificates (self-signed, missing CA bit, or v1 certs). Clearing
    it keeps chain and hostname verification in place.

    ``OMADA_TLS_SERVER_NAME`` overrides the ``server_hostname`` passed during
    the TLS handshake so connecting by IP against Omada's default certificate
    (whose SAN is typically ``DNS:Omada``) still performs full chain + SAN
    verification.
    """
    if not config.verify_ssl:
        context = ssl._create_unverified_context()  # noqa: SLF001 - documented opt-out
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    cafile = str(config.ca_bundle) if config.ca_bundle else None
    context = ssl.create_default_context(cafile=cafile)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if not config.strict_x509 and hasattr(ssl, "VERIFY_X509_STRICT"):
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if config.tls_server_name:
        pinned_name = config.tls_server_name
        orig_wrap = context.wrap_socket

        def _wrap_with_pinned_name(sock, *args, **kwargs):
            kwargs["server_hostname"] = pinned_name
            return orig_wrap(sock, *args, **kwargs)

        context.wrap_socket = _wrap_with_pinned_name  # type: ignore[method-assign]
    return context
