"""Minimal, dependency-free client for the TP-Link Omada **Web API v2**.

The Omada controller exposes two unrelated API families:

* **Web API** (``/{omadacId}/api/v2/...``) -- what the web UI itself calls. Works
  with ordinary local accounts (Viewer or Admin) and a username/password login.
* **Open API** (``/openapi/v1...``) -- OAuth2 client-credentials, only after
  "Platform Integration" is configured on the controller.

This module speaks the Web API because it is available on every controller
(software v5.x/v6.x, and OC200/OC300 hardware) without extra setup.

Documented controller behaviour encoded here:

* the ``omadacId`` prefix is mandatory in the path (otherwise the SPA shell is
  returned instead of JSON);
* the token must appear in **both** the query string and the ``Csrf-Token``
  header, and the ``TPOMADA_SESSIONID`` cookie must be replayed;
* the server-side session can die while the cookie lives (15-day max-age), which
  surfaces as a 200 response containing the ~2937-byte HTML SPA shell -- handled
  by re-authenticating once and replaying the call;
* a burst of calls (more than ~5 in a few seconds) makes the controller answer
  ``-1600`` for endpoints that work when paced, so calls are spaced and a
  ``-1600`` is retried once after 0.8 s.
"""

from __future__ import annotations

import datetime
import http.cookiejar
import json
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import Config

__all__ = [
    "AuthInfo",
    "BURST_BACKOFF_SECONDS",
    "OmadaClient",
    "OmadaError",
    "SiteInfo",
    "UrllibTransport",
    "describe_error",
]

#: Delay used when the controller signals a burst block (``errorCode -1600``).
BURST_BACKOFF_SECONDS = 0.8

#: Controllers report the account role three different ways depending on build:
#: ``roleName`` (6.2+), an integer ``privilege`` (5.x), or a ``privilege`` object
#: carrying only the site scope (6.2 with a local account). All three are folded
#: into one readable label plus an optional scope string.
_PRIVILEGE_LABELS = {0: "viewer", 1: "admin", 2: "owner"}

#: Controllers answer ``-1600`` both for "path not registered" and for "slow
#: down"; a single paced retry disambiguates the two in practice.
_MAX_BURST_RETRIES = 1

ERROR_HINTS: Dict[int, str] = {
    -1: ("General error -- usually a required field is missing from the request body, "
         "not a credentials problem."),
    -1001: ("Bean-validation failure: the body is missing a mandatory field "
            "(e.g. lanNetworkIpv6Config.proto when PATCHing a LAN network)."),
    -1505: ("No permission for this site: the URL needs the hex site ID, not the site "
            "name. Run `omada-mcp --doctor` to resolve it."),
    -1600: ("Unsupported request path -- or a burst block. The path shape is wrong when "
            "the endpoint is not in the documented table; more than ~5 rapid calls "
            "produce the same code until you pace them (0.8 s)."),
    -30109: "Session expired or invalid; re-authenticate.",
    -33726: ("IP group is full: a group holds at most 16 entries. Store an address "
             "range as network-aligned CIDRs instead of one /32 per host."),
    -41011: ("This client does not exist -- the client endpoints are Admin-only; use "
             "insight/clients with a Viewer account."),
    -44116: ("Open API is not enabled: the controller needs Platform Integration for "
             "openapi/*. The Web API used here does not."),
}


def describe_error(code: Optional[int], msg: str = "") -> str:
    """Human explanation for an Omada ``errorCode`` (falls back to the raw msg)."""
    if code is None:
        return msg or "unknown error"
    hint = ERROR_HINTS.get(int(code))
    text = f"errorCode {code}"
    if msg:
        text += f": {msg}"
    if hint:
        text += f" -- {hint}"
    return text


class OmadaError(RuntimeError):
    """A controller-side or transport-side failure with an optional fix hint."""

    def __init__(
        self,
        message: str,
        code: Optional[int] = None,
        hint: Optional[str] = None,
        endpoint: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.hint = hint
        self.endpoint = endpoint

    def __str__(self) -> str:  # pragma: no cover - trivial
        text = self.message
        if self.endpoint:
            text += f" [endpoint: {self.endpoint}]"
        if self.hint:
            text += f" (fix: {self.hint})"
        return text


@dataclass(frozen=True)
class SiteInfo:
    """Resolved site: the controller's internal hex id plus its display name."""

    site_id: str
    name: str
    index: int = 0
    total: int = 1
    requested: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
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
    user_id: Optional[str] = None
    privilege: Optional[str] = None
    site_scope: Optional[str] = None


class UrllibTransport:
    """HTTP transport over :mod:`urllib` with a shared cookie jar and TLS context."""

    def __init__(self, ssl_context: ssl.SSLContext, timeout: float = 30.0):
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_context),
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
        )
        self.timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[int, bytes]:
        """Perform one request, returning ``(status, body)``.

        HTTP error statuses are returned rather than raised: the controller
        frequently answers 4xx/5xx with a useful JSON ``errorCode`` payload.
        """
        req = urllib.request.Request(url, method=method, data=data)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            response = self.opener.open(req, timeout=timeout or self.timeout)
            return int(response.getcode() or 200), response.read()
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read()


def build_ssl_context(config: Config) -> ssl.SSLContext:
    """Create the TLS context implied by ``OMADA_VERIFY_SSL`` / ``OMADA_CA_BUNDLE``.

    ``OMADA_STRICT_X509=false`` clears :data:`ssl.VERIFY_X509_STRICT`, which
    Python 3.13+ enables by default and which rejects otherwise-working
    controller certificates (self-signed, missing CA bit, or v1 certs). Clearing
    it keeps chain and hostname verification in place.
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
        context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT")
    return context


def log(message: str, stream=None) -> None:
    """Log to stderr: stdout is reserved for JSON-RPC frames."""
    stream = stream if stream is not None else sys.stderr
    stamp = datetime.datetime.now().strftime("%H:%M:%S")
    try:
        print(f"[{stamp}] {message}", file=stream, flush=True)
    except Exception:  # pragma: no cover - never let logging kill the server
        pass


def _describe_privilege(user_result: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Fold the three role shapes the controller uses into ``(role, scope)``."""
    if not isinstance(user_result, dict):
        return None, None
    raw = user_result.get("privilege")
    scope: Optional[str] = None
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


class OmadaClient:
    """Authenticated, paced Web API v2 client.

    ``transport`` and ``sleep`` are injectable so tests exercise the real code
    paths without a controller or real delays.
    """

    def __init__(
        self,
        config: Config,
        transport: Optional[UrllibTransport] = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self.config = config
        self._sleep = sleep
        self._clock = clock
        self._log = log_fn or log
        self._transport = transport
        self._lock = threading.RLock()
        self._last_request_at = 0.0
        self._auth_in_progress = False
        self.token: Optional[str] = None
        self.controller_id: Optional[str] = None
        self.site: Optional[SiteInfo] = None
        self.auth_info: Optional[AuthInfo] = None
        self.request_count = 0

    # -- infrastructure -------------------------------------------------------

    @property
    def transport(self) -> UrllibTransport:
        if self._transport is None:
            self._transport = UrllibTransport(
                build_ssl_context(self.config), timeout=self.config.timeout
            )
        return self._transport

    def _pace(self) -> None:
        interval = max(0.0, float(self.config.min_interval or 0.0))
        if interval <= 0:
            return
        elapsed = self._clock() - self._last_request_at
        if self._last_request_at and elapsed < interval:
            self._sleep(interval - elapsed)

    def _raw(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
    ) -> Tuple[int, bytes]:
        self._pace()
        self.request_count += 1
        try:
            status, body = self.transport.request(
                method, url, headers=headers, data=data, timeout=self.config.timeout
            )
        except ssl.SSLCertVerificationError as exc:
            raise OmadaError(
                f"TLS verification failed: {exc.verify_message or exc.reason}",
                hint=("set OMADA_CA_BUNDLE to the controller's CA PEM, or "
                      "OMADA_STRICT_X509=false for a self-signed cert, or "
                      "OMADA_VERIFY_SSL=false to disable verification"),
            ) from exc
        except ssl.SSLError as exc:
            raise OmadaError(
                f"TLS handshake failed: {exc.reason or exc}",
                hint="the controller's web port is usually 8043 (https) or 8088 (http)",
            ) from exc
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise OmadaError(
                f"cannot reach {self.config.base_url}: {reason}",
                hint=("check OMADA_BASE_URL, the port (8043 by default) and that this host "
                      "can route to the controller; hardware controllers answer on the "
                      "management network"),
            ) from exc
        finally:
            self._last_request_at = self._clock()
        return status, body

    @staticmethod
    def _looks_like_html(body: bytes) -> bool:
        head = body[:512].lstrip().lower()
        return head.startswith(b"<!doctype html") or head.startswith(b"<html")

    # -- authentication -------------------------------------------------------

    def controller_info(self) -> Dict[str, Any]:
        """Public ``/api/info`` probe: resolves ``omadacId`` and the controller version."""
        status, body = self._raw("GET", f"{self.config.base_url}/api/info")
        if status != 200 or self._looks_like_html(body):
            raise OmadaError(
                f"/api/info returned HTTP {status} with a non-JSON body",
                hint=("OMADA_BASE_URL should point at the controller web UI root, e.g. "
                      "https://<controller-host>:8043 (not a /path)"),
                endpoint="/api/info",
            )
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            raise OmadaError(
                "/api/info did not return JSON",
                hint="check OMADA_BASE_URL -- a redirect to the login page means the URL is wrong",
                endpoint="/api/info",
            ) from None
        result = payload.get("result") or {}
        controller_id = result.get("omadacId")
        if not controller_id:
            raise OmadaError(
                "/api/info has no result.omadacId",
                hint="this does not look like an Omada SDN controller (v5/v6 Web API)",
                endpoint="/api/info",
            )
        self.controller_id = controller_id
        return {
            "omadacId": controller_id,
            "controllerVer": str(result.get("controllerVer") or result.get("version") or ""),
            "apiVer": result.get("apiVer"),
            "configured": result.get("configured"),
        }

    def authenticate(self, force: bool = False, resolve_site: bool = True) -> AuthInfo:
        """Log in (idempotent unless ``force``) and resolve the target site.

        The re-entrancy guard matters: a controller that answers the site lookup
        with the SPA shell would otherwise recurse through
        :meth:`api` -> :meth:`authenticate` without bound.
        """
        with self._lock:
            cached_site_ok = self.site is not None or not resolve_site
            if self.auth_info is not None and self.token and cached_site_ok and not force:
                return self.auth_info
            if self._auth_in_progress:
                raise OmadaError(
                    "re-authentication loop: the controller keeps answering "
                    "authenticated API calls with the web UI shell",
                    hint=("the account may be locked, or another session invalidates this "
                          "one on every login -- use a dedicated controller account"),
                )
            self._auth_in_progress = True
            try:
                return self._authenticate_locked(resolve_site)
            finally:
                self._auth_in_progress = False

    def _authenticate_locked(self, resolve_site: bool = True) -> AuthInfo:
        with self._lock:

            info = self.controller_info()
            controller_id = info["omadacId"]
            credentials = json.dumps(
                {"username": self.config.username, "password": self.config.password}
            ).encode()

            status, body = self._raw(
                "POST",
                f"{self.config.base_url}/{controller_id}/api/v2/login",
                headers={"Content-Type": "application/json"},
                data=credentials,
            )
            payload = self._decode(body)
            if self._looks_like_html(body):
                raise OmadaError(
                    "login returned the web UI HTML instead of JSON",
                    hint=("OMADA_BASE_URL must be the controller web root "
                          "(https://<controller-host>:8043); a proxy or reverse proxy in "
                          "front of the UI breaks the /api/v2 path"),
                    endpoint="/api/v2/login",
                )
            if payload.get("errorCode") not in (0, None):
                raise OmadaError(
                    "login rejected: " + describe_error(
                        payload.get("errorCode"), str(payload.get("msg") or "")
                    ),
                    code=payload.get("errorCode"),
                    hint=("check OMADA_USERNAME / OMADA_PASSWORD; repeated failures also "
                          "lock the account for a few minutes"),
                    endpoint="/api/v2/login",
                )
            result = payload.get("result") or {}
            token = result.get("token")
            if not token:
                raise OmadaError(
                    "login succeeded but returned no token",
                    hint="the account may be SSO-only; use a local controller account",
                    endpoint="/api/v2/login",
                )
            self.token = token
            self.controller_id = controller_id
            self._log(f"authenticated as {self.config.username} on controller {controller_id}")

            user = self.api("users/current", require_auth=False)
            user_result = user.get("result") or {}
            privilege, site_scope = _describe_privilege(user_result)

            if resolve_site:
                self.site = self.resolve_site()
            self.auth_info = AuthInfo(
                controller_id=controller_id,
                controller_version=info.get("controllerVer") or "",
                username=self.config.username,
                user_id=str(user_result.get("id")) if user_result.get("id") else None,
                privilege=privilege,
                site_scope=site_scope,
            )
            if self.site is not None:
                self._log(f"site resolved: {self.site.name} ({self.site.site_id})")
            return self.auth_info

    # -- request plumbing -----------------------------------------------------

    @staticmethod
    def _decode(body: bytes) -> Dict[str, Any]:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {"result": payload, "errorCode": 0}

    def api(
        self,
        endpoint: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        require_auth: bool = True,
        _retry: bool = True,
        _burst: int = 0,
    ) -> Dict[str, Any]:
        """Call ``/{omadacId}/api/v2/{endpoint}`` and return the raw JSON envelope.

        Recovers from a dead server-side session (HTML instead of JSON on a 200)
        by re-authenticating exactly once, and retries a single ``-1600`` after
        :data:`BURST_BACKOFF_SECONDS` because the controller reuses that code for
        rate limiting.
        """
        if require_auth and (not self.token or not self.controller_id):
            self.authenticate()

        endpoint = endpoint.lstrip("/")
        separator = "&" if "?" in endpoint else "?"
        url = (f"{self.config.base_url}/{self.controller_id}/api/v2/"
               f"{endpoint}{separator}token={self.token}")
        headers = {"Csrf-Token": str(self.token), "Content-Type": "application/json"}
        body = json.dumps(data).encode() if data is not None else None

        status, raw = self._raw(method, url, headers=headers, data=body)

        if self._looks_like_html(raw):
            # 200 + SPA shell == the server-side API session is gone.
            if not _retry:
                raise OmadaError(
                    "controller returned the web UI HTML instead of JSON, twice",
                    hint=("the API session keeps dying: another session may be logging in "
                          "with the same account; log in with a dedicated account"),
                    endpoint=endpoint,
                )
            self._log("session expired (HTML response); re-authenticating and replaying once")
            self.authenticate(force=True)
            return self.api(endpoint, method, data, require_auth=False, _retry=False,
                            _burst=_burst)

        payload = self._decode(raw)
        if not payload:
            raise OmadaError(
                f"non-JSON response (HTTP {status}) from {endpoint}",
                hint=("check that the controller id prefix is in the URL -- a missing "
                      "prefix returns the SPA shell"),
                endpoint=endpoint,
            )

        code = payload.get("errorCode")
        if code == -1600 and method == "GET" and _burst < _MAX_BURST_RETRIES:
            self._log(f"-1600 from {endpoint}; pacing {BURST_BACKOFF_SECONDS}s and retrying once")
            self._sleep(BURST_BACKOFF_SECONDS)
            return self.api(endpoint, method, data, require_auth=False, _retry=_retry,
                            _burst=_burst + 1)

        payload["_httpStatus"] = status
        return payload

    def api_result(self, endpoint: str, method: str = "GET",
                   data: Optional[Dict[str, Any]] = None) -> Any:
        """Like :meth:`api` but raises :class:`OmadaError` on a non-zero ``errorCode``."""
        payload = self.api(endpoint, method, data)
        code = payload.get("errorCode")
        if code not in (0, None):
            raise OmadaError(
                describe_error(code, str(payload.get("msg") or "")),
                code=code,
                endpoint=endpoint,
            )
        return payload.get("result")

    # -- discovery ------------------------------------------------------------

    def list_sites(self, page_size: int = 50, max_pages: int = 5) -> List[Dict[str, Any]]:
        """All sites visible to the logged-in account."""
        sites: List[Dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            result = self.api_result(
                f"sites?currentPage={page}&currentPageSize={page_size}"
            ) or {}
            rows = result.get("data") if isinstance(result, dict) else result
            rows = rows or []
            sites.extend(rows)
            total = result.get("totalRows", len(sites)) if isinstance(result, dict) else len(sites)
            if len(sites) >= int(total or 0) or not rows:
                break
        return sites

    def resolve_site(self) -> SiteInfo:
        """Resolve ``OMADA_SITE_ID`` / ``OMADA_SITE_NAME``, defaulting to the first site.

        ``OMADA_SITE_ID`` accepts either the hex id or the display name -- the
        controller itself only accepts the hex id in URLs, which is exactly the
        mistake ``-1505`` reports.
        """
        sites = self.list_sites()
        if not sites:
            raise OmadaError(
                "the account can see no sites",
                hint=("grant the account access to a site (Controller > Administrators), "
                      "or check OMADA_SITE_ID"),
            )
        wanted = self.config.site_id or self.config.site_name
        if wanted:
            needle = wanted.strip().lower()
            for index, site in enumerate(sites):
                if str(site.get("id", "")).lower() == needle or \
                        str(site.get("name", "")).lower() == needle:
                    return SiteInfo(
                        site_id=str(site.get("id")),
                        name=str(site.get("name") or site.get("id")),
                        index=index,
                        total=len(sites),
                        requested=wanted,
                    )
            names = ", ".join(f"{s.get('name')} ({s.get('id')})" for s in sites)
            raise OmadaError(
                f"no site matches {wanted!r}; this account can see: {names}",
                hint="set OMADA_SITE_NAME to one of the names above, or omit both "
                     "variables to use the first site",
            )
        first = sites[0]
        return SiteInfo(
            site_id=str(first.get("id")),
            name=str(first.get("name") or first.get("id")),
            index=0,
            total=len(sites),
            requested=None,
        )

    def close(self) -> None:
        self.token = None
