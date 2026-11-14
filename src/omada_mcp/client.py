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

import contextlib
import copy
import datetime
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .config import Config, default_snapshot_dir
from .errors import (
    ERROR_CATALOG,
    ERROR_HINTS,
    OmadaError,
    OmadaSessionExpiredError,
    describe_error,
    explain_error_code,
    redact_secrets,
)
from .transport import (
    SESSION_COOKIE_NAMES,
    AuthInfo,
    SiteInfo,
    UrllibTransport,
    _describe_privilege,
    build_ssl_context,
    classify_controller_family,
)

__all__ = [
    "AuthInfo",
    "BURST_BACKOFF_SECONDS",
    "ERROR_CATALOG",
    "ERROR_HINTS",
    "OmadaClient",
    "OmadaError",
    "OmadaSessionExpiredError",
    "SESSION_COOKIE_NAMES",
    "SiteInfo",
    "UrllibTransport",
    "build_ssl_context",
    "classify_controller_family",
    "describe_error",
    "explain_error_code",
    "fetch_paginated",
    "redact_secrets",
]


def fetch_paginated(
    client: OmadaClient,
    endpoint: str,
    *,
    page_size: int = 100,
    max_pages: int = 50,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Collect all rows across paginated Omada Web API v2 endpoints."""
    return client.paginate(endpoint, page_size=page_size, max_pages=max_pages)

#: Delay used when the controller signals a burst block (``errorCode -1600``).
BURST_BACKOFF_SECONDS = 0.8

#: Controllers answer ``-1600`` both for "path not registered" and for "slow
#: down"; a single paced retry disambiguates the two in practice.
_MAX_BURST_RETRIES = 1

#: TTL for session-scoped negative caching when an uncached GET hits ``-1600``
#: even after the burst-backoff retry (e.g., unsupported firmware endpoints).
_NEGATIVE_CACHE_TTL_SECONDS = 300.0


def log(message: str, stream=None) -> None:
    """Log to stderr: stdout is reserved for JSON-RPC frames."""
    stream = stream if stream is not None else sys.stderr
    stamp = datetime.datetime.now().strftime("%H:%M:%S")
    with contextlib.suppress(Exception):  # pragma: no cover - never let logging kill the server
        print(f"[{stamp}] {message}", file=stream, flush=True)


class OmadaClient:
    """Authenticated, paced Web API v2 client.

    ``transport`` and ``sleep`` are injectable so tests exercise the real code
    paths without a controller or real delays.
    """

    def __init__(
        self,
        config: Config,
        transport: UrllibTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        log_fn: Callable[[str], None] | None = None,
    ):
        self.config = config
        self._sleep = sleep
        self._clock = clock
        self._log = log_fn or log
        self._transport = transport
        self._lock = threading.RLock()
        self._last_request_at = 0.0
        self._adaptive_min_interval = 0.0
        self._last_write_at: float | None = None
        self._snapshot_seq = 0
        self._auth_in_progress = False
        self._cache: dict[tuple[str, str], dict[str, Any]] | None = None
        self._cache_depth: int = 0
        self._cache_bypass_depth: int = 0
        self._negative_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
        self.token: str | None = None
        self.controller_id: str | None = None
        self.site: SiteInfo | None = None
        self.auth_info: AuthInfo | None = None
        self.request_count = 0

    @contextlib.contextmanager
    def scoped_cache(self):
        """Memoize GET API calls within one composite tool invocation.

        Caches deep-copied responses in memory only until the outermost scope
        exits. Never reads cached data during mutating operations or read-back
        verification inside :meth:`write`.
        """
        with self._lock:
            if self._cache_depth == 0:
                self._cache = {}
            self._cache_depth += 1
        try:
            yield
        finally:
            with self._lock:
                self._cache_depth = max(0, self._cache_depth - 1)
                if self._cache_depth == 0:
                    self._cache = None

    # -- infrastructure -------------------------------------------------------

    @property
    def transport(self) -> UrllibTransport:
        if self._transport is None:
            self._transport = UrllibTransport(
                build_ssl_context(self.config),
                timeout=self.config.timeout,
                use_system_proxy=self.config.use_system_proxy,
            )
        return self._transport

    def _pace(self) -> None:
        base_interval = max(0.0, float(self.config.min_interval or 0.0))
        if base_interval <= 0:
            return
        interval = max(base_interval, self._adaptive_min_interval)
        elapsed = self._clock() - self._last_request_at
        if self._last_request_at and elapsed < interval:
            self._sleep(interval - elapsed)

    def _raw(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes]:
        self._pace()
        self.request_count += 1
        try:
            status, body = self.transport.request(
                method, url, headers=headers, data=data, timeout=self.config.timeout
            )
        except ssl.SSLCertVerificationError as exc:
            detail = exc.verify_message or exc.reason or str(exc)
            hint = ("set OMADA_CA_BUNDLE to the controller's CA PEM, or "
                    "OMADA_STRICT_X509=false for a self-signed cert, or "
                    "OMADA_VERIFY_SSL=false to disable verification")
            if "mismatch" in str(detail).lower():
                hint = ("set OMADA_TLS_SERVER_NAME=Omada (with OMADA_CA_BUNDLE and "
                        "OMADA_STRICT_X509=false) when connecting by IP against Omada's "
                        "default cert, or " + hint)
            raise OmadaError(
                f"TLS verification failed: {detail}",
                hint=hint,
            ) from exc
        except ssl.SSLError as exc:
            raise OmadaError(
                f"TLS handshake failed: {exc.reason or exc}",
                hint="the controller's web port is usually 8043 (https) or 8088 (http)",
            ) from exc
        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise OmadaError(
                f"cannot reach {self.config.base_url}: {reason}",
                hint=("check OMADA_BASE_URL, the port (8043 by default) and that this host "
                      "can route to the controller; on Windows, disabled system proxies "
                      "mean a proxy-only route needs OMADA_USE_SYSTEM_PROXY=true"),
            ) from exc
        finally:
            self._last_request_at = self._clock()
        return status, body

    @staticmethod
    def _looks_like_html(body: bytes) -> bool:
        head = body[:512].lstrip().lower()
        return head.startswith(b"<!doctype html") or head.startswith(b"<html")

    # -- authentication -------------------------------------------------------

    def controller_info(self) -> dict[str, Any]:
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
        info_out: dict[str, Any] = {
            "omadacId": controller_id,
            "controllerVer": str(result.get("controllerVer") or result.get("version") or ""),
            "apiVer": result.get("apiVer"),
            "configured": result.get("configured"),
        }
        for extra in ("model", "deviceModel", "hardware", "omadacCategory", "type"):
            if extra in result and result[extra] is not None:
                info_out[extra] = result[extra]
        return info_out

    def session_cookie_name(self) -> str | None:
        """Return the active Omada session cookie name in the transport jar, if any."""
        jar = getattr(self.transport, "cookie_jar", None)
        if jar is None:
            return None
        names = [getattr(c, "name", "") for c in jar]
        for preferred in SESSION_COOKIE_NAMES:
            if preferred in names:
                return preferred
        for name in names:
            if "SESSIONID" in name.upper():
                return name
        return None

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
                        payload.get("errorCode"),
                        str(payload.get("msg") or ""),
                        endpoint="/api/v2/login",
                        method="POST",
                    ),
                    code=payload.get("errorCode"),
                    hint=("check OMADA_USERNAME / OMADA_PASSWORD; repeated failures also "
                          "lock the account for a few minutes"),
                    endpoint="/api/v2/login",
                )
            result = payload.get("result") or {}
            if result.get("omadacId"):
                controller_id = str(result["omadacId"])
            token = result.get("token") or payload.get("token")
            if not token:
                raise OmadaError(
                    "login succeeded but returned no token",
                    hint="the account may be SSO-only; use a local controller account",
                    endpoint="/api/v2/login",
                )
            self.token = token
            self.controller_id = controller_id
            cookie_name = self.session_cookie_name()
            family = classify_controller_family(info, session_cookie=cookie_name)
            self._log(
                f"authenticated as {self.config.username} on controller {controller_id}"
                f" (family={family}" + (f", cookie={cookie_name}" if cookie_name else "") + ")"
            )

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
                controller_family=family,
                session_cookie=cookie_name,
            )
            if self.site is not None:
                self._log(f"site resolved: {self.site.name} ({self.site.site_id})")
            return self.auth_info

    # -- request plumbing -----------------------------------------------------

    @staticmethod
    def _decode(body: bytes) -> dict[str, Any]:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {"result": payload, "errorCode": 0}

    def api(
        self,
        endpoint: str,
        method: str = "GET",
        data: dict[str, Any] | None = None,
        require_auth: bool = True,
        _retry: bool = True,
        _burst: int = 0,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """Call ``/{omadacId}/api/v2/{endpoint}`` and return the raw JSON envelope.

        Recovers from a dead server-side session (HTML instead of JSON on a 200)
        by re-authenticating exactly once, and retries a single ``-1600`` after
        :data:`BURST_BACKOFF_SECONDS` because the controller reuses that code for
        rate limiting.
        """
        if require_auth and (not self.token or not self.controller_id):
            self.authenticate()

        endpoint = endpoint.lstrip("/")
        method_upper = method.upper()
        cache_key = (self.controller_id or "", endpoint)
        if (
            use_cache
            and method_upper == "GET"
            and data is None
            and require_auth
            and _retry
            and _burst == 0
        ):
            with self._lock:
                if self._cache_bypass_depth == 0:
                    if self._cache is not None:
                        cached = self._cache.get(cache_key)
                        if cached is not None:
                            return copy.deepcopy(cached)
                    neg = self._negative_cache.get(cache_key)
                    if neg is not None:
                        cached_at, neg_payload = neg
                        if (self._clock() - cached_at) < _NEGATIVE_CACHE_TTL_SECONDS:
                            return copy.deepcopy(neg_payload)
                        del self._negative_cache[cache_key]
        elif method_upper != "GET":
            with self._lock:
                if self._cache is not None:
                    self._cache.clear()
                self._negative_cache.clear()

        separator = "&" if "?" in endpoint else "?"
        url = (f"{self.config.base_url}/{self.controller_id}/api/v2/"
               f"{endpoint}{separator}token={self.token}")
        headers = {"Csrf-Token": str(self.token), "Content-Type": "application/json"}
        body = json.dumps(data).encode() if data is not None else None

        status, raw = self._raw(method, url, headers=headers, data=body)

        if self._looks_like_html(raw) or status in (301, 302, 303, 307, 308):
            # Expired sessions return either the SPA shell or a redirect to it.
            # Do not follow redirects: credentials stay on the configured origin.
            if not _retry:
                raise OmadaError(
                    "controller returned the web UI HTML instead of JSON, twice (or repeated redirects)",
                    hint=("the API session keeps dying: another session may be logging in "
                          "with the same account; log in with a dedicated account"),
                    endpoint=endpoint,
                )
            cookie_name = self.session_cookie_name()
            cookie_state = f"cookie={cookie_name} present, server-side session expired" \
                if cookie_name else "no session cookie"
            self._log(f"session expired (HTML/redirect response; {cookie_state}); "
                      "re-authenticating")
            self.authenticate(force=True)
            if method_upper != "GET":
                # Never blindly replay POST/PATCH/DELETE: callers must re-read
                # state first to verify whether the write already landed.
                raise OmadaSessionExpiredError(
                    f"session expired during {method_upper} {endpoint}; re-authenticated, "
                    "re-read state before retrying",
                    reauthenticated=True,
                    hint="use a dedicated Admin account for write operations to avoid session eviction",
                    endpoint=endpoint,
                )
            return self.api(endpoint, method_upper, data, require_auth=False, _retry=False,
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
        if code == -30109 and not endpoint.lower().startswith("login"):
            if not _retry:
                raise OmadaError(
                    "controller returned -30109 (session expired) twice",
                    code=-30109,
                    hint=("the API session keeps dying: another session may be logging in "
                          "with the same account; log in with a dedicated account"),
                    endpoint=endpoint,
                )
            self._log(f"session expired (-30109 on {method_upper} {endpoint}); re-authenticating")
            self.authenticate(force=True)
            if method_upper != "GET":
                raise OmadaSessionExpiredError(
                    f"session expired during {method_upper} {endpoint}; re-authenticated, "
                    "re-read state before retrying",
                    reauthenticated=True,
                    hint="use a dedicated Admin account for write operations to avoid session eviction",
                    endpoint=endpoint,
                )
            return self.api(endpoint, method_upper, data, require_auth=False, _retry=False,
                            _burst=_burst)

        if code == -1600 and method_upper == "GET" and _burst < _MAX_BURST_RETRIES:
            self._adaptive_min_interval = max(self._adaptive_min_interval, 0.25)
            self._log(f"-1600 from {endpoint}; pacing {BURST_BACKOFF_SECONDS}s and retrying once")
            self._sleep(BURST_BACKOFF_SECONDS)
            return self.api(endpoint, method_upper, data, require_auth=False, _retry=_retry,
                            _burst=_burst + 1)

        payload["_httpStatus"] = status
        if use_cache and method_upper == "GET" and data is None:
            with self._lock:
                if self._cache_bypass_depth == 0:
                    if code in (0, None):
                        self._negative_cache.pop(cache_key, None)
                        if self._cache is not None:
                            self._cache[cache_key] = copy.deepcopy(payload)
                    elif code == -1600 and _burst >= _MAX_BURST_RETRIES:
                        self._negative_cache[cache_key] = (
                            self._clock(),
                            copy.deepcopy(payload),
                        )
        return payload

    def api_result(self, endpoint: str, method: str = "GET",
                   data: dict[str, Any] | None = None) -> Any:
        """Like :meth:`api` but raises :class:`OmadaError` on a non-zero ``errorCode``."""
        payload = self.api(endpoint, method, data)
        code = payload.get("errorCode")
        if code not in (0, None):
            raise OmadaError(
                describe_error(code, str(payload.get("msg") or ""),
                               endpoint=endpoint, method=method),
                code=code,
                endpoint=endpoint,
            )
        return payload.get("result")

    def paginate(
        self,
        endpoint: str,
        *,
        page_size: int = 100,
        max_pages: int = 50,
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        """Collect all rows across paginated Omada Web API v2 endpoints."""
        collected: list[dict[str, Any]] = []
        last_meta: dict[str, Any] | None = None
        prev_rows: list[dict[str, Any]] | None = None
        sep = "&" if "?" in endpoint else "?"
        pages_fetched = 0
        total_int: int | None = None
        exhausted_loop = False
        stopped_duplicate = False

        for page in range(1, max_pages + 1):
            paged = f"{endpoint}{sep}currentPage={page}&currentPageSize={page_size}"
            result = self.api_result(paged)
            pages_fetched += 1
            if isinstance(result, list):
                collected.extend(dict(r) for r in result if isinstance(r, Mapping))
                return collected, {
                    "_pagination": {
                        "pagesFetched": pages_fetched,
                        "maxPages": max_pages,
                        "totalRows": len(collected),
                        "truncated": False,
                        "truncationReason": None,
                    },
                }
            if not isinstance(result, Mapping):
                break
            last_meta = dict(result)
            raw_rows = result.get("data")
            if not isinstance(raw_rows, list) or not raw_rows:
                total_val = result.get("totalRows")
                if total_val is not None:
                    total_int = int(total_val)
                break
            rows = [dict(r) for r in raw_rows if isinstance(r, Mapping)]
            if prev_rows is not None and rows == prev_rows:
                stopped_duplicate = True
                break
            prev_rows = rows
            collected.extend(rows)
            total_val = result.get("totalRows")
            if total_val is not None:
                total_int = int(total_val)
                if len(collected) >= total_int:
                    break
            elif len(rows) < page_size:
                break
            if page == max_pages:
                exhausted_loop = True

        truncated = False
        reason: str | None = None
        if exhausted_loop and (total_int is None or len(collected) < total_int):
            truncated = True
            reason = f"pagination reached maxPages={max_pages}"
        elif total_int is not None and len(collected) < total_int and not stopped_duplicate:
            truncated = True
            reason = f"controller returned {len(collected)} of {total_int} totalRows"

        if last_meta is None:
            last_meta = {}
        last_meta["_pagination"] = {
            "pagesFetched": pages_fetched,
            "maxPages": max_pages,
            "totalRows": total_int if total_int is not None else len(collected),
            "truncated": truncated,
            "truncationReason": reason,
        }
        return collected, last_meta

    # -- write plumbing (gated, paced, snapshotted, verified, audited) --------

    def _pace_write(self) -> None:
        interval = max(
            float(getattr(self.config, "write_min_interval", 1.0) or 0.0),
            float(self.config.min_interval or 0.0),
        )
        if interval <= 0 or self._last_write_at is None:
            return
        elapsed = self._clock() - self._last_write_at
        if elapsed < interval:
            self._sleep(interval - elapsed)

    def _snapshot_dir(self) -> Path:
        return Path(self.config.snapshot_dir) if self.config.snapshot_dir else default_snapshot_dir()

    @staticmethod
    def _safe_filename_part(value: str, fallback: str = "target") -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-.")
        return (cleaned[:64] if cleaned else fallback)

    def _ensure_snapshot_dir(self) -> Path:
        directory = self._snapshot_dir()
        directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            with contextlib.suppress(OSError):
                os.chmod(directory, 0o700)
        return directory

    def _save_snapshot(self, tool_name: str, target: str, payload: Any) -> str:
        directory = self._ensure_snapshot_dir()
        self._snapshot_seq += 1
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_tool = self._safe_filename_part(tool_name, "write")
        safe_target = self._safe_filename_part(target, "target")
        filename = f"{stamp}-{self._snapshot_seq:04d}-{uuid.uuid4().hex[:12]}-{safe_tool}-{safe_target}.json"
        path = directory / filename
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "tool": tool_name,
            "target": target,
            "account": self.config.username,
            "data": redact_secrets(payload),
        }
        # Exclusive creation prevents a second process from replacing rollback state.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, indent=2, ensure_ascii=False, default=str) + "\n")
        if os.name != "nt":
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
        return filename

    def _append_audit(
        self,
        *,
        tool_name: str,
        target: str,
        snapshot_id: str,
        fields_changed: Any,
        result: str,
        verified: bool,
        detail: str | None = None,
    ) -> None:
        directory = self._ensure_snapshot_dir()
        audit_path = directory / "audit.jsonl"
        entry: dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "tool": tool_name,
            "target": target,
            "snapshot": snapshot_id,
            "fieldsChanged": fields_changed,
            "result": result,
            "verified": bool(verified),
            "account": self.config.username,
        }
        if detail:
            entry["detail"] = detail
        with open(audit_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        if os.name != "nt":
            with contextlib.suppress(OSError):
                os.chmod(audit_path, 0o600)

    @staticmethod
    def _verify_expect_keys(
        expect_keys: Mapping[str, Any],
        after: Any,
    ) -> tuple[bool, str | None]:
        if not isinstance(after, Mapping):
            return False, "read-back did not return a JSON object"
        for key, expected in expect_keys.items():
            if key not in after:
                return False, f"field {key!r} missing in read-back"
            actual = after[key]
            if isinstance(expected, Mapping):
                ok, reason = OmadaClient._verify_expect_keys(expected, actual)
                if not ok:
                    return False, f"{key}.{reason}"
            elif actual != expected:
                return False, f"field {key!r} expected {expected!r}, got {actual!r}"
        return True, None

    def _require_write_allowed(self, tool_name: str | None, endpoint: str) -> None:
        if self.config.read_only:
            raise OmadaError(
                "OMADA_READ_ONLY=true refuses all write operations",
                hint="set OMADA_READ_ONLY=false and add the exact tool name to OMADA_WRITE_TOOLS",
                endpoint=endpoint,
            )
        allowed = set(getattr(self.config, "write_tools", ()) or ())
        if not allowed or (tool_name is not None and tool_name not in allowed):
            raise OmadaError(
                f"OMADA_WRITE_TOOLS does not allow {tool_name or 'write operations'}",
                hint="set OMADA_WRITE_TOOLS to a comma-separated list of exact write tool names",
                endpoint=endpoint,
            )

    def write(
        self,
        endpoint: str,
        method: str = "PATCH",
        data: dict[str, Any] | None = None,
        *,
        expect_keys: Mapping[str, Any] | None = None,
        tool_name: str | None = None,
        target: str | None = None,
        before: Any = None,
        snapshot_payload: Any = None,
        read_back: Callable[[], Any] | None = None,
        verify_fn: Callable[[Any, Any], tuple[bool, str | None]] | None = None,
        reauth_prepare: Callable[[], tuple[bool, dict[str, Any] | None, Any]] | None = None,
        fields_changed: Any = None,
    ) -> dict[str, Any]:
        """Single serialised write path: gate -> pace -> snapshot -> call -> verify -> audit."""
        method_upper = method.upper()
        if method_upper not in ("POST", "PATCH", "PUT", "DELETE"):
            raise OmadaError(
                f"OmadaClient.write() does not accept method {method_upper!r}",
                endpoint=endpoint,
            )
        self._require_write_allowed(tool_name, endpoint)

        eff_tool = tool_name or f"write_{method_upper.lower()}"
        eff_target = target or endpoint
        eff_fields = fields_changed if fields_changed is not None else sorted((expect_keys or {}).keys())

        with self._lock:
            if self._cache is not None:
                self._cache.clear()
            self._cache_bypass_depth += 1
            try:
                return self._write_locked(
                    endpoint=endpoint,
                    method_upper=method_upper,
                    data=data,
                    expect_keys=expect_keys,
                    eff_tool=eff_tool,
                    eff_target=eff_target,
                    eff_fields=eff_fields,
                    before=before,
                    snapshot_payload=snapshot_payload,
                    read_back=read_back,
                    verify_fn=verify_fn,
                    reauth_prepare=reauth_prepare,
                )
            finally:
                self._cache_bypass_depth = max(0, self._cache_bypass_depth - 1)

    def _write_locked(
        self,
        *,
        endpoint: str,
        method_upper: str,
        data: dict[str, Any] | None,
        expect_keys: Mapping[str, Any] | None,
        eff_tool: str,
        eff_target: str,
        eff_fields: Any,
        before: Any,
        snapshot_payload: Any,
        read_back: Callable[[], Any] | None,
        verify_fn: Callable[[Any, Any], tuple[bool, str | None]] | None,
        reauth_prepare: Callable[[], tuple[bool, dict[str, Any] | None, Any]] | None,
    ) -> dict[str, Any]:
        with self._lock:
            snap_data = before if snapshot_payload is None else snapshot_payload
            snapshot_id = self._save_snapshot(eff_tool, eff_target, snap_data)

            already_applied = False
            payload: dict[str, Any] | None = None
            write_data = data
            self._pace_write()
            try:
                try:
                    payload = self.api(endpoint, method=method_upper, data=write_data)
                except OmadaSessionExpiredError:
                    if reauth_prepare is None:
                        raise OmadaError(
                            f"session expired during {method_upper} {endpoint}; write not replayed blindly",
                            hint=("re-read controller state before retrying, and give write tools a "
                                  "dedicated Admin account"),
                            endpoint=endpoint,
                        ) from None
                    already_applied, refreshed_data, refreshed_before = reauth_prepare()
                    if refreshed_before is not None:
                        before = refreshed_before
                    if not already_applied:
                        self._pace_write()
                        payload = self.api(
                            endpoint,
                            method=method_upper,
                            data=write_data if refreshed_data is None else refreshed_data,
                            require_auth=False,
                            _retry=False,
                        )
            except OmadaError as exc:
                self._append_audit(
                    tool_name=eff_tool,
                    target=eff_target,
                    snapshot_id=snapshot_id,
                    fields_changed=eff_fields,
                    result="error",
                    verified=False,
                    detail=str(exc),
                )
                raise
            finally:
                self._last_write_at = self._clock()

            if not already_applied and payload is not None:
                code = payload.get("errorCode")
                if code not in (0, None):
                    msg = describe_error(
                        code,
                        str(payload.get("msg") or ""),
                        endpoint=endpoint,
                        method=method_upper,
                    )
                    self._append_audit(
                        tool_name=eff_tool,
                        target=eff_target,
                        snapshot_id=snapshot_id,
                        fields_changed=eff_fields,
                        result="error",
                        verified=False,
                        detail=msg,
                    )
                    raise OmadaError(msg, code=code, endpoint=endpoint)

            after: Any = None
            try:
                if read_back is not None:
                    after = read_back()
                if verify_fn is not None:
                    verified, reason = verify_fn(before, after)
                elif expect_keys is not None:
                    verified, reason = self._verify_expect_keys(expect_keys, after)
                else:
                    verified = read_back is None
                    reason = None
            except OmadaError as exc:
                self._append_audit(
                    tool_name=eff_tool,
                    target=eff_target,
                    snapshot_id=snapshot_id,
                    fields_changed=eff_fields,
                    result="verification_failed",
                    verified=False,
                    detail=str(exc),
                )
                raise

            if not verified:
                detail = reason or "controller accepted write but read-back did not match intent"
                self._append_audit(
                    tool_name=eff_tool,
                    target=eff_target,
                    snapshot_id=snapshot_id,
                    fields_changed=eff_fields,
                    result="verification_failed",
                    verified=False,
                    detail=detail,
                )
                raise OmadaError(
                    f"write verification failed for {eff_tool} ({eff_target}): {detail}",
                    hint=(f"the controller may have silently ignored or altered the write; inspect "
                          f"snapshot {snapshot_id} and re-read state before retrying"),
                    endpoint=endpoint,
                )

            self._append_audit(
                tool_name=eff_tool,
                target=eff_target,
                snapshot_id=snapshot_id,
                fields_changed=eff_fields,
                result="success",
                verified=True,
            )
            return {
                "result": payload.get("result") if payload is not None else None,
                "before": before,
                "after": after,
                "verified": True,
                "snapshot": snapshot_id,
            }

    # -- discovery ------------------------------------------------------------

    def list_sites(self, page_size: int = 50, max_pages: int = 5) -> list[dict[str, Any]]:
        """All sites visible to the logged-in account."""
        sites: list[dict[str, Any]] = []
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
        closer = getattr(self._transport, "close", None)
        if callable(closer):
            closer()
