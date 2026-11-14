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
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from .config import Config, default_snapshot_dir

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

import contextlib
import copy
import http.client
import select
import urllib.parse

_SECRET_FIELD_NAMES = frozenset({
    "securityKey",
    "password",
    "passphrase",
    "psk",
    "preSharedKey",
    "presharedKey",
    "radiusSecret",
    "acctSecret",
    "secretKey",
    "privateKey",
    "clientPassword",
    "wanPwd",
    "ddnsPwd",
    "bindPwd",
    "authKey",
    "authPwd",
    "privKey",
    "privPwd",
    "community",
    "roCommunity",
    "rwCommunity",
    "sharedSecret",
    "radiusKey",
    "acctKey",
    "secret",
    "tlsKey",
    "encKey",
})


def redact_secrets(value: Any) -> Any:
    """Recursively mask sensitive credential/PSK fields before snapshots or output."""
    if isinstance(value, Mapping):
        cleaned: Dict[str, Any] = {}
        for k, v in value.items():
            if str(k) in _SECRET_FIELD_NAMES and v not in (None, ""):
                cleaned[k] = "***REDACTED***"
            else:
                cleaned[k] = redact_secrets(v)
        return cleaned
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [redact_secrets(item) for item in value]
    return value


def fetch_paginated(
    client: "OmadaClient",
    endpoint: str,
    *,
    page_size: int = 100,
    max_pages: int = 50,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Collect all rows across paginated Omada Web API v2 endpoints."""
    return client.paginate(endpoint, page_size=page_size, max_pages=max_pages)

#: Delay used when the controller signals a burst block (``errorCode -1600``).
BURST_BACKOFF_SECONDS = 0.8

#: Session cookies issued by Omada controllers across v5.x and v6.x builds.
SESSION_COOKIE_NAMES: Tuple[str, ...] = ("TPOMADA_SESSIONID", "TPEAP_SESSIONID")

#: Controllers report the account role three different ways depending on build:
#: ``roleName`` (6.2+), an integer ``privilege`` (5.x), or a ``privilege`` object
#: carrying only the site scope (6.2 with a local account). All three are folded
#: into one readable label plus an optional scope string.
_PRIVILEGE_LABELS = {0: "viewer", 1: "admin", 2: "owner"}

#: Controllers answer ``-1600`` both for "path not registered" and for "slow
#: down"; a single paced retry disambiguates the two in practice.
_MAX_BURST_RETRIES = 1

ERROR_CATALOG: Dict[int, Dict[str, Any]] = {
    0: {
        "title": "Success",
        "meaning": "The controller accepted and completed the request.",
        "fix": "No action needed.",
        "ambiguous": False,
        "causes": ["Normal successful response."],
    },
    -1: {
        "title": "General error",
        "meaning": ("General error -- usually a required field is missing from the request body "
                    "or the endpoint requires higher privileges, not a credentials problem."),
        "fix": ("Compare your request body against a full GET of the object (e.g. include "
                "ipSetting.netId for client fixed IP) or verify the account role."),
        "ambiguous": True,
        "causes": [
            "Required field omitted in PATCH/POST body (such as ipSetting.netId).",
            "Endpoint restricted for the current account role (e.g. Viewer calling Admin-only paths).",
        ],
    },
    -1001: {
        "title": "Bean validation failure",
        "meaning": ("Bean-validation failure: the body is missing a mandatory field "
                    "(e.g. lanNetworkIpv6Config.proto and lanNetworkIpv6Config.enable when PATCHing a LAN network)."),
        "fix": ("Send the complete object obtained from GET .../networks/interface and ensure "
                "nested fields like lanNetworkIpv6Config={'proto': 'none', 'enable': 0} are present."),
        "ambiguous": False,
        "causes": [
            "Partial PATCH body missing mandatory nested fields.",
            "lanNetworkIpv6Config.proto or lanNetworkIpv6Config.enable omitted on LAN network update.",
        ],
    },
    -1007: {
        "title": "Insufficient user permissions",
        "meaning": ("The current user account does not have permission for this endpoint or operation "
                    "(for example, a Viewer account attempting a write on Omada 6.x)."),
        "fix": "Use a dedicated Admin account for write operations; keep Viewer accounts for read-only mode.",
        "ambiguous": False,
        "causes": [
            "Viewer or read-only role calling an Admin-only write endpoint.",
            "Account privilege lacks permission for the target site setting.",
        ],
    },
    -1505: {
        "title": "No permission for this site",
        "meaning": ("No permission for this site: the URL needs the hex site ID, not the site "
                    "name. Run `omada-mcp --doctor` to resolve it."),
        "fix": ("Set OMADA_SITE_NAME or OMADA_SITE_ID so omada-mcp resolves the controller's "
                "internal hex site ID, and verify the user account has access to that site."),
        "ambiguous": False,
        "causes": [
            "Site display name used in the URL path instead of the internal hex site ID.",
            "Account does not have permission for the target site.",
        ],
    },
    -1600: {
        "title": "Unsupported request path or burst rate-limit",
        "meaning": ("Unsupported request path -- or a burst block. The path shape is wrong when "
                    "the endpoint is not in the documented table; more than ~5 rapid calls "
                    "produce the same code until you pace them (0.8 s)."),
        "fix": ("Pace requests with OMADA_MIN_INTERVAL_SECONDS=0.8 (GET calls automatically retry "
                "once after 0.8 s). If it still returns -1600 on retry, check the URL path shape "
                "(e.g. DELETE /groups/0/{groupId} requires the type segment, and GET /networks/{id} "
                "is unsupported -- use the collection endpoint)."),
        "ambiguous": True,
        "causes": [
            "Burst rate-limiting (>~5 requests in a couple of seconds without 0.8 s pacing).",
            "Wrong or unsupported Web API v2 endpoint path shape or missing path segment.",
        ],
    },
    -30104: {
        "title": "Authentication failed or account locked",
        "meaning": "The controller rejected the login credentials or temporarily locked the account.",
        "fix": ("Verify OMADA_USERNAME and OMADA_PASSWORD against a browser login at the same URL; "
                "wait a few minutes if repeated attempts triggered a temporary lockout."),
        "ambiguous": False,
        "causes": [
            "Incorrect username or password.",
            "Temporary lockout after repeated failed login attempts.",
        ],
    },
    -30109: {
        "title": "Invalid credentials or expired session",
        "meaning": ("Session expired or invalid (when returned after login), or wrong "
                    "username/password (when returned by /api/v2/login)."),
        "fix": ("On /api/v2/login, verify OMADA_USERNAME and OMADA_PASSWORD (note repeated failures "
                "lock the account briefly). On other endpoints, re-authenticate to obtain a fresh "
                "token and session cookie."),
        "ambiguous": True,
        "causes": [
            "Incorrect username or password on /api/v2/login.",
            "Expired or evicted server-side session token/cookie on subsequent API calls.",
        ],
    },
    -33001: {
        "title": "No gateways adopted in site",
        "meaning": ("This setting or service requires an adopted Omada gateway (router) in the "
                    "target site, and none is currently adopted."),
        "fix": ("Adopt an Omada gateway (e.g. ER605/ER7206/ER8411) on this site before "
                "configuring UPnP or gateway-only services."),
        "ambiguous": False,
        "causes": ["Calling a gateway-only endpoint such as setting/upnp on a gatewayless site."],
    },
    -33239: {
        "title": "SSID limit reached or duplicate SSID name",
        "meaning": ("The controller rejected creating or updating the SSID because the name "
                    "already exists in the WLAN group or the maximum SSID count was reached."),
        "fix": "Choose a distinct SSID name within the WLAN group or remove an unused SSID first.",
        "ambiguous": False,
        "causes": ["Duplicate SSID name in the same WLAN group or per-radio SSID limit exceeded."],
    },
    -33515: {
        "title": "LAN interface ports missing",
        "meaning": ("Creating an interface (routed) LAN network requires at least one gateway "
                    "LAN port in interfaceIds."),
        "fix": ("Supply interfaceIds (from setting/wan/networks osgPortInfo.wanLanPortSettings "
                "where mode=1) or create a pure VLAN network with purpose='vlan'."),
        "ambiguous": False,
        "causes": ["POST setting/lan/networks with purpose='interface' and empty interfaceIds."],
    },
    -33598: {
        "title": "Device does not support Network Isolation",
        "meaning": ("The controller refused enabling VLAN network isolation because no adopting/capable "
                    "gateway or switch on the site supports Network Isolation on that network."),
        "fix": ("Adopt an isolation-capable Omada gateway/switch or use gateway ACL rules on "
                "controller-only/standalone sites instead."),
        "ambiguous": False,
        "causes": [
            "Site has no adopted Omada gateway/switch supporting VLAN isolation (existNetworkIsolation=false).",
        ],
    },
    -33601: {
        "title": "Invalid ACL destination type",
        "meaning": ("Invalid gateway ACL destination type for the chosen rule direction (for example, "
                    "using destinationType=0 'network' on a LAN->WAN rule)."),
        "fix": ("For LAN->WAN rules, use destination.type='ip_group' (e.g. 'IPGroup_Any') or "
                "'port_group'; destination.type='network' is only valid when direction.lanToLan is enabled."),
        "ambiguous": False,
        "causes": [
            "destinationType=0 (network) selected on a LAN->WAN gateway ACL without lanToLan.",
        ],
    },
    -33717: {
        "title": "Object is referenced elsewhere; delete refused",
        "meaning": ("Object is referenced elsewhere and cannot be deleted directly (for example, "
                    "an IP profile group still referenced by a gateway ACL rule)."),
        "fix": ("Re-point every referencing rule to a temporary group first, delete and recreate "
                "the target group, re-point the rules back, then delete the temporary group "
                "(the replace_ip_group tool automates this swap)."),
        "ambiguous": False,
        "causes": [
            "Attempting to DELETE an IP profile group while a firewall ACL rule references its ID.",
        ],
    },
    -33726: {
        "title": "IP group entry limit exceeded",
        "meaning": ("IP group is full: a group holds at most 16 entries. Store an address "
                    "range as network-aligned CIDRs instead of one /32 per host."),
        "fix": ("Collapse contiguous /32 host entries into network-aligned CIDR blocks (for "
                "example .180-.191 fits in 4 CIDRs instead of 12) so the group stays within the "
                "16-entry limit."),
        "ambiguous": False,
        "causes": ["Attempting to create or replace an IP profile group with more than 16 entries."],
    },
    -34522: {
        "title": "DHCP reservation or IP-MAC conflict",
        "meaning": ("The requested static DHCP IP or MAC conflicts with an existing reservation "
                    "or IP-MAC binding entry."),
        "fix": ("Choose an unused IP/MAC or update the existing DHCP reservation record "
                "instead of creating a duplicate."),
        "ambiguous": False,
        "causes": ["Duplicate MAC or IP across setting/service/dhcp or IP-MAC bindings."],
    },
    -39005: {
        "title": "Device is disconnected or not ready",
        "meaning": ("The controller refused the command because the target device is disconnected "
                    "or pending adoption."),
        "fix": "Ensure the device is connected (statusCategory=1) before running LED/locate or reboot.",
        "ambiguous": False,
        "causes": ["Calling cmd/devices/{MAC}/locate or device config on an offline device."],
    },
    -39006: {
        "title": "Device does not exist",
        "meaning": "No managed device matches the specified MAC address on this site.",
        "fix": "Resolve the device MAC via list_devices first (do not pass a client MAC).",
        "ambiguous": False,
        "causes": ["Unknown or unadopted device MAC passed to cmd/devices/{MAC}/*."],
    },
    -39303: {
        "title": "Access point does not exist",
        "meaning": "No adopted EAP (access point) matches the specified MAC on this site.",
        "fix": "Check list_devices and confirm the device type is 'ap'.",
        "ambiguous": False,
        "causes": ["Calling PATCH eaps/{MAC} with an unknown or non-AP MAC."],
    },
    -39501: {
        "title": "Gateway does not exist",
        "meaning": "No adopted gateway matches the specified MAC on this site.",
        "fix": "Check list_devices and confirm the device type is 'gateway'.",
        "ambiguous": False,
        "causes": ["Calling PATCH gateways/{MAC} with an unknown or non-gateway MAC."],
    },
    -39700: {
        "title": "Switch does not exist",
        "meaning": "No adopted switch matches the specified MAC on this site.",
        "fix": "Check list_devices and confirm the device type is 'switch'.",
        "ambiguous": False,
        "causes": ["Calling PATCH switches/{MAC} with an unknown or non-switch MAC."],
    },
    -41002: {
        "title": "Client does not exist",
        "meaning": "The target client MAC was not found in the active client table for this command.",
        "fix": ("Check search_clients/list_clients for the exact client MAC (note some client "
                "commands only accept currently known/active clients)."),
        "ambiguous": False,
        "causes": ["Calling cmd/clients/{MAC}/block or unblock on an unknown client MAC."],
    },
    -41011: {
        "title": "Not a client or Admin-only endpoint",
        "meaning": ("This client does not exist -- either the target MAC belongs to a managed "
                    "network device (switch/AP/gateway) rather than a client, the MAC is unknown "
                    "to the site, or a Viewer account called an Admin-only clients/* endpoint."),
        "fix": ("Resolve client MACs via sites/{siteId}/insight/clients (never pass a switch/AP/"
                "gateway MAC from devices), and ensure write operations use an Admin account."),
        "ambiguous": True,
        "causes": [
            "Managed device MAC (switch/AP/gateway) passed to sites/{siteId}/clients/{MAC}.",
            "Viewer account calling the Admin-only sites/{siteId}/clients* endpoint.",
            "Target client MAC is not present in the site's client table.",
        ],
    },
    -44116: {
        "title": "Open API is not enabled",
        "meaning": ("Open API is not enabled: the controller needs Platform Integration for "
                    "openapi/*. The Web API used here does not."),
        "fix": ("Use the Web API v2 paths (/{omadacId}/api/v2/...) used by omada-mcp instead of "
                "/openapi/v1, or enable Platform Integration if using the Open API."),
        "ambiguous": False,
        "causes": ["Calling /openapi/* endpoints without Platform Integration configured."],
    },
}

ERROR_HINTS: Dict[int, str] = {code: entry["meaning"] for code, entry in ERROR_CATALOG.items()}


def _endpoint_context(code: int, endpoint: Optional[str], method: Optional[str]) -> Optional[str]:
    ep = (endpoint or "").strip().lower()
    meth = (method or "").strip().upper()
    if code in (-30109, -30104) and "login" in ep:
        return ("On /api/v2/login, this indicates invalid username/password (or temporary "
                "lockout), not an expired session.")
    if code == -1600:
        if meth in ("POST", "PATCH", "PUT", "DELETE"):
            return (f"On {meth} {endpoint or ''}, -1600 usually means an unsupported path+method "
                    "pair or missing path segment (e.g. DELETE /groups/{type}/{groupId}); do not "
                    "blindly retry writes.")
        if ep or meth:
            return (f"On {meth or 'GET'} {endpoint or ''}, -1600 may be either burst rate-limiting "
                    "(retry once after 0.8 s) or an unsupported endpoint path shape (e.g. "
                    "GET setting/lan/networks/{id} is unsupported).")
    if code == -41011 and "clients" in ep and "insight" not in ep:
        return ("sites/{siteId}/clients* requires an Admin account and a known client MAC "
                "(device MACs from devices return -41011; Viewer accounts must use insight/clients).")
    if code == -41002 and "cmd/clients" in ep:
        return ("cmd/clients/{MAC}/block|unblock only operates on clients registered on the site.")
    if code == -33001:
        return "This setting requires at least one adopted Omada gateway on the site."
    if code == -33717 and "groups" in ep:
        return ("The IP group is still referenced by one or more ACL rules; re-point rules to a "
                "temporary group before deleting.")
    if code == -1001 and "lan/networks" in ep and meth == "PATCH":
        return ("PATCHing a LAN network requires the complete object from setting/lan/networks/"
                "interface with lanNetworkIpv6Config={'proto': 'none', 'enable': 0} present.")
    if code == -1001 and "ssids" in ep and meth == "PATCH":
        return ("PATCHing an SSID requires the full SSID object (not a sparse diff); start from "
                "the GET setting/wlans/{wlanId}/ssids record minus server metadata fields.")
    if code == -1 and "clients" in ep:
        return ("PATCHing clients/{MAC} requires ipSetting.netId (the LAN network hex id) and "
                "Admin privileges.")
    if code == -33515 and "lan/networks" in ep:
        return ("POST setting/lan/networks with purpose='interface' requires at least one "
                "gateway LAN portUuid in interfaceIds.")
    return None


def describe_error(
    code: Optional[int],
    msg: str = "",
    endpoint: Optional[str] = None,
    method: Optional[str] = None,
) -> str:
    """Human explanation for an Omada ``errorCode`` (falls back to the raw msg)."""
    if code is None:
        return msg or "unknown error"
    num = int(code)
    context = _endpoint_context(num, endpoint, method)
    if num == -30109 and endpoint and "login" in endpoint.lower():
        hint: Optional[str] = ("Invalid username or password (or account temporarily locked after "
                               "repeated failures).")
    elif context and num == -1600:
        hint = context
    else:
        hint = ERROR_HINTS.get(num)
    text = f"errorCode {code}"
    if msg:
        text += f": {msg}"
    if hint:
        text += f" -- {hint}"
    return text


def explain_error_code(code: int, endpoint: Optional[str] = None) -> Dict[str, Any]:
    """Return structured explanation, ambiguity notes, and remediation for an ``errorCode``."""
    num = int(code)
    entry = ERROR_CATALOG.get(num)
    ep = endpoint.strip() if endpoint and endpoint.strip() else None
    ep_context = _endpoint_context(num, ep, None) if ep else None
    if entry is None:
        return {
            "code": num,
            "known": False,
            "title": "Undocumented Omada errorCode",
            "meaning": f"errorCode {num} is not in the omada-mcp catalog.",
            "fix": ("Check `omada-mcp --doctor`, inspect the endpoint path and required fields, "
                    "and compare against a browser DevTools request on the controller UI."),
            "ambiguous": False,
            "causes": [],
            "endpointContext": ep_context,
            "summary": f"errorCode {num}: undocumented code",
        }
    return {
        "code": num,
        "known": True,
        "title": entry["title"],
        "meaning": entry["meaning"],
        "fix": entry["fix"],
        "ambiguous": bool(entry["ambiguous"]),
        "causes": list(entry["causes"]),
        "endpointContext": ep_context,
        "summary": describe_error(num, endpoint=ep),
    }


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


class OmadaSessionExpiredError(OmadaError):
    """Raised when a non-GET request receives HTML on HTTP 200 (session evicted/expired).

    ``OmadaClient.api`` re-authenticates once before raising so callers such as
    ``OmadaClient.write`` can re-read state safely instead of blindly replaying
    a mutating POST/PATCH/DELETE.
    """

    def __init__(
        self,
        message: str,
        *,
        reauthenticated: bool = True,
        hint: Optional[str] = None,
        endpoint: Optional[str] = None,
    ):
        super().__init__(message, hint=hint, endpoint=endpoint)
        self.reauthenticated = reauthenticated


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
    controller_family: str = "unknown"
    session_cookie: Optional[str] = None


def classify_controller_family(
    info: Mapping[str, Any],
    session_cookie: Optional[str] = None,
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
            urllib.request.HTTPSHandler(context=ssl_context),
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
        )
        self.timeout = timeout
        self._ssl_context = ssl_context
        self._use_system_proxy = bool(use_system_proxy)
        self._conn_lock = threading.RLock()
        self._pool: Dict[Tuple[str, str, int], http.client.HTTPConnection] = {}
        self.connections_created = 0
        self.requests_reused = 0

    def _should_use_opener(self, scheme: str, host: str, port: Optional[int]) -> bool:
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
        self, key: Tuple[str, str, int], conn: Optional[http.client.HTTPConnection],
    ) -> None:
        if self._pool.get(key) is conn:
            self._pool.pop(key, None)
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - best-effort socket cleanup
                pass

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
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
            self._pool.clear()

    def _request_via_opener(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]],
        data: Optional[bytes],
        req_timeout: float,
    ) -> Tuple[int, bytes]:
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
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[int, bytes]:
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
                send_headers: Dict[str, str] = dict(headers or {})
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
                ) as exc:
                    self._drop_conn(key, conn)
                    if idempotent and attempt == 0:
                        continue
                    if not idempotent:
                        raise OmadaError(
                            f"connection closed after sending non-idempotent {method_upper} {target}: {exc}",
                            hint="verify controller state before retrying; write was not replayed automatically",
                            endpoint=target,
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
                    self.cookie_jar.extract_cookies(_CookieResponseAdapter(headers_obj), cookie_req)
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
        context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT")
    if config.tls_server_name:
        pinned_name = config.tls_server_name
        orig_wrap = context.wrap_socket

        def _wrap_with_pinned_name(sock, *args, **kwargs):
            kwargs["server_hostname"] = pinned_name
            return orig_wrap(sock, *args, **kwargs)

        context.wrap_socket = _wrap_with_pinned_name  # type: ignore[method-assign]
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
        self._adaptive_min_interval = 0.0
        self._last_write_at: Optional[float] = None
        self._snapshot_seq = 0
        self._auth_in_progress = False
        self._cache: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None
        self._cache_depth: int = 0
        self._cache_bypass_depth: int = 0
        self.token: Optional[str] = None
        self.controller_id: Optional[str] = None
        self.site: Optional[SiteInfo] = None
        self.auth_info: Optional[AuthInfo] = None
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
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
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
        info_out: Dict[str, Any] = {
            "omadacId": controller_id,
            "controllerVer": str(result.get("controllerVer") or result.get("version") or ""),
            "apiVer": result.get("apiVer"),
            "configured": result.get("configured"),
        }
        for extra in ("model", "deviceModel", "hardware", "omadacCategory", "type"):
            if extra in result and result[extra] is not None:
                info_out[extra] = result[extra]
        return info_out

    def session_cookie_name(self) -> Optional[str]:
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
        use_cache: bool = True,
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
                if self._cache is not None and self._cache_bypass_depth == 0:
                    cached = self._cache.get(cache_key)
                    if cached is not None:
                        return copy.deepcopy(cached)
        elif method_upper != "GET":
            with self._lock:
                if self._cache is not None:
                    self._cache.clear()

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
            cookie_name = self.session_cookie_name()
            cookie_state = f"cookie={cookie_name} present, server-side session expired" \
                if cookie_name else "no session cookie"
            self._log(f"session expired (HTML response; {cookie_state}); "
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
        if use_cache and method_upper == "GET" and data is None and code in (0, None):
            with self._lock:
                if self._cache is not None and self._cache_bypass_depth == 0:
                    self._cache[cache_key] = copy.deepcopy(payload)
        return payload

    def api_result(self, endpoint: str, method: str = "GET",
                   data: Optional[Dict[str, Any]] = None) -> Any:
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
    ) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Collect all rows across paginated Omada Web API v2 endpoints."""
        collected: List[Dict[str, Any]] = []
        last_meta: Optional[Dict[str, Any]] = None
        prev_rows: Optional[List[Dict[str, Any]]] = None
        sep = "&" if "?" in endpoint else "?"
        for page in range(1, max_pages + 1):
            paged = f"{endpoint}{sep}currentPage={page}&currentPageSize={page_size}"
            result = self.api_result(paged)
            if isinstance(result, list):
                collected.extend(dict(r) for r in result if isinstance(r, Mapping))
                return collected, None
            if not isinstance(result, Mapping):
                break
            last_meta = dict(result)
            raw_rows = result.get("data")
            if not isinstance(raw_rows, list) or not raw_rows:
                break
            rows = [dict(r) for r in raw_rows if isinstance(r, Mapping)]
            if prev_rows is not None and rows == prev_rows:
                break
            prev_rows = rows
            collected.extend(rows)
            total = result.get("totalRows")
            if total is not None:
                if len(collected) >= int(total):
                    break
            elif len(rows) < page_size:
                break
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
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass
        return directory

    def _save_snapshot(self, tool_name: str, target: str, payload: Any) -> str:
        directory = self._ensure_snapshot_dir()
        self._snapshot_seq += 1
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_tool = self._safe_filename_part(tool_name, "write")
        safe_target = self._safe_filename_part(target, "target")
        filename = f"{stamp}-{self._snapshot_seq:04d}-{safe_tool}-{safe_target}.json"
        path = directory / filename
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "tool": tool_name,
            "target": target,
            "account": self.config.username,
            "data": redact_secrets(payload),
        }
        path.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str) + "\n",
                        encoding="utf-8")
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
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
        detail: Optional[str] = None,
    ) -> None:
        directory = self._ensure_snapshot_dir()
        audit_path = directory / "audit.jsonl"
        entry: Dict[str, Any] = {
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
            try:
                os.chmod(audit_path, 0o600)
            except OSError:
                pass

    @staticmethod
    def _verify_expect_keys(
        expect_keys: Mapping[str, Any],
        after: Any,
    ) -> Tuple[bool, Optional[str]]:
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

    def _require_write_allowed(self, tool_name: Optional[str], endpoint: str) -> None:
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
        data: Optional[Dict[str, Any]] = None,
        *,
        expect_keys: Optional[Mapping[str, Any]] = None,
        tool_name: Optional[str] = None,
        target: Optional[str] = None,
        before: Any = None,
        snapshot_payload: Any = None,
        read_back: Optional[Callable[[], Any]] = None,
        verify_fn: Optional[Callable[[Any, Any], Tuple[bool, Optional[str]]]] = None,
        reauth_prepare: Optional[Callable[[], Tuple[bool, Optional[Dict[str, Any]], Any]]] = None,
        fields_changed: Any = None,
    ) -> Dict[str, Any]:
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
        data: Optional[Dict[str, Any]],
        expect_keys: Optional[Mapping[str, Any]],
        eff_tool: str,
        eff_target: str,
        eff_fields: Any,
        before: Any,
        snapshot_payload: Any,
        read_back: Optional[Callable[[], Any]],
        verify_fn: Optional[Callable[[Any, Any], Tuple[bool, Optional[str]]]],
        reauth_prepare: Optional[Callable[[], Tuple[bool, Optional[Dict[str, Any]], Any]]],
    ) -> Dict[str, Any]:
        with self._lock:
            snap_data = before if snapshot_payload is None else snapshot_payload
            snapshot_id = self._save_snapshot(eff_tool, eff_target, snap_data)

            already_applied = False
            payload: Optional[Dict[str, Any]] = None
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
        closer = getattr(self._transport, "close", None)
        if callable(closer):
            closer()
