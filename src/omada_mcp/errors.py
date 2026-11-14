"""Error taxonomy, Omada exception types, and secret redaction."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = [
    "ERROR_CATALOG",
    "ERROR_HINTS",
    "OmadaError",
    "OmadaSessionExpiredError",
    "describe_error",
    "explain_error_code",
    "redact_secrets",
]

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
        cleaned: dict[str, Any] = {}
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


ERROR_CATALOG: dict[int, dict[str, Any]] = {
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

ERROR_HINTS: dict[int, str] = {code: entry["meaning"] for code, entry in ERROR_CATALOG.items()}


def _endpoint_context(code: int, endpoint: str | None, method: str | None) -> str | None:
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
    code: int | None,
    msg: str = "",
    endpoint: str | None = None,
    method: str | None = None,
) -> str:
    """Human explanation for an Omada ``errorCode`` (falls back to the raw msg)."""
    if code is None:
        return msg or "unknown error"
    num = int(code)
    context = _endpoint_context(num, endpoint, method)
    if num == -30109 and endpoint and "login" in endpoint.lower():
        hint: str | None = ("Invalid username or password (or account temporarily locked after "
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


def explain_error_code(code: int, endpoint: str | None = None) -> dict[str, Any]:
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
        code: int | None = None,
        hint: str | None = None,
        endpoint: str | None = None,
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
        hint: str | None = None,
        endpoint: str | None = None,
    ):
        super().__init__(message, hint=hint, endpoint=endpoint)
        self.reauthenticated = reauthenticated
