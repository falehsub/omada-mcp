"""Stateful mock TP-Link Omada SDN v2 controller with realistic quirks & fault injection."""

from __future__ import annotations

import copy
import http.cookiejar
import http.server
import json
import re
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
MOCK_CONTROLLER_ID = "mockctrl000000000000000000000001"
MOCK_SITE_ID = "mocksite0000000000000001"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _normalize_mac(value: str) -> str:
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum()).lower()
    if len(cleaned) == 12:
        return "-".join(cleaned[i:i + 2] for i in range(0, 12, 2)).upper()
    return str(value or "").strip().upper()


DEFAULT_WLANS: List[Dict[str, Any]] = [
    {
        "id": "wlan-grp-1",
        "name": "Default",
    }
]

DEFAULT_SSIDS_BY_GROUP: Dict[str, List[Dict[str, Any]]] = {
    "wlan-grp-1": [
        {
            "id": "ssid-corp",
            "name": "Lab-Main",
            "band": 7,
            "security": 3,
            "guestNetEnable": False,
            "broadcast": True,
            "vlanSetting": {"mode": 0, "currentVlanId": 1},
            "pskSetting": {"securityKey": "synthetic-test-passphrase-never-leak"},
        },
        {
            "id": "ssid-guest",
            "name": "Lab-Guest",
            "band": 3,
            "security": 3,
            "guestNetEnable": True,
            "broadcast": True,
            "vlanSetting": {"mode": 1, "currentVlanId": 30},
            "pskSetting": {"securityKey": "synthetic-guest-secret-never-leak"},
        },
    ]
}


class MockController:
    """Stateful Omada Web API v2 controller double modeled from live controller probes."""

    def __init__(
        self,
        *,
        username: str = "admin-writer",
        password: str = "pw",
        role: str = "Administrator",
        controller_ver: str = "6.2.10.17",
        cookie_name: str = "TPOMADA_SESSIONID",
        acl_disable: bool = True,
    ) -> None:
        self.username = username
        self.password = password
        self.role = role
        self.controller_ver = controller_ver
        self.cookie_name = cookie_name
        self.acl_disable = acl_disable

        self.sites: List[Dict[str, Any]] = [
            {
                "id": MOCK_SITE_ID,
                "name": "Mock Lab Site",
                "type": 0,
                "wan": True,
                "lan": True,
                "wlan": True,
            }
        ]
        self.devices: List[Dict[str, Any]] = load_fixture("devices.json")
        client_one = load_fixture("client_detail.json")
        client_two = copy.deepcopy(client_one)
        client_two.update({
            "mac": "AA-BB-CC-11-11-02",
            "name": "guest-tablet",
            "hostName": "guest-tablet",
            "ip": "192.168.30.88",
            "wireless": True,
            "networkName": "Guest",
            "networkId": "net-guest-30",
            "vid": 30,
            "vlan": 30,
            "guest": True,
            "ssid": "Lab-Guest",
            "apMac": "AA-BB-CC-00-00-03",
            "apName": "ap-living",
            "connectType": "wireless",
            "connectDevType": "ap",
            "ipSetting": {
                "useFixedAddr": False,
                "netId": "net-guest-30",
                "ip": "192.168.30.88",
            },
        })
        client_three = copy.deepcopy(client_one)
        client_three.update({
            "mac": "AA-BB-CC-11-11-03",
            "name": "legacy-bridge",
            "hostName": "legacy-bridge",
            "ip": "192.168.20.99",
            "supportFixedIp": False,
            "ipSetting": {
                "useFixedAddr": False,
                "netId": "net-iot-20",
                "ip": "192.168.20.99",
            },
        })
        self.clients: Dict[str, Dict[str, Any]] = {
            _normalize_mac(client_one["mac"]): client_one,
            _normalize_mac(client_two["mac"]): client_two,
            _normalize_mac(client_three["mac"]): client_three,
        }

        lan_fixture = load_fixture("lan_networks.json")
        self.lan_collection: List[Dict[str, Any]] = lan_fixture["collection"]
        self.lan_interfaces: List[Dict[str, Any]] = lan_fixture["interface"]
        self.groups: List[Dict[str, Any]] = load_fixture("ip_groups.json")
        acl_fixture = load_fixture("gateway_acls.json")
        self.acls: List[Dict[str, Any]] = acl_fixture["data"]
        if acl_disable is not None:
            self.acl_disable = acl_disable
        else:
            self.acl_disable = acl_fixture.get("aclDisable", True)

        self.wlans: List[Dict[str, Any]] = copy.deepcopy(DEFAULT_WLANS)
        self.ssids_by_group: Dict[str, List[Dict[str, Any]]] = copy.deepcopy(DEFAULT_SSIDS_BY_GROUP)

        self.cookie_jar = http.cookiejar.CookieJar()
        self.token: str = "tok-mock-001"
        self.logins: int = 0
        self.requests: List[Dict[str, Any]] = []
        self._id_seq: int = 100

        # Fault-injection controls
        self.html_once_for: set[Any] = set()
        self.html_always_for: set[Any] = set()
        self.burst_once_for: set[Any] = set()
        self.silent_noop_for: set[Any] = set()
        self.corrupt_dhcp_on_patch: bool = False
        self.drop_collection_isolation_sync: bool = False
        self.next_fault_hook: Optional[
            Callable[[str, str, Any], Optional[Tuple[int, Dict[str, Any]]]]
        ] = None

    @property
    def write_request_count(self) -> int:
        return sum(1 for req in self.requests if req["method"] in ("POST", "PATCH", "DELETE")
                   and not req["path"].endswith("/api/v2/login"))

    def _next_id(self, prefix: str) -> str:
        self._id_seq += 1
        return f"{prefix}-{self._id_seq}"

    def _set_cookie(self, host: str = "controller.test") -> None:
        self.cookie_jar.clear()
        cookie = http.cookiejar.Cookie(
            version=0,
            name=self.cookie_name,
            value=f"sess-{self.logins}",
            port=None,
            port_specified=False,
            domain=host,
            domain_specified=False,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=True,
            expires=int(time.time()) + 3600,
            discard=False,
            comment=None,
            comment_url=None,
            rest={},
        )
        self.cookie_jar.set_cookie(cookie)

    @staticmethod
    def _match_fault_set(faults: set[Any], method: str, path: str) -> Optional[Any]:
        for entry in list(faults):
            if isinstance(entry, tuple) and len(entry) == 2:
                f_method, frag = entry
                if f_method.upper() == method.upper() and frag in path:
                    return entry
            elif isinstance(entry, str) and entry in path:
                return entry
        return None

    @staticmethod
    def _json_response(payload: Any, status: int = 200) -> Tuple[int, bytes]:
        return status, json.dumps(payload).encode("utf-8")

    def _ok(self, result: Any = None, msg: str = "Success.") -> Tuple[int, bytes]:
        return self._json_response({"errorCode": 0, "msg": msg, "result": result})

    def _err(self, code: int, msg: str, status: int = 200) -> Tuple[int, bytes]:
        return self._json_response({"errorCode": code, "msg": msg}, status=status)

    def _is_authenticated(self, headers: Mapping[str, str]) -> bool:
        if not list(self.cookie_jar):
            return False
        csrf = headers.get("Csrf-Token") or headers.get("csrf-token")
        return csrf == self.token

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[int, bytes]:
        parsed = urllib.parse.urlsplit(url)
        full_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        req_headers = dict(headers or {})
        body_obj: Any = None
        if data:
            try:
                body_obj = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                body_obj = data.decode("utf-8", errors="replace")

        self.requests.append({
            "method": method.upper(),
            "url": url,
            "path": parsed.path,
            "query": parsed.query,
            "headers": req_headers,
            "body": body_obj,
        })

        # Unauthenticated bootstrap endpoint
        if parsed.path.endswith("/api/info"):
            return self._ok({
                "omadacId": MOCK_CONTROLLER_ID,
                "controllerVer": self.controller_ver,
                "configured": True,
                "type": 0,
                "supportApp": True,
            })

        # Login endpoint (rotates token and sets session cookie, mimicking single-session eviction)
        if parsed.path.endswith("/api/v2/login"):
            self.logins += 1
            if not isinstance(body_obj, Mapping) or (
                body_obj.get("username") != self.username
                or body_obj.get("password") != self.password
            ):
                return self._err(-30109, "Invalid username or password.")
            self.token = f"tok-mock-{self.logins:03d}"
            host = parsed.hostname or "controller.test"
            self._set_cookie(host)
            return self._ok({
                "token": self.token,
                "roleType": 0 if "admin" in self.role.lower() else 2,
                "privilege": self.role,
                "sitePrivilege": "All",
            })

        if parsed.path.endswith("/api/v2/loginStatus"):
            if not list(self.cookie_jar):
                return self._ok({"login": False})
            return self._ok({"login": True, "username": self.username, "role": self.role})

        # Fault-injection hooks for HTML-on-200 / rate-limit / custom faults
        if self._match_fault_set(self.html_always_for, method, full_path):
            return 200, b"<!DOCTYPE html><html><title>Login</title></html>"
        hit_once = self._match_fault_set(self.html_once_for, method, full_path)
        if hit_once is not None:
            self.html_once_for.discard(hit_once)
            self.cookie_jar.clear()
            return 200, b"<!DOCTYPE html><html><title>Login</title></html>"
        burst_once = self._match_fault_set(self.burst_once_for, method, full_path)
        if burst_once is not None:
            self.burst_once_for.discard(burst_once)
            return self._err(-1600, "Too many requests.")

        if not self._is_authenticated(req_headers):
            return 200, b"<!DOCTYPE html><html><title>Login</title></html>"

        if self.next_fault_hook is not None:
            custom = self.next_fault_hook(method.upper(), full_path, body_obj)
            if custom is not None:
                status, payload = custom
                return self._json_response(payload, status=status)

        if method.upper() in ("POST", "PATCH", "DELETE"):
            if "viewer" in self.role.lower():
                return self._err(-41011, "No permission for Viewer role.")

        if self._match_fault_set(self.silent_noop_for, method, full_path) and method.upper() != "GET":
            return self._ok({})

        return self._dispatch(method.upper(), parsed.path, parsed.query, body_obj)

    def _strip_api_prefix(self, path: str) -> str:
        marker = f"/{MOCK_CONTROLLER_ID}/api/v2/"
        if marker in path:
            return path.split(marker, 1)[1]
        marker2 = "/api/v2/"
        if marker2 in path:
            return path.split(marker2, 1)[1]
        return path.lstrip("/")

    def _dispatch(self, method: str, raw_path: str, query: str, body: Any) -> Tuple[int, bytes]:
        ep = self._strip_api_prefix(raw_path)
        params = urllib.parse.parse_qs(query)

        if ep == "users/current" and method == "GET":
            return self._ok({"name": self.username, "role": {"name": self.role}, "privilege": self.role})

        if ep == "sites" and method == "GET":
            return self._ok({"data": self.sites, "totalRows": len(self.sites)})

        m_site = re.fullmatch(r"sites/([^/]+)", ep)
        if m_site and method == "GET":
            site = next((s for s in self.sites if s["id"] == m_site.group(1)), None)
            if site is None:
                return self._err(-1600, "Site not found.")
            return self._ok(site)

        m_dev = re.fullmatch(r"sites/([^/]+)/devices", ep)
        if m_dev and method == "GET":
            return self._ok({"data": copy.deepcopy(self.devices), "totalRows": len(self.devices)})

        m_ic = re.fullmatch(r"sites/([^/]+)/insight/clients", ep)
        if m_ic and method == "GET":
            rows = []
            for c in self.clients.values():
                rows.append({
                    "mac": c["mac"],
                    "name": c["name"],
                    "hostName": c["hostName"],
                    "ip": c["ip"],
                    "wireless": c["wireless"],
                    "guest": c["guest"],
                    "active": c["active"],
                    "ssid": c["ssid"],
                    "apName": c.get("apName") or c.get("switchName", ""),
                    "networkName": c["networkName"],
                    "vid": c["vid"],
                    "download": c.get("trafficDown", 0),
                    "upload": c.get("trafficUp", 0),
                    "duration": c.get("uptime", 0),
                    "lastSeen": c.get("lastSeen", 0),
                    "signalLevel": c.get("signalLevel", 0),
                })
            return self._ok({"data": rows, "totalRows": len(rows)})

        m_client = re.fullmatch(r"sites/([^/]+)/clients/([^/]+)", ep)
        if m_client:
            mac = _normalize_mac(urllib.parse.unquote(m_client.group(2)))
            # Managed device MAC answers -41011 because devices are not clients
            if any(_normalize_mac(d["mac"]) == mac for d in self.devices):
                return self._err(-41011, "Managed device MAC is not a client.")
            client_obj = self.clients.get(mac)
            if client_obj is None:
                return self._err(-41011, "Client not found.")
            if method == "GET":
                return self._ok(copy.deepcopy(client_obj))
            if method == "PATCH":
                if not isinstance(body, Mapping):
                    return self._err(-1001, "PATCH body must be JSON object.")
                ip_setting = body.get("ipSetting")
                if isinstance(ip_setting, Mapping) and ip_setting.get("useFixedAddr"):
                    if not ip_setting.get("netId"):
                        # Real Omada returns opaque -1 with no field hint when netId is omitted
                        return self._err(-1, "General error.")
                    if not ip_setting.get("ip"):
                        return self._err(-1001, "Missing fixed ip.")
                updated = copy.deepcopy(client_obj)
                for k, v in body.items():
                    updated[k] = copy.deepcopy(v)
                self.clients[mac] = updated
                return self._ok(copy.deepcopy(updated))
            return self._err(-1600, "Method not supported.")

        m_lan_col = re.fullmatch(r"sites/([^/]+)/setting/lan/networks", ep)
        if m_lan_col and method == "GET":
            return self._ok({"data": copy.deepcopy(self.lan_collection), "totalRows": len(self.lan_collection)})

        m_lan_iface = re.fullmatch(r"sites/([^/]+)/setting/lan/networks/interface", ep)
        if m_lan_iface and method == "GET":
            return self._ok({"data": copy.deepcopy(self.lan_interfaces), "totalRows": len(self.lan_interfaces)})

        m_lan_id = re.fullmatch(r"sites/([^/]+)/setting/lan/networks/([^/]+)", ep)
        if m_lan_id:
            nid = m_lan_id.group(2)
            if method == "GET":
                # Collection/{id} GET is rejected with -1600 on real controller
                return self._err(-1600, "GET on setting/lan/networks/{id} is not supported.")
            if method == "PATCH":
                if not isinstance(body, Mapping):
                    return self._err(-1001, "PATCH body must be JSON object.")
                v6 = body.get("lanNetworkIpv6Config")
                if not isinstance(v6, Mapping) or not v6.get("proto"):
                    return self._err(-1001, "lanNetworkIpv6Config.proto is required.")
                idx = next((i for i, item in enumerate(self.lan_interfaces) if str(item["id"]) == nid), None)
                if idx is None:
                    return self._err(-1600, "Network not found.")
                new_iface = copy.deepcopy(dict(body))
                new_iface["id"] = nid
                if self.corrupt_dhcp_on_patch and isinstance(new_iface.get("dhcpSettings"), dict):
                    new_iface["dhcpSettings"]["leaseTime"] = 999
                self.lan_interfaces[idx] = new_iface

                col_item = next((c for c in self.lan_collection if str(c["id"]) == nid), None)
                if col_item is not None:
                    if "isolation" in new_iface and not self.drop_collection_isolation_sync:
                        col_item["isolation"] = bool(new_iface["isolation"])
                    dhcp_new = new_iface.get("dhcpSettings") or {}
                    pools = dhcp_new.get("ipRangePool") or []
                    if pools:
                        # Mirror ipRangeStart/End as stale/first-pool mirrors
                        col_item.setdefault("dhcpSettings", {})
                        col_item["dhcpSettings"]["ipRangeStart"] = pools[0]["ipaddrStart"]
                        col_item["dhcpSettings"]["ipRangeEnd"] = pools[-1]["ipaddrEnd"]
                return self._ok({})
            return self._err(-1600, "Method not allowed.")

        m_groups = re.fullmatch(r"sites/([^/]+)/setting/profiles/groups", ep)
        if m_groups:
            if method == "GET":
                return self._ok({"data": copy.deepcopy(self.groups), "totalRows": len(self.groups)})
            if method == "POST":
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid body.")
                ip_list = body.get("ipList") or []
                if len(ip_list) > 16:
                    return self._err(-33726, "IP group entries exceed 16.")
                name = str(body.get("name") or "")
                gtype = int(body.get("type", 0))
                if any(g.get("name") == name and int(g.get("type", 0)) == gtype for g in self.groups):
                    return self._err(-1, "Group name already exists.")
                new_id = self._next_id("grp-new")
                created = copy.deepcopy(dict(body))
                created["id"] = new_id
                self.groups.append(created)
                return self._ok({"id": new_id})
            return self._err(-1600, "No PATCH support on setting/profiles/groups.")

        # DELETE without {type} segment returns -1600
        m_group_no_type = re.fullmatch(r"sites/([^/]+)/setting/profiles/groups/([^/]+)", ep)
        if m_group_no_type:
            return self._err(-1600, "DELETE group requires /{type}/{id}.")

        m_group_typed = re.fullmatch(r"sites/([^/]+)/setting/profiles/groups/(\d+)/([^/]+)", ep)
        if m_group_typed:
            gtype = int(m_group_typed.group(2))
            gid = m_group_typed.group(3)
            if method != "DELETE":
                return self._err(-1600, "Only DELETE is supported on /groups/{type}/{id}.")
            # Check ACL reference (-33717)
            for acl in self.acls:
                if (int(acl.get("sourceType", -1)) == 1 and gid in (acl.get("sourceIds") or [])) or (
                    int(acl.get("destinationType", -1)) == 1 and gid in (acl.get("destinationIds") or [])
                ):
                    return self._err(-33717, f"Group {gid} is referenced by ACL {acl.get('id')}.")
            before_len = len(self.groups)
            self.groups = [
                g for g in self.groups if not (str(g.get("id")) == gid and int(g.get("type", 0)) == gtype)
            ]
            if len(self.groups) == before_len:
                return self._err(-1600, "Group not found.")
            return self._ok({})

        m_acls = re.fullmatch(r"sites/([^/]+)/setting/firewall/acls", ep)
        if m_acls:
            if method == "GET":
                return self._ok({
                    "aclDisable": self.acl_disable,
                    "data": copy.deepcopy(self.acls),
                    "totalRows": len(self.acls),
                })
            if method == "POST":
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid ACL body.")
                new_id = self._next_id("acl-new")
                created = copy.deepcopy(dict(body))
                created["id"] = new_id
                created.setdefault("index", len(self.acls))
                self.acls.append(created)
                return self._ok({"id": new_id})
            return self._err(-1600, "Method not supported.")

        m_acl_id = re.fullmatch(r"sites/([^/]+)/setting/firewall/acls/([^/]+)", ep)
        if m_acl_id and method == "PATCH":
            if params.get("type", [""])[0] != "0":
                return self._err(-1600, "Gateway ACL PATCH requires ?type=0.")
            acl_id = m_acl_id.group(2)
            idx = next((i for i, a in enumerate(self.acls) if str(a.get("id")) == acl_id), None)
            if idx is None:
                return self._err(-1600, "ACL rule not found.")
            updated = copy.deepcopy(self.acls[idx])
            if isinstance(body, Mapping):
                for k, v in body.items():
                    updated[k] = copy.deepcopy(v)
            updated["id"] = acl_id
            self.acls[idx] = updated
            return self._ok({})

        m_wlans = re.fullmatch(r"sites/([^/]+)/setting/wlans", ep)
        if m_wlans and method == "GET":
            return self._ok({"data": copy.deepcopy(self.wlans), "totalRows": len(self.wlans)})

        m_ssids = re.fullmatch(r"sites/([^/]+)/setting/wlans/([^/]+)/ssids", ep)
        if m_ssids and method == "GET":
            rows = copy.deepcopy(self.ssids_by_group.get(m_ssids.group(2), []))
            return self._ok({"data": rows, "totalRows": len(rows)})

        return self._err(-1600, f"Unmocked endpoint: {method} {ep}")


class MockControllerHTTPServer:
    """Optional loopback HTTP server wrapper around MockController."""

    def __init__(self, controller: Optional[MockController] = None) -> None:
        self.controller = controller or MockController()
        ctrl = self.controller

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length) if length > 0 else b""
                headers = {k: v for k, v in self.headers.items()}
                status, body = ctrl.request(method, self.path, headers=headers, data=raw)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for c in ctrl.cookie_jar:
                    self.send_header("Set-Cookie", f"{c.name}={c.value}; Path=/")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                self._handle("GET")

            def do_POST(self) -> None:
                self._handle("POST")

            def do_PATCH(self) -> None:
                self._handle("PATCH")

            def do_DELETE(self) -> None:
                self._handle("DELETE")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "MockControllerHTTPServer":
        self.thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
