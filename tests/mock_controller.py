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
        self.dhcp_reservations: List[Dict[str, Any]] = []
        self.port_forwards: List[Dict[str, Any]] = []
        self.static_routes: List[Dict[str, Any]] = []
        self.mdns_rules: List[Dict[str, Any]] = []
        self.mdns_profiles: List[Dict[str, Any]] = [
            {"id": "buildIn-1", "name": "AirPlay", "serviceId": ["_airplay._tcp.local"], "defaultProfile": True},
            {"id": "buildIn-7", "name": "Printers", "serviceId": ["_ipp._tcp.local"], "defaultProfile": True},
        ]
        self.upnp: Dict[str, Any] = {"enable": False, "resource": 0}
        self.dns_proxy: Dict[str, Any] = {"enable": False, "supportDnsOverride": True}
        self.ddns: Dict[str, Any] = {"data": [], "totalRows": 0}
        self.wan: Dict[str, Any] = {
            "wanMode": 0,
            "osgPortInfo": {
                "wanLanPortSettings": [
                    {"portUuid": "wan-port-1", "portName": "WAN", "mode": 0, "status": 1},
                    {"portUuid": "lan-port-1", "portName": "LAN1", "mode": 1, "status": 1},
                ]
            },
        }
        now_ms = int(time.time() * 1000)
        self.logs_alerts: List[Dict[str, Any]] = [
            {"id": "al-1", "level": 2, "type": 1, "module": 1, "content": "Mock alert entry", "time": now_ms - 60000, "resolved": False},
        ]
        self.logs_events: List[Dict[str, Any]] = [
            {"id": "ev-1", "level": 4, "type": 10, "module": 2, "content": "Client connected", "time": now_ms - 30000},
        ]
        self.logs_audit: List[Dict[str, Any]] = [
            {"id": "au-1", "level": 4, "auditType": 1, "content": "Admin session started", "operator": username, "time": now_ms - 15000},
        ]

        # Milestone 1 / Milestone 2 diagnostic & config fixtures mapped to MockController MACs
        sp_fx = load_fixture("switch_ports.json")
        er_fx = load_fixture("eap_radios.json")
        tw_fx = load_fixture("topology_and_wan.json")

        sw_detail = copy.deepcopy(sp_fx["switch_detail"])
        sw_detail.update({"mac": "AA-BB-CC-00-00-02", "name": "sw-access"})
        if isinstance(sw_detail.get("uplink"), dict):
            sw_detail["uplink"].update({"mac": "AA-BB-CC-00-00-01", "name": "gw-core"})
        self.switch_details: Dict[str, Dict[str, Any]] = {"AA-BB-CC-00-00-02": sw_detail}

        sw_ports = copy.deepcopy(sp_fx["ports"])
        for p in sw_ports:
            p["switchMac"] = "AA-BB-CC-00-00-02"
            ps = p.get("portStatus")
            if isinstance(ps, dict) and ps.get("port") == 3:
                ps["chassisId"] = "AA-BB-CC-00-00-03"
                ps["portId"] = "AA-BB-CC-00-00-03"
            elif isinstance(ps, dict) and ps.get("port") == 17:
                ps["chassisId"] = "AA-BB-CC-00-00-01"
                ps["portId"] = "AA-BB-CC-00-00-01"
        self.switch_ports: Dict[str, List[Dict[str, Any]]] = {"AA-BB-CC-00-00-02": sw_ports}
        self.switch_lags: Dict[str, List[Dict[str, Any]]] = {"AA-BB-CC-00-00-02": copy.deepcopy(sp_fx.get("lags", []))}

        self.switch_insight_counters: Dict[str, List[Dict[str, Any]]] = {
            "AA-BB-CC-00-00-02": [
                {**copy.deepcopy(r), "switchMac": "AA-BB-CC-00-00-02", "switchName": "sw-access"}
                for r in sp_fx.get("insight_counters", [])
            ]
        }
        self.switch_insight_poe: Dict[str, List[Dict[str, Any]]] = {
            "AA-BB-CC-00-00-02": [
                {**copy.deepcopy(r), "switchMac": "AA-BB-CC-00-00-02", "switchName": "sw-access"}
                for r in sp_fx.get("insight_poe", [])
            ]
        }
        ins_detail = copy.deepcopy(sp_fx.get("insight_switch_detail", []))
        if ins_detail:
            ins_detail[0]["mac"] = "AA-BB-CC-00-00-02"
        self.switch_insight_detail: List[Dict[str, Any]] = ins_detail
        self.switch_stat: Dict[str, Dict[str, Any]] = {
            "AA-BB-CC-00-00-02": copy.deepcopy(sp_fx.get("stat_switch", {}))
        }
        ct_ports = copy.deepcopy(sp_fx.get("cable_test_ports", []))
        for ctp in ct_ports:
            for dl in ctp.get("downlinkDevices") or []:
                if isinstance(dl, dict):
                    if dl.get("type") == "ap":
                        dl.update({"mac": "AA-BB-CC-00-00-03", "name": "ap-living"})
                    elif dl.get("type") == "gateway":
                        dl.update({"mac": "AA-BB-CC-00-00-01", "name": "gw-core"})
        self.cable_test_ports: Dict[str, List[Dict[str, Any]]] = {"AA-BB-CC-00-00-02": ct_ports}
        self.cable_test_results: Dict[str, Dict[str, Any]] = {
            "AA-BB-CC-00-00-02": copy.deepcopy(sp_fx.get("cable_test_full", {"status": 0, "data": []}))
        }
        self.port_profiles: List[Dict[str, Any]] = copy.deepcopy(sp_fx["lan_profiles"]["data"])

        ap_detail = copy.deepcopy(er_fx["eap_detail"])
        ap_detail.update({"mac": "AA-BB-CC-00-00-03", "name": "ap-living", "wlanId": "wlan-grp-1"})
        self.eap_details: Dict[str, Dict[str, Any]] = {"AA-BB-CC-00-00-03": ap_detail}
        self.eap_channel_info: Dict[str, Any] = {
            "AA-BB-CC-00-00-03": copy.deepcopy(er_fx["eap_channel_info"])
        }
        self.eap_rf_scan: Dict[str, Dict[str, Any]] = {
            "AA-BB-CC-00-00-03": copy.deepcopy(er_fx["eap_rf_scan"])
        }

        gw_detail = copy.deepcopy(tw_fx["gateway_detail"])
        gw_detail.update({"mac": "AA-BB-CC-00-00-01", "name": "gw-core"})
        self.gateway_details: Dict[str, Dict[str, Any]] = {"AA-BB-CC-00-00-01": gw_detail}
        self.wan_lan_status: Dict[str, Any] = copy.deepcopy(tw_fx["wanlanstatus"])
        self.port_state_details: Dict[str, Any] = copy.deepcopy(tw_fx["portstatedetails"])
        self.speedtest_result: Optional[Dict[str, Any]] = None
        topo = copy.deepcopy(tw_fx["topology_v2"])
        if topo.get("topologyArray"):
            gw_node = topo["topologyArray"][0]
            gw_node.update({"mac": "AA-BB-CC-00-00-01", "name": "gw-core"})
            for sw_node in gw_node.get("successors") or []:
                if sw_node.get("type") == "switch":
                    sw_node.update({"mac": "AA-BB-CC-00-00-02", "name": "sw-access"})
                    for child in sw_node.get("successors") or []:
                        if child.get("type") == "ap":
                            child.update({"mac": "AA-BB-CC-00-00-03", "name": "ap-living"})
        self.topology_v2: Dict[str, Any] = topo

        self.ips_settings: Dict[str, Any] = copy.deepcopy(tw_fx["setting_ips"])
        self.threat_alerts: List[Dict[str, Any]] = copy.deepcopy(tw_fx["ips_threat_management"].get("data", []))
        self.attack_defense: Dict[str, Any] = copy.deepcopy(tw_fx["setting_attackdefense"])
        self.rogue_aps: List[Dict[str, Any]] = copy.deepcopy(tw_fx["insight_rogueaps"].get("data", []))
        self.wids_events: List[Dict[str, Any]] = []
        self.wids_blacklist: List[Dict[str, Any]] = []
        self.wids_supported: bool = False

        self.vpn_tunnels: List[Dict[str, Any]] = []
        self.vpn_configs: List[Dict[str, Any]] = []
        self.wireguard_configs: List[Dict[str, Any]] = []
        self.wireguard_peers: List[Dict[str, Any]] = []
        self.past_connections: List[Dict[str, Any]] = []

        self.policy_routes: List[Dict[str, Any]] = copy.deepcopy(tw_fx["policy_routings"].get("data", []))
        self.lan_dns_rules: List[Dict[str, Any]] = copy.deepcopy(tw_fx["lan_dns"].get("data", []))
        self.switch_acls: List[Dict[str, Any]] = copy.deepcopy(tw_fx["acls_switch"].get("data", []))
        self.eap_acls: List[Dict[str, Any]] = copy.deepcopy(tw_fx["acls_eap"].get("data", []))
        self.rate_limit_profiles: List[Dict[str, Any]] = [
            {
                "id": "rl-prof-1",
                "name": "Guest-10M",
                "downLimit": {"enable": True, "limit": 10000, "unit": 1},
                "upLimit": {"enable": True, "limit": 5000, "unit": 1},
            },
            {
                "id": "rl-prof-2",
                "name": "IoT-2M",
                "downLimit": {"enable": True, "limit": 2000, "unit": 1},
                "upLimit": {"enable": True, "limit": 1000, "unit": 1},
            },
        ]

        self.has_gateway: bool = True
        self.lan_dns_supported: bool = True
        self.topology_v2_supported: bool = True

        self.cookie_jar = http.cookiejar.CookieJar()
        self.token: str = "tok-mock-001"
        self.logins: int = 0
        self.requests: List[Dict[str, Any]] = []
        self._id_seq: int = 100

        # Fault-injection controls
        self.html_once_for: set[Any] = set()
        self.html_always_for: set[Any] = set()
        self.burst_once_for: set[Any] = set()
        self.expired_once_for: set[Any] = set()
        self.silent_noop_for: set[Any] = set()
        self.corrupt_dhcp_on_patch: bool = False
        self.drop_collection_isolation_sync: bool = False
        self.omada62_lan_normalization: bool = False
        self.next_fault_hook: Optional[
            Callable[[str, str, Any], Optional[Tuple[int, Dict[str, Any]]]]
        ] = None

    @property
    def write_request_count(self) -> int:
        return sum(1 for req in self.requests if req["method"] in ("POST", "PATCH", "PUT", "DELETE")
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
        expired_once = self._match_fault_set(self.expired_once_for, method, full_path)
        if expired_once is not None:
            self.expired_once_for.discard(expired_once)
            self.cookie_jar.clear()
            return self._err(-30109, "Session expired.")

        if not self._is_authenticated(req_headers):
            return 200, b"<!DOCTYPE html><html><title>Login</title></html>"

        if self.next_fault_hook is not None:
            custom = self.next_fault_hook(method.upper(), full_path, body_obj)
            if custom is not None:
                status, payload = custom
                return self._json_response(payload, status=status)

        if method.upper() in ("POST", "PATCH", "PUT", "DELETE"):
            if "viewer" in self.role.lower():
                return self._err(-1007, "The current user does not have permissions to access this page.")

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

    @staticmethod
    def _paginate_rows(rows: Sequence[Dict[str, Any]], params: Mapping[str, List[str]]) -> Dict[str, Any]:
        total = len(rows)
        if "currentPage" in params:
            page = max(1, int(params["currentPage"][0]))
            size = max(1, int(params.get("currentPageSize", ["100"])[0]))
            start = (page - 1) * size
            chunk = list(rows[start:start + size])
            return {
                "data": copy.deepcopy(chunk),
                "totalRows": total,
                "currentPage": page,
                "currentSize": size,
            }
        return {"data": copy.deepcopy(list(rows)), "totalRows": total}

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
            return self._ok(self._paginate_rows(self.devices, params))

        m_dev_cfg = re.fullmatch(r"sites/([^/]+)/(eaps|switches|gateways)/([^/]+)(?:/config/general)?", ep)
        if m_dev_cfg:
            kind, mac_raw = m_dev_cfg.group(2), m_dev_cfg.group(3)
            has_general = ep.endswith("/config/general")
            if method == "PUT" and not has_general:
                return self._err(-1600, "PUT on device root requires /config/general.")
            mac = _normalize_mac(urllib.parse.unquote(mac_raw))
            kind_map = {"eaps": ("ap", -39303), "switches": ("switch", -39700), "gateways": ("gateway", -39501)}
            expected_type, err_code = kind_map[kind]
            dev = next((d for d in self.devices if _normalize_mac(d["mac"]) == mac and d.get("type") == expected_type), None)
            if dev is None:
                return self._err(err_code, f"{kind} device does not exist.")
            if method == "GET" and not has_general:
                store = {
                    "eaps": self.eap_details,
                    "switches": self.switch_details,
                    "gateways": self.gateway_details,
                }[kind]
                merged = copy.deepcopy(dev)
                merged.update(copy.deepcopy(store.get(mac, {})))
                return self._ok(merged)
            if method in ("PATCH", "PUT"):
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Device update body must be JSON object.")
                store = {
                    "eaps": self.eap_details,
                    "switches": self.switch_details,
                    "gateways": self.gateway_details,
                }[kind]
                for k, v in body.items():
                    dev[k] = copy.deepcopy(v)
                    if mac in store:
                        store[mac][k] = copy.deepcopy(v)
                return self._ok(copy.deepcopy(dev))
            return self._err(-1600, "Method not supported.")

        m_dev_cmd = re.fullmatch(r"sites/([^/]+)/cmd/devices/([^/]+)/(locate|reboot)", ep)
        if m_dev_cmd and method == "POST":
            mac = _normalize_mac(urllib.parse.unquote(m_dev_cmd.group(2)))
            action = m_dev_cmd.group(3)
            dev = next((d for d in self.devices if _normalize_mac(d["mac"]) == mac), None)
            if dev is None:
                return self._err(-39303, "Device does not exist.")
            if action == "locate":
                if isinstance(body, Mapping) and "locateEnable" in body:
                    dev["locateEnable"] = bool(body["locateEnable"])
            elif action == "reboot":
                dev["lastReboot"] = int(time.time() * 1000)
            return self._ok({})

        m_ic = re.fullmatch(r"sites/([^/]+)/insight/clients", ep)
        if m_ic and method == "GET":
            rows = []
            for c in self.clients.values():
                rows.append({
                    "mac": c["mac"],
                    "name": c.get("name") or c["mac"],
                    "hostName": c.get("hostName", ""),
                    "ip": c.get("ip", ""),
                    "wireless": bool(c.get("wireless")),
                    "guest": bool(c.get("guest")),
                    "active": bool(c.get("active", True)),
                    "ssid": c.get("ssid", ""),
                    "apName": c.get("apName") or c.get("switchName", ""),
                    "networkName": c.get("networkName", ""),
                    "vid": c.get("vid", 1),
                    "download": c.get("trafficDown", 0),
                    "upload": c.get("trafficUp", 0),
                    "duration": c.get("uptime", 0),
                    "lastSeen": c.get("lastSeen", 0),
                    "signalLevel": c.get("signalLevel", 0),
                })
            return self._ok(self._paginate_rows(rows, params))

        m_clients_col = re.fullmatch(r"sites/([^/]+)/clients", ep)
        if m_clients_col and method == "GET":
            if "viewer" in self.role.lower():
                return self._err(-1007, "Insufficient user permissions for clients endpoint.")
            if "filters.active" not in params:
                return self._err(-1, "filters.active parameter is required.")
            want_active = params["filters.active"][0].lower() == "true"
            rows = [
                copy.deepcopy(c) for c in self.clients.values()
                if bool(c.get("active", True)) == want_active
            ]
            return self._ok(self._paginate_rows(rows, params))

        m_client_cmd = re.fullmatch(r"sites/([^/]+)/cmd/clients/([^/]+)/(block|unblock|reconnect)", ep)
        if m_client_cmd and method == "POST":
            mac = _normalize_mac(urllib.parse.unquote(m_client_cmd.group(2)))
            action = m_client_cmd.group(3)
            if any(_normalize_mac(d["mac"]) == mac for d in self.devices):
                return self._err(-41011, "Managed device MAC is not a client.")
            client_obj = self.clients.get(mac)
            if client_obj is None:
                return self._err(-41011, "Client not found.")
            if action == "block":
                client_obj["blocked"] = True
            elif action == "unblock":
                client_obj["blocked"] = False
            elif action == "reconnect":
                if not client_obj.get("wireless") or not client_obj.get("active", True):
                    return self._err(-41002, "Client is not an online wireless client.")
                client_obj["lastReconnect"] = int(time.time() * 1000)
            return self._ok({})

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
                lock_setting = body.get("clientLockToApSetting")
                if isinstance(lock_setting, Mapping):
                    aps = lock_setting.get("aps")
                    if isinstance(aps, list) and any(not isinstance(a, str) for a in aps):
                        return self._err(-1001, "clientLockToApSetting.aps must be wire MAC strings.")
                updated = copy.deepcopy(client_obj)
                for k, v in body.items():
                    updated[k] = copy.deepcopy(v)
                self.clients[mac] = updated
                return self._ok(copy.deepcopy(updated))
            return self._err(-1600, "Method not supported.")

        m_wan = re.fullmatch(r"sites/([^/]+)/setting/wan/networks", ep)
        if m_wan and method == "GET":
            return self._ok(copy.deepcopy(self.wan))

        m_lan_col = re.fullmatch(r"sites/([^/]+)/setting/lan/networks", ep)
        if m_lan_col:
            if method == "GET":
                return self._ok(self._paginate_rows(self.lan_collection, params))
            if method == "POST":
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid LAN network body.")
                if body.get("domain") == "":
                    return self._err(-1001, "domain must not be empty string.")
                purpose = str(body.get("purpose") or "interface")
                if purpose == "interface" and not (body.get("interfaceIds") or []):
                    return self._err(-33515, "Select at least one LAN interface port.")
                new_id = self._next_id("net-new")
                col_item = {
                    "id": new_id,
                    "name": str(body.get("name") or new_id),
                    "vlan": int(body.get("vlan", 1)),
                    "purpose": purpose,
                    "isolation": bool(body.get("isolation", False)),
                    "existNetworkIsolation": bool(body.get("isolation", False)),
                    "accessControlRule": False,
                    "igmpSnoopEnable": bool(body.get("igmpSnoopEnable", False)),
                    "gatewaySubnet": body.get("gatewaySubnet"),
                    "dhcpSettings": copy.deepcopy(body.get("dhcpSettings") or {"enable": False}),
                }
                self.lan_collection.append(col_item)
                if purpose == "interface":
                    iface_item = copy.deepcopy(dict(body))
                    iface_item["id"] = new_id
                    iface_item.setdefault("origName", str(body.get("name") or new_id))
                    iface_item["lanNetworkIpv6Config"] = {"enable": 0}
                    iface_item.setdefault("dhcpGuard", {})
                    iface_item.setdefault("dhcpv6Guard", {})
                    iface_item.setdefault("icmpPingEnable", True)
                    self.lan_interfaces.append(iface_item)
                return self._ok({"id": new_id})
            return self._err(-1600, "Method not supported.")

        m_lan_iface = re.fullmatch(r"sites/([^/]+)/setting/lan/networks/interface", ep)
        if m_lan_iface and method == "GET":
            return self._ok(self._paginate_rows(self.lan_interfaces, params))

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
                    return self._err(-1001, "Parameter [proto] should not be null.")
                if v6.get("enable") is None:
                    return self._err(-1001, "Parameter [enable] should not be null.")
                for gk in ("dhcpGuard", "dhcpv6Guard"):
                    gv = body.get(gk)
                    if isinstance(gv, Mapping) and gv.get("enable") is None:
                        return self._err(-1001, f"Parameter [{gk}.enable] should not be null.")
                idx = next((i for i, item in enumerate(self.lan_interfaces) if str(item["id"]) == nid), None)
                if idx is None:
                    return self._err(-1600, "Network not found.")
                prev_iface = self.lan_interfaces[idx]
                new_iface = copy.deepcopy(dict(body))
                new_iface["id"] = nid
                if self.omada62_lan_normalization:
                    new_v6 = dict(new_iface.get("lanNetworkIpv6Config") or {})
                    new_v6.pop("proto", None)
                    new_iface["lanNetworkIpv6Config"] = new_v6
                    new_iface["qosQueueEnable"] = False
                    if "name" in new_iface and (
                        "origName" in prev_iface or new_iface.get("name") != prev_iface.get("name")
                    ):
                        new_iface["origName"] = new_iface["name"]
                    if isinstance(new_iface.get("dhcpSettings"), dict):
                        for legacy_dns in ("dns1", "dns2"):
                            new_iface["dhcpSettings"].pop(legacy_dns, None)
                if self.corrupt_dhcp_on_patch and isinstance(new_iface.get("dhcpSettings"), dict):
                    new_iface["dhcpSettings"]["leaseTime"] = 999
                self.lan_interfaces[idx] = new_iface

                col_item = next((c for c in self.lan_collection if str(c["id"]) == nid), None)
                if col_item is not None:
                    for field in ("name", "igmpSnoopEnable", "dhcpSettings"):
                        if field in new_iface:
                            col_item[field] = copy.deepcopy(new_iface[field])
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
            if method == "DELETE":
                target_col = next((c for c in self.lan_collection if str(c.get("id")) == nid), None)
                if target_col is None:
                    return self._err(-1600, "Network not found.")
                if int(target_col.get("vlan", 0)) == 1:
                    return self._err(-33501, "Cannot delete default LAN network.")
                self.lan_collection = [c for c in self.lan_collection if str(c.get("id")) != nid]
                self.lan_interfaces = [i for i in self.lan_interfaces if str(i.get("id")) != nid]
                return self._ok({})
            return self._err(-1600, "Method not allowed.")

        m_dhcp = re.fullmatch(r"sites/([^/]+)/setting/service/dhcp", ep)
        if m_dhcp:
            if method == "GET":
                return self._ok(self._paginate_rows(self.dhcp_reservations, params))
            if method == "POST":
                if not isinstance(body, Mapping) or not body.get("mac") or not body.get("ip") or not body.get("netId"):
                    return self._err(-1001, "mac, ip, and netId are required.")
                mac_norm = _normalize_mac(body["mac"])
                if any(_normalize_mac(r.get("mac", "")) == mac_norm for r in self.dhcp_reservations):
                    return self._err(-34522, "MAC reservation already exists.")
                if any(str(r.get("ip")) == str(body["ip"]) and str(r.get("netId")) == str(body["netId"]) for r in self.dhcp_reservations):
                    return self._err(-34522, "IP reservation already exists.")
                new_id = self._next_id("dhcp-new")
                created = copy.deepcopy(dict(body))
                created["id"] = new_id
                created.setdefault("status", True)
                created.setdefault("description", "")
                created.setdefault("exportToIpMacBinding", True)
                self.dhcp_reservations.append(created)
                return self._ok({"id": new_id})
            return self._err(-1600, "Method not supported.")

        m_dhcp_mac = re.fullmatch(r"sites/([^/]+)/setting/service/dhcp/([^/]+)", ep)
        if m_dhcp_mac:
            mac_norm = _normalize_mac(urllib.parse.unquote(m_dhcp_mac.group(2)))
            idx = next((i for i, r in enumerate(self.dhcp_reservations) if _normalize_mac(r.get("mac", "")) == mac_norm), None)
            if idx is None:
                return self._err(-1600, "DHCP reservation not found.")
            if method == "PUT":
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid body.")
                updated = copy.deepcopy(self.dhcp_reservations[idx])
                updated.update(copy.deepcopy(dict(body)))
                self.dhcp_reservations[idx] = updated
                return self._ok({})
            if method == "DELETE":
                self.dhcp_reservations.pop(idx)
                return self._ok({})
            return self._err(-1600, "Method not supported.")

        m_groups = re.fullmatch(r"sites/([^/]+)/setting/profiles/groups", ep)
        if m_groups:
            if method == "GET":
                return self._ok(self._paginate_rows(self.groups, params))
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
                created["groupId"] = new_id
                self.groups.append(created)
                return self._ok(new_id)
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
                g for g in self.groups
                if not (str(g.get("groupId") or g.get("id")) == gid and int(g.get("type", 0)) == gtype)
            ]
            if len(self.groups) == before_len:
                return self._err(-1600, "Group not found.")
            return self._ok({})

        m_acls = re.fullmatch(r"sites/([^/]+)/setting/firewall/acls", ep)
        if m_acls:
            acl_t = params.get("type", ["0"])[0]
            acl_store = {"0": self.acls, "1": self.switch_acls, "2": self.eap_acls}.get(acl_t)
            if acl_store is None:
                return self._err(-1600, f"Invalid ACL type {acl_t!r}.")
            if method == "GET":
                paged = self._paginate_rows(acl_store, params)
                paged["aclDisable"] = self.acl_disable
                return self._ok(paged)
            if method == "POST":
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid ACL body.")
                direction = body.get("direction") if isinstance(body.get("direction"), Mapping) else {}
                if acl_t == "0" and direction.get("lanToWan") and not direction.get("lanToLan") and int(body.get("destinationType", -1)) == 0:
                    return self._err(-33601, "Invalid Destination Type.")
                new_id = self._next_id("acl-new")
                created = copy.deepcopy(dict(body))
                created["id"] = new_id
                created.setdefault("index", len(acl_store))
                acl_store.append(created)
                return self._ok({"id": new_id})
            return self._err(-1600, "Method not supported.")

        m_acl_id = re.fullmatch(r"sites/([^/]+)/setting/firewall/acls/([^/]+)", ep)
        if m_acl_id:
            if method == "PATCH":
                return self._err(-1600, "Unsupported request path.")
            acl_t = params.get("type", [""])[0]
            acl_store = {"0": self.acls, "1": self.switch_acls, "2": self.eap_acls}.get(acl_t)
            if acl_store is None:
                return self._err(-1600, "ACL PUT/DELETE requires ?type=0, 1, or 2.")
            acl_id = m_acl_id.group(2)
            idx = next((i for i, a in enumerate(acl_store) if str(a.get("id")) == acl_id), None)
            if idx is None:
                return self._err(-1600, "ACL rule not found.")
            if method == "PUT":
                updated = copy.deepcopy(acl_store[idx])
                if isinstance(body, Mapping):
                    for k, v in body.items():
                        updated[k] = copy.deepcopy(v)
                updated["id"] = acl_id
                if isinstance(body, Mapping) and "syslog" in body and body["syslog"] != acl_store[idx].get("syslog"):
                    updated["existSyslog"] = bool(updated.get("syslog"))
                acl_store[idx] = updated
                return self._ok({})
            if method == "DELETE":
                acl_store.pop(idx)
                return self._ok({})
            return self._err(-1600, "Method not supported.")

        m_wlans = re.fullmatch(r"sites/([^/]+)/setting/wlans", ep)
        if m_wlans and method == "GET":
            return self._ok(self._paginate_rows(self.wlans, params))

        m_ssids = re.fullmatch(r"sites/([^/]+)/setting/wlans/([^/]+)/ssids", ep)
        if m_ssids:
            gid = m_ssids.group(2)
            if method == "GET":
                return self._ok(self._paginate_rows(self.ssids_by_group.get(gid, []), params))
            if method == "POST":
                if not isinstance(body, Mapping) or not body.get("name"):
                    return self._err(-1001, "SSID name is required.")
                new_id = self._next_id("ssid-new")
                created = copy.deepcopy(dict(body))
                created["id"] = new_id
                created["wlanId"] = gid
                self.ssids_by_group.setdefault(gid, []).append(created)
                return self._ok({"id": new_id})
            return self._err(-1600, "Method not supported.")

        m_ssid_id = re.fullmatch(r"sites/([^/]+)/setting/wlans/([^/]+)/ssids/([^/]+)", ep)
        if m_ssid_id:
            gid, sid = m_ssid_id.group(2), m_ssid_id.group(3)
            items = self.ssids_by_group.get(gid, [])
            idx = next((i for i, s in enumerate(items) if str(s.get("id")) == sid), None)
            if idx is None:
                return self._err(-1600, "SSID not found.")
            if method == "PATCH":
                if not isinstance(body, Mapping) or "band" not in body or "security" not in body:
                    return self._err(-1001, "SSID PATCH requires full DTO (band/security missing).")
                if any(k in body for k in ("id", "wlanId", "site")):
                    return self._err(-1001, "SSID PATCH rejects server-only keys.")
                updated = copy.deepcopy(dict(body))
                updated["id"] = sid
                updated["wlanId"] = gid
                items[idx] = updated
                return self._ok({})
            if method == "DELETE":
                items.pop(idx)
                return self._ok({})
            return self._err(-1600, "Method not supported.")

        crud_collections = {
            "setting/transmission/portForwardings": (self.port_forwards, "pf-new"),
            "setting/transmission/staticRoutings": (self.static_routes, "sr-new"),
            "setting/service/mdns": (self.mdns_rules, "mdns-new"),
        }
        for path_suffix, (store, id_prefix) in crud_collections.items():
            m_col = re.fullmatch(rf"sites/([^/]+)/{re.escape(path_suffix)}", ep)
            if m_col:
                if method == "GET":
                    return self._ok(self._paginate_rows(store, params))
                if method == "POST":
                    if not isinstance(body, Mapping):
                        return self._err(-1001, "Invalid body.")
                    new_id = self._next_id(id_prefix)
                    created = copy.deepcopy(dict(body))
                    created["id"] = new_id
                    store.append(created)
                    return self._ok({"id": new_id})
                return self._err(-1600, "Method not supported.")
            m_item = re.fullmatch(rf"sites/([^/]+)/{re.escape(path_suffix)}/([^/]+)", ep)
            if m_item:
                rid = m_item.group(2)
                idx = next((i for i, item in enumerate(store) if str(item.get("id")) == rid), None)
                if idx is None:
                    return self._err(-1600, "Rule not found.")
                if method == "PUT":
                    if not isinstance(body, Mapping):
                        return self._err(-1001, "Invalid body.")
                    updated = copy.deepcopy(store[idx])
                    updated.update(copy.deepcopy(dict(body)))
                    updated["id"] = rid
                    store[idx] = updated
                    return self._ok({})
                if method == "DELETE":
                    store.pop(idx)
                    return self._ok({})
                return self._err(-1600, "Method not supported.")

        m_mdns_prof = re.fullmatch(r"sites/([^/]+)/setting/profiles/mdns", ep)
        if m_mdns_prof and method == "GET":
            return self._ok(self._paginate_rows(self.mdns_profiles, params))

        m_upnp = re.fullmatch(r"sites/([^/]+)/setting/upnp", ep)
        if m_upnp:
            if method == "GET":
                return self._ok(copy.deepcopy(self.upnp))
            if method == "PUT":
                if not isinstance(body, Mapping) or "enable" not in body:
                    return self._err(-1001, "enable is required.")
                enabled = bool(body["enable"])
                if enabled:
                    wan_ports = body.get("wanPortIds")
                    net_ids = body.get("networkIds")
                    if not isinstance(wan_ports, list) or not wan_ports or not isinstance(net_ids, list) or not net_ids:
                        return self._err(-1001, "Invalid request parameters.")
                    self.upnp["wanPortIds"] = [str(p) for p in wan_ports]
                    self.upnp["networkIds"] = [str(n) for n in net_ids]
                else:
                    self.upnp.pop("wanPortIds", None)
                    self.upnp.pop("networkIds", None)
                self.upnp["enable"] = enabled
                return self._ok({})
            return self._err(-1600, "Method not supported.")

        m_dns_proxy = re.fullmatch(r"sites/([^/]+)/setting/dns-proxy", ep)
        if m_dns_proxy and method == "GET":
            return self._ok(copy.deepcopy(self.dns_proxy))

        m_ddns = re.fullmatch(r"sites/([^/]+)/setting/service/ddns", ep)
        if m_ddns and method == "GET":
            return self._ok(copy.deepcopy(self.ddns))

        m_logs = re.fullmatch(r"sites/([^/]+)/logs/(alerts|events)", ep)
        if m_logs and method == "GET":
            kind = m_logs.group(2)
            if "filters.timeStart" not in params or "filters.timeEnd" not in params:
                return self._err(-1001 if kind == "alerts" else -1, "timeStart and timeEnd required.")
            rows = self.logs_alerts if kind == "alerts" else self.logs_events
            return self._ok(self._paginate_rows(rows, params))

        m_audit = re.fullmatch(r"sites/([^/]+)/audit/logs", ep)
        if m_audit and method == "GET":
            return self._ok(self._paginate_rows(self.logs_audit, params))

        # -- Milestone 1 & Milestone 2 endpoints ------------------------------
        m_sw_ports = re.fullmatch(r"sites/([^/]+)/switches/([^/]+)/ports", ep)
        if m_sw_ports and method == "GET":
            mac = _normalize_mac(urllib.parse.unquote(m_sw_ports.group(2)))
            if mac not in self.switch_ports:
                return self._err(-39700, "Switch does not exist.")
            return self._ok(copy.deepcopy(self.switch_ports[mac]))

        m_sw_port_item = re.fullmatch(r"sites/([^/]+)/switches/([^/]+)/ports/(\d+)", ep)
        if m_sw_port_item and method == "PATCH":
            mac = _normalize_mac(urllib.parse.unquote(m_sw_port_item.group(2)))
            pnum = int(m_sw_port_item.group(3))
            ports = self.switch_ports.get(mac)
            if ports is None:
                return self._err(-39700, "Switch does not exist.")
            idx = next((i for i, r in enumerate(ports) if int(r.get("port", 0)) == pnum), None)
            if idx is None:
                return self._err(-1001, f"Switch port {pnum} does not exist.")
            if not isinstance(body, Mapping):
                return self._err(-1001, "Invalid body.")
            if not body.get("profileOverrideEnable") and any(
                k in body for k in ("poe", "portIsolationEnable", "lldpMedEnable", "spanningTreeEnable")
            ):
                return self._err(-1001, "Override fields require profileOverrideEnable=True.")
            updated = copy.deepcopy(ports[idx])
            for k, v in body.items():
                updated[k] = copy.deepcopy(v)
            if "profileId" in body:
                prof = next((p for p in self.port_profiles if str(p.get("id")) == str(body["profileId"])), None)
                if prof is None:
                    return self._err(-1001, f"Unknown profileId {body['profileId']!r}.")
                updated["profileName"] = prof.get("name", updated.get("profileName"))
                if int(prof.get("type", 0)) == 1:
                    updated["disable"] = True
                else:
                    updated["disable"] = False
            ports[idx] = updated
            return self._ok({})

        m_sw_port_restart = re.fullmatch(r"sites/([^/]+)/cmd/switches/([^/]+)/ports/(\d+)/restart", ep)
        if m_sw_port_restart and method == "POST":
            mac = _normalize_mac(urllib.parse.unquote(m_sw_port_restart.group(2)))
            pnum = int(m_sw_port_restart.group(3))
            ports = self.switch_ports.get(mac)
            if ports is None:
                return self._err(-39700, "Switch does not exist.")
            row = next((r for r in ports if int(r.get("port", 0)) == pnum), None)
            if row is None:
                return self._err(-1001, f"Switch port {pnum} does not exist.")
            row["lastPoeCycleAt"] = int(time.time() * 1000)
            return self._ok({})

        m_sw_lags = re.fullmatch(r"sites/([^/]+)/switches/([^/]+)/lags", ep)
        if m_sw_lags and method == "GET":
            mac = _normalize_mac(urllib.parse.unquote(m_sw_lags.group(2)))
            return self._ok(copy.deepcopy(self.switch_lags.get(mac, [])))

        m_ins_cnt = re.fullmatch(r"sites/([^/]+)/insight/switch/port/counters", ep)
        if m_ins_cnt and method == "GET":
            all_rows = [row for rows in self.switch_insight_counters.values() for row in rows]
            return self._ok(self._paginate_rows(all_rows, params))

        m_ins_poe = re.fullmatch(r"sites/([^/]+)/insight/switch/port/poe", ep)
        if m_ins_poe and method == "GET":
            all_rows = [row for rows in self.switch_insight_poe.values() for row in rows]
            return self._ok(self._paginate_rows(all_rows, params))

        m_ins_sw_detail = re.fullmatch(r"sites/([^/]+)/insight/switch/detail", ep)
        if m_ins_sw_detail and method == "GET":
            return self._ok(copy.deepcopy(self.switch_insight_detail))

        m_ct_ports = re.fullmatch(r"sites/([^/]+)/cable-test/switches/([^/]+)/ports", ep)
        if m_ct_ports and method == "GET":
            mac = _normalize_mac(urllib.parse.unquote(m_ct_ports.group(2)))
            return self._ok(copy.deepcopy(self.cable_test_ports.get(mac, [])))

        m_ct_full = re.fullmatch(r"sites/([^/]+)/cable-test/switches/([^/]+)/full-results", ep)
        if m_ct_full and method == "GET":
            mac = _normalize_mac(urllib.parse.unquote(m_ct_full.group(2)))
            return self._ok(copy.deepcopy(self.cable_test_results.get(mac, {"status": 0, "data": []})))

        m_stat_sw = re.fullmatch(r"sites/([^/]+)/stat/switches/([^/]+)", ep)
        if m_stat_sw and method == "GET":
            mac = _normalize_mac(urllib.parse.unquote(m_stat_sw.group(2)))
            return self._ok(copy.deepcopy(self.switch_stat.get(mac, {"ports": []})))

        m_eap_ci = re.fullmatch(r"sites/([^/]+)/eaps/([^/]+)/channelInfo", ep)
        if m_eap_ci and method == "GET":
            mac = _normalize_mac(urllib.parse.unquote(m_eap_ci.group(2)))
            if mac not in self.eap_channel_info:
                return self._err(-39303, "EAP does not exist.")
            return self._ok(copy.deepcopy(self.eap_channel_info[mac]))

        m_eap_rf = re.fullmatch(r"sites/([^/]+)/eaps/([^/]+)/tools/rfScan", ep)
        if m_eap_rf and method == "GET":
            mac = _normalize_mac(urllib.parse.unquote(m_eap_rf.group(2)))
            if mac not in self.eap_rf_scan:
                return self._err(-39303, "EAP does not exist.")
            return self._ok(copy.deepcopy(self.eap_rf_scan[mac]))

        m_eap_rf_cmd = re.fullmatch(r"sites/([^/]+)/cmd/eaps/([^/]+)/tools/rfScan", ep)
        if m_eap_rf_cmd and method == "POST":
            mac = _normalize_mac(urllib.parse.unquote(m_eap_rf_cmd.group(2)))
            if mac not in self.eap_details:
                return self._err(-39303, "EAP does not exist.")
            rf_obj = self.eap_rf_scan.setdefault(mac, {"status": 0})
            rf_obj["lastScanAt"] = int(time.time() * 1000)
            if isinstance(body, Mapping) and "scanType" in body:
                rf_obj["lastScanBands"] = copy.deepcopy(body["scanType"])
            return self._ok({})

        m_eap_radios = re.fullmatch(r"sites/([^/]+)/eaps/([^/]+)/config/radios", ep)
        if m_eap_radios:
            mac = _normalize_mac(urllib.parse.unquote(m_eap_radios.group(2)))
            ap = self.eap_details.get(mac)
            if ap is None:
                return self._err(-39303, "EAP does not exist.")
            if method == "GET":
                out = {k: copy.deepcopy(ap[k]) for k in ("radioSetting2g", "radioSetting5g", "radioSetting5g1", "radioSetting5g2", "radioSetting6g") if k in ap}
                return self._ok(out)
            if method in ("PUT", "PATCH"):
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid radio body.")
                for k, v in body.items():
                    if k.startswith("radioSetting"):
                        ap[k] = copy.deepcopy(v)
                        dev = next((d for d in self.devices if _normalize_mac(d["mac"]) == mac), None)
                        if dev is not None:
                            dev[k] = copy.deepcopy(v)
                return self._ok({})
            return self._err(-1600, "Method not supported.")

        m_eap_wlans = re.fullmatch(r"sites/([^/]+)/eaps/([^/]+)/config/wlans", ep)
        if m_eap_wlans and method in ("PUT", "PATCH"):
            mac = _normalize_mac(urllib.parse.unquote(m_eap_wlans.group(2)))
            ap = self.eap_details.get(mac)
            if ap is None:
                return self._err(-39303, "EAP does not exist.")
            if not isinstance(body, Mapping) or "wlanId" not in body:
                return self._err(-1001, "wlanId is required.")
            wid = str(body["wlanId"])
            if not any(str(w.get("id")) == wid for w in self.wlans):
                return self._err(-1001, f"Unknown wlanId {wid!r}.")
            ap["wlanId"] = wid
            if "ssidOverrides" in body:
                ap["ssidOverrides"] = copy.deepcopy(body["ssidOverrides"])
            dev = next((d for d in self.devices if _normalize_mac(d["mac"]) == mac), None)
            if dev is not None:
                dev["wlanId"] = wid
            return self._ok({})

        m_wlan_ssid = re.fullmatch(r"sites/([^/]+)/wlanSsid", ep)
        if m_wlan_ssid and method == "GET":
            rows = [
                {
                    "wlanId": g["id"],
                    "wlanName": g["name"],
                    "primary": g.get("primary", False),
                    "ssids": copy.deepcopy(self.ssids_by_group.get(g["id"], [])),
                }
                for g in self.wlans
            ]
            return self._ok(rows)

        m_profiles = re.fullmatch(r"sites/([^/]+)/setting/lan/profiles", ep)
        if m_profiles:
            if method == "GET":
                return self._ok(self._paginate_rows(self.port_profiles, params))
            if method == "POST":
                if not isinstance(body, Mapping) or not body.get("name"):
                    return self._err(-1001, "Profile name required.")
                new_id = self._next_id("prof-new")
                created = copy.deepcopy(dict(body))
                created.update({"id": new_id, "type": 0, "prohibitModify": False})
                self.port_profiles.append(created)
                return self._ok({"id": new_id})
            return self._err(-1600, "Method not supported.")

        m_profile_id = re.fullmatch(r"sites/([^/]+)/setting/lan/profiles/([^/]+)", ep)
        if m_profile_id:
            pid = m_profile_id.group(2)
            idx = next((i for i, p in enumerate(self.port_profiles) if str(p.get("id")) == pid), None)
            if idx is None:
                return self._err(-1600, "Port profile not found.")
            if method in ("PATCH", "PUT"):
                if self.port_profiles[idx].get("prohibitModify"):
                    return self._err(-1001, "Built-in port profile cannot be modified.")
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid body.")
                updated = copy.deepcopy(self.port_profiles[idx])
                updated.update(copy.deepcopy(dict(body)))
                updated["id"] = pid
                self.port_profiles[idx] = updated
                return self._ok({})
            if method == "DELETE":
                if self.port_profiles[idx].get("prohibitModify"):
                    return self._err(-1001, "Built-in port profile cannot be deleted.")
                self.port_profiles.pop(idx)
                return self._ok({})
            return self._err(-1600, "Method not supported.")

        m_rate_limits = re.fullmatch(r"sites/([^/]+)/setting/profiles/rateLimits", ep)
        if m_rate_limits and method == "GET":
            return self._ok(self._paginate_rows(self.rate_limit_profiles, params))

        m_wls = re.fullmatch(r"sites/([^/]+)/setting/wanlanstatus", ep)
        if m_wls and method == "GET":
            if not self.has_gateway:
                return self._err(-1007, "No adopted gateway.")
            return self._ok(copy.deepcopy(self.wan_lan_status))

        m_psd = re.fullmatch(r"sites/([^/]+)/dashboard/portstatedetails", ep)
        if m_psd and method == "GET":
            if not self.has_gateway:
                return self._err(-1007, "No adopted gateway.")
            return self._ok(copy.deepcopy(self.port_state_details))

        m_st = re.fullmatch(r"sites/([^/]+)/cmd/getSpeedTestResult", ep)
        if m_st and method == "GET":
            if self.speedtest_result is None:
                return self._err(-1600, "No speedtest result available.")
            return self._ok(copy.deepcopy(self.speedtest_result))

        m_vpn_stats = re.fullmatch(r"sites/([^/]+)/setting/vpn/stats/(tunnel|ipsec|sslvpn)", ep)
        if m_vpn_stats and method == "GET":
            if not self.has_gateway:
                return self._err(-1007, "No adopted gateway.")
            kind = m_vpn_stats.group(2)
            rows = [t for t in self.vpn_tunnels if t.get("vpnCategory") == kind]
            return self._ok(self._paginate_rows(rows, params))

        m_vpn_dash = re.fullmatch(r"sites/([^/]+)/dashboard/(wireguardtunnels|ipsectunnels|sslvpntunnels|openvpntunnels)", ep)
        if m_vpn_dash and method == "GET":
            if not self.has_gateway:
                return self._err(-1007, "No adopted gateway.")
            seg = m_vpn_dash.group(2)
            wanted = {"wireguardtunnels": "wireguard", "ipsectunnels": "ipsec", "sslvpntunnels": "sslvpn"}.get(seg)
            if seg == "openvpntunnels":
                ov_type = "openvpn_server" if params.get("type", ["0"])[0] == "0" else "openvpn_client"
                rows = [t for t in self.vpn_tunnels if t.get("vpnCategory") == ov_type]
            else:
                rows = [t for t in self.vpn_tunnels if t.get("vpnCategory") == wanted]
            return self._ok(copy.deepcopy(rows))

        m_vpn_cfg = re.fullmatch(r"sites/([^/]+)/setting/(vpns|wireguard|wireguard/peer)", ep)
        if m_vpn_cfg and method == "GET":
            if not self.has_gateway:
                return self._err(-1007, "No adopted gateway.")
            kind = m_vpn_cfg.group(2)
            store = {"vpns": self.vpn_configs, "wireguard": self.wireguard_configs, "wireguard/peer": self.wireguard_peers}[kind]
            return self._ok(self._paginate_rows(store, params))

        m_topo = re.fullmatch(r"sites/([^/]+)/(topology-v2|topology)", ep)
        if m_topo and method == "GET":
            which = m_topo.group(2)
            if which == "topology-v2" and not self.topology_v2_supported:
                return self._err(-1600, "topology-v2 not supported on 5.x.")
            return self._ok(copy.deepcopy(self.topology_v2))

        m_ips = re.fullmatch(r"sites/([^/]+)/setting/ips", ep)
        if m_ips and method == "GET":
            if not self.has_gateway:
                return self._err(-1007, "No adopted gateway.")
            return self._ok(copy.deepcopy(self.ips_settings))

        m_threats = re.fullmatch(r"sites/([^/]+)/ips/threat-management", ep)
        if m_threats and method == "GET":
            if not self.has_gateway:
                return self._err(-1007, "No adopted gateway.")
            return self._ok(self._paginate_rows(self.threat_alerts, params))

        m_ad = re.fullmatch(r"sites/([^/]+)/setting/firewall/attackdefense", ep)
        if m_ad and method == "GET":
            if not self.has_gateway:
                return self._err(-1007, "No adopted gateway.")
            return self._ok(copy.deepcopy(self.attack_defense))

        m_wids = re.fullmatch(r"sites/([^/]+)/insight/wids(?:/(blacklist))?", ep)
        if m_wids and method == "GET":
            if not self.wids_supported:
                return self._err(-1001, "WIDS unsupported on this controller.")
            rows = self.wids_blacklist if m_wids.group(2) else self.wids_events
            return self._ok(self._paginate_rows(rows, params))

        m_rogue = re.fullmatch(r"sites/([^/]+)/insight/rogueaps", ep)
        if m_rogue and method == "GET":
            return self._ok(self._paginate_rows(self.rogue_aps, params))

        m_past = re.fullmatch(r"sites/([^/]+)/insight/pastConnection", ep)
        if m_past and method == "GET":
            key = params.get("searchKey", [""])[0].strip().lower()
            rows = self.past_connections
            if key:
                rows = [r for r in rows if key in json.dumps(r).lower()]
            return self._ok(self._paginate_rows(rows, params))

        m_pr = re.fullmatch(r"sites/([^/]+)/setting/transmission/policyRoutings", ep)
        if m_pr:
            if not self.has_gateway:
                return self._err(-1007, "No adopted gateway.")
            if method == "GET":
                return self._ok(self._paginate_rows(self.policy_routes, params))
            if method == "POST":
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid body.")
                new_id = self._next_id("pr-new")
                created = copy.deepcopy(dict(body))
                created["id"] = new_id
                self.policy_routes.append(created)
                return self._ok({"id": new_id})
            return self._err(-1600, "Method not supported.")

        m_pr_id = re.fullmatch(r"sites/([^/]+)/setting/transmission/policyRoutings/([^/]+)", ep)
        if m_pr_id:
            if not self.has_gateway:
                return self._err(-1007, "No adopted gateway.")
            rid = m_pr_id.group(2)
            idx = next((i for i, r in enumerate(self.policy_routes) if str(r.get("id")) == rid), None)
            if idx is None:
                return self._err(-1600, "Policy route not found.")
            if method in ("PUT", "PATCH"):
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid body.")
                updated = copy.deepcopy(self.policy_routes[idx])
                updated.update(copy.deepcopy(dict(body)))
                updated["id"] = rid
                self.policy_routes[idx] = updated
                return self._ok({})
            if method == "DELETE":
                self.policy_routes.pop(idx)
                return self._ok({})
            return self._err(-1600, "Method not supported.")

        m_dns = re.fullmatch(r"sites/([^/]+)/setting/lan/dns", ep)
        if m_dns:
            if not self.lan_dns_supported:
                return self._err(-41011, "LAN DNS not supported on this controller version.")
            if method == "GET":
                res = self._paginate_rows(self.lan_dns_rules, params)
                res["supportTtl"] = True
                return self._ok(res)
            if method == "POST":
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid body.")
                new_id = self._next_id("dns-new")
                created = copy.deepcopy(dict(body))
                created["id"] = new_id
                self.lan_dns_rules.append(created)
                return self._ok({"id": new_id})
            return self._err(-1600, "Method not supported.")

        m_dns_id = re.fullmatch(r"sites/([^/]+)/setting/lan/dns/([^/]+)", ep)
        if m_dns_id:
            if not self.lan_dns_supported:
                return self._err(-41011, "LAN DNS not supported on this controller version.")
            did = m_dns_id.group(2)
            idx = next((i for i, r in enumerate(self.lan_dns_rules) if str(r.get("id")) == did), None)
            if idx is None:
                return self._err(-1600, "LAN DNS rule not found.")
            if method in ("PATCH", "PUT"):
                if not isinstance(body, Mapping):
                    return self._err(-1001, "Invalid body.")
                updated = copy.deepcopy(self.lan_dns_rules[idx])
                updated.update(copy.deepcopy(dict(body)))
                updated["id"] = did
                self.lan_dns_rules[idx] = updated
                return self._ok({})
            if method == "DELETE":
                self.lan_dns_rules.pop(idx)
                return self._ok({})
            return self._err(-1600, "Method not supported.")

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

            def do_PUT(self) -> None:
                self._handle("PUT")

            def do_PATCH(self) -> None:
                self._handle("PATCH")

            def do_DELETE(self) -> None:
                self._handle("DELETE")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

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
