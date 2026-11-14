"""Offline fake HTTP transport and fixture payloads for bridge unit tests."""

from __future__ import annotations

import http.cookiejar
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
TESTS = Path(__file__).resolve().parent
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from omada_mcp.client import OmadaClient  # noqa: E402
from omada_mcp.config import Config  # noqa: E402

CONTROLLER_ID = "0123456789abcdef01234567"


SITE_ID = "89abcdef0123456789abcdef"


HTML_SHELL = b"<!DOCTYPE html><html><head><title>Omada</title></head><body></body></html>"


DEVICES = [
    {"mac": "AA-BB-CC-00-00-01", "name": "gw", "type": "gateway", "showModel": "ER605",
     "ip": "192.168.20.1", "firmwareVersion": "1.3.0", "uptime": "1d", "clientNum": 4,
     "statusCategory": 1},
    {"mac": "AA-BB-CC-00-00-02", "name": "ap1", "type": "ap", "showModel": "EAP650",
     "ip": "192.168.20.2", "firmwareVersion": "1.2.0", "uptime": "2d", "clientNum": 3,
     "statusCategory": 1},
]


CLIENTS = [
    {"mac": "AA-BB-CC-11-11-01", "name": "laptop", "hostName": "laptop.lan",
     "ip": "192.168.20.31", "wireless": True, "guest": False, "vid": 20,
     "ssid": "lab", "apName": "ap1", "networkName": "LAN", "download": 10, "upload": 5,
     "duration": 60, "lastSeen": 1700000000000},
    {"mac": "aabbcc111102", "name": "desktop", "ip": "192.168.20.32", "wireless": False,
     "vid": 1, "download": 1, "upload": 1, "duration": 10, "lastSeen": 0},
]


WLANS = [
    {"id": "w1", "name": "lab", "ssid": "lab", "band": 3, "enabled": True, "guest": False,
     "security": "wpa2", "vlanId": 20, "securityKey": "super-secret-passphrase"},
]


LAN_NETWORKS = [
    {"id": "n1", "name": "Default", "vlan": 1, "gatewaySubnet": "192.168.1.1/24",
     "accessControlRule": False, "isolation": False,
     "dhcpSettings": {"enable": True, "ipRangePool": [{"ipaddrStart": "192.168.1.10", "ipaddrEnd": "192.168.1.200"}]}},
    {"id": "n20", "name": "IoT", "vlan": 20, "gatewaySubnet": "192.168.20.1/24",
     "accessControlRule": True, "isolation": False,
     "dhcpSettings": {"enable": True, "ipRangePool": [{"ipaddrStart": "192.168.20.10", "ipaddrEnd": "192.168.20.200"}]}},
]


class FakeController:
    """Minimal stateful stand-in for the controller's Web API v2."""

    def __init__(self, username="admin", password="pw", sites=None, devices=None,
                 clients=None, wlans=None, lan_networks=None, ssids_by_group=None,
                 token="tok-abc123", cookie_name="TPOMADA_SESSIONID",
                 controller_ver="5.13.30.8", controller_info_extra=None,
                 legacy_login_shape=False):
        self.username = username
        self.password = password
        self.token = token
        self.sites = sites if sites is not None else [{"id": SITE_ID, "name": "Test Site"}]
        self.devices = devices if devices is not None else DEVICES
        self.clients = clients if clients is not None else CLIENTS
        self.wlans = wlans if wlans is not None else WLANS
        self.lan_networks = lan_networks if lan_networks is not None else LAN_NETWORKS
        self.ssids_by_group = ssids_by_group or {}
        self.dhcp_reservations = [
            {"id": "d1", "mac": "AA-BB-CC-11-11-01", "ip": "192.168.20.42", "netId": "n20", "status": True, "description": "cam"}
        ]
        self.acls = [
            {"id": "acl1", "index": 0, "name": "Block IoT", "status": True, "policy": 0,
             "sourceType": 0, "sourceIds": ["n20"], "destinationType": 2, "destinationIds": [],
             "direction": {"lanToWan": True, "lanToLan": False}, "protocols": [256]}
        ]
        self.groups = [
            {"groupId": "grp1", "name": "RFC1918", "type": 0, "ipList": [{"ip": "192.168.0.0", "mask": "16"}]}
        ]
        self.port_forwards = [
            {"id": "pf1", "name": "Web", "status": True, "externalPort": "443", "forwardIp": "192.168.1.50", "forwardPort": "8443", "protocol": 6, "dMZ": False}
        ]
        self.static_routes = [
            {"id": "sr1", "name": "LabRoute", "status": True, "routeType": 0, "destinations": ["10.99.0.0/24"], "nextHopIp": "192.168.1.254", "interfaceId": "wan1", "metric": 1}
        ]
        self.mdns_rules = [{"id": "m1", "name": "Cast", "status": True, "type": 1}]
        self.mdns_profiles = [{"id": "buildIn-1", "name": "AirPlay", "serviceId": ["_airplay._tcp.local"], "defaultProfile": True}]
        self.logs = [{"id": "l1", "level": 2, "type": 1, "module": 1, "content": "Test log", "time": 1700000000000, "resolved": False}]
        self.cookie_name = cookie_name
        self.controller_ver = controller_ver
        self.controller_info_extra = controller_info_extra or {}
        self.legacy_login_shape = legacy_login_shape
        self.cookie_jar = http.cookiejar.CookieJar()
        self.requests = []
        self.logins = 0
        self.html_once_for = set()   # endpoint fragments answered with HTML exactly once
        self.html_always_for = set()  # fragments answered with HTML every time
        self.burst_once_for = set()  # endpoint fragments answered with -1600 once

    def _set_session_cookie(self):
        if not self.cookie_name:
            return
        cookie = http.cookiejar.Cookie(
            version=0, name=self.cookie_name, value="sess-123", port=None,
            port_specified=False, domain="controller.test", domain_specified=True,
            domain_initial_dot=False, path="/", path_specified=True,
            secure=True, expires=None, discard=True, comment=None,
            comment_url=None, rest={}, rfc2109=False,
        )
        self.cookie_jar.set_cookie(cookie)

    # transport protocol
    def request(self, method, url, headers=None, data=None, timeout=None):
        self.requests.append({"method": method, "url": url,
                              "headers": dict(headers or {}), "body": data})
        path = url.split("?")[0]
        if path.endswith("/api/info"):
            info_result = {"omadacId": CONTROLLER_ID, "controllerVer": self.controller_ver}
            info_result.update(self.controller_info_extra)
            return 200, json.dumps({
                "errorCode": 0,
                "result": info_result,
            }).encode()
        if path.endswith("/api/v2/login"):
            self.logins += 1
            payload = json.loads(data or b"{}")
            if payload.get("username") != self.username or payload.get("password") != self.password:
                return 200, json.dumps({"errorCode": -30109, "msg": "wrong credentials"}).encode()
            self._set_session_cookie()
            login_result = {"token": self.token}
            if self.legacy_login_shape:
                login_result["omadacId"] = CONTROLLER_ID
            return 200, json.dumps({"errorCode": 0, "result": login_result}).encode()

        fragment = path.split("/api/v2/", 1)[-1]
        for key in list(self.html_once_for):
            if fragment.startswith(key):
                self.html_once_for.discard(key)
                return 200, HTML_SHELL
        for key in self.html_always_for:
            if fragment.startswith(key):
                return 200, HTML_SHELL
        for key in list(self.burst_once_for):
            if fragment.startswith(key):
                self.burst_once_for.discard(key)
                return 200, json.dumps({"errorCode": -1600, "msg": "unsupported"}).encode()

        if fragment.startswith("users/current"):
            return 200, json.dumps({"errorCode": 0, "result": {
                "id": "u1", "privilege": 0}}).encode()
        if fragment.startswith("sites?") or fragment == "sites":
            return 200, json.dumps({"errorCode": 0, "result": {
                "data": self.sites, "totalRows": len(self.sites)}}).encode()

        site_prefix = f"sites/{SITE_ID}"
        if fragment == site_prefix:
            return 200, json.dumps({"errorCode": 0, "result": {
                "id": SITE_ID, "name": self.sites[0]["name"],
                "wan": True, "lan": True, "wlan": True}}).encode()
        if fragment.startswith(site_prefix + "/devices"):
            return 200, json.dumps({"errorCode": 0, "result": self.devices}).encode()
        if fragment.startswith(site_prefix + "/insight/clients"):
            page = 1
            if "currentPage=" in url:
                page = int(url.split("currentPage=")[1].split("&")[0])
            return 200, json.dumps({"errorCode": 0, "result": {
                "data": self.clients if page == 1 else [],
                "totalRows": len(self.clients)}}).encode()
        if fragment.startswith(site_prefix + "/setting/wlans/") and "/ssids" in fragment:
            group_id = fragment.split("/setting/wlans/", 1)[1].split("/ssids", 1)[0]
            return 200, json.dumps({"errorCode": 0, "result": {
                "data": self.ssids_by_group.get(group_id, [])}}).encode()
        if fragment.startswith(site_prefix + "/setting/wlans"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": self.wlans}}).encode()
        if fragment.startswith(site_prefix + "/setting/lan/networks"):
            return 200, json.dumps({"errorCode": 0, "result": {
                "data": self.lan_networks, "totalRows": len(self.lan_networks)}}).encode()
        if fragment == site_prefix + "/clients":
            want = "filters.active=true" in url
            rows = [c for c in self.clients if bool(c.get("active", True)) == want]
            return 200, json.dumps({"errorCode": 0, "result": {"data": rows, "totalRows": len(rows)}}).encode()
        if fragment.startswith(site_prefix + "/setting/service/dhcp"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": self.dhcp_reservations, "totalRows": len(self.dhcp_reservations)}}).encode()
        if fragment.startswith(site_prefix + "/setting/firewall/acls"):
            return 200, json.dumps({"errorCode": 0, "result": {"aclDisable": True, "data": self.acls, "totalRows": len(self.acls)}}).encode()
        if fragment.startswith(site_prefix + "/setting/profiles/groups"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": self.groups, "totalRows": len(self.groups)}}).encode()
        if fragment.startswith(site_prefix + "/setting/transmission/portForwardings"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": self.port_forwards, "totalRows": len(self.port_forwards)}}).encode()
        if fragment.startswith(site_prefix + "/setting/transmission/staticRoutings"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": self.static_routes, "totalRows": len(self.static_routes)}}).encode()
        if fragment.startswith(site_prefix + "/setting/service/mdns"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": self.mdns_rules, "totalRows": len(self.mdns_rules)}}).encode()
        if fragment.startswith(site_prefix + "/setting/profiles/mdns"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": self.mdns_profiles, "totalRows": len(self.mdns_profiles)}}).encode()
        if fragment.startswith(site_prefix + "/setting/upnp"):
            return 200, json.dumps({"errorCode": 0, "result": {"enable": False}}).encode()
        if fragment.startswith(site_prefix + "/setting/dns-proxy"):
            return 200, json.dumps({"errorCode": 0, "result": {"enable": False}}).encode()
        if fragment.startswith(site_prefix + "/setting/service/ddns"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": [], "totalRows": 0}}).encode()
        if fragment.startswith(site_prefix + "/setting/wan/networks"):
            return 200, json.dumps({"errorCode": 0, "result": {"wanMode": 0, "osgPortInfo": {"wanLanPortSettings": []}}}).encode()
        if fragment.startswith(site_prefix + "/logs/") or fragment.startswith(site_prefix + "/audit/logs"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": self.logs, "totalRows": len(self.logs)}}).encode()
        if fragment.endswith("/ports") and "/switches/" in fragment:
            return 200, json.dumps({"errorCode": 0, "result": [
                {"port": 1, "name": "Port1", "disable": False, "operation": "switching",
                 "profileId": "prof-all", "profileName": "All", "maxSpeed": 3, "speed": 3,
                 "duplex": 2, "supportPoe": True, "poe": 1,
                 "portStatus": {"port": 1, "linkStatus": 1, "linkSpeed": 3, "duplex": 2, "poe": True, "poePower": 6.5}}
            ]}).encode()
        if fragment.endswith("/channelInfo") and "/eaps/" in fragment:
            return 200, json.dumps({"errorCode": 0, "result": {"data": [
                {"radioId": 1, "band": "5G", "channelList": [
                    {"freq": 5180, "channelName": "36/5180MHz", "value": 1, "channelValue": 36, "maxPow": 23, "widthFlag": 28508992}
                ]}
            ]}}).encode()
        if fragment.endswith("/tools/rfScan") and "/eaps/" in fragment:
            return 200, json.dumps({"errorCode": 0, "result": {"time": 1700000000000, "status": 1, "status2g": 1, "status5g": 1}}).encode()
        if "/eaps/" in fragment:
            return 200, json.dumps({"errorCode": 0, "result": {
                **self.devices[1],
                "radioSetting2g": {"radioEnable": True, "channel": "11", "channelWidth": "2", "txPower": 20, "txPowerLevel": 3},
                "radioSetting5g": {"radioEnable": True, "channel": "1", "channelWidth": "5", "txPower": 23, "txPowerLevel": 3},
                "wp5g": {"actualChannel": "36 / 5180MHz", "bandWidth": "80MHz", "txPower": 23, "txUtil": 5, "rxUtil": 10, "interUtil": 2},
                "radioTraffic5g": {"txPkts": 1000, "rxPkts": 1000, "txRetryPkts": 10, "rxRetryPkts": 5, "txDropPkts": 0, "rxDropPkts": 0, "txErrPkts": 0, "rxErrPkts": 0},
            }}).encode()
        if "/switches/" in fragment:
            return 200, json.dumps({"errorCode": 0, "result": {
                "mac": "AA-BB-CC-00-00-03", "name": "sw1", "type": "switch", "showModel": "SG2210P",
                "statusCategory": 1, "poeTotalPower": 61.0, "poeRemain": 54.5, "poeRemainPercent": 89.34,
                "uplinkPort": 8,
            }}).encode()
        if fragment.startswith(site_prefix + "/setting/lan/profiles"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": [
                {"id": "prof-all", "name": "All", "type": 0, "prohibitModify": True, "poe": 2, "vlanConfigEnable": True,
                 "nativeNetworkId": "n1", "tagNetworkIds": ["n20"], "untagNetworkIds": ["n1"], "portIsolationEnable": False}
            ], "totalRows": 1}}).encode()
        if fragment.startswith(site_prefix + "/topology-v2"):
            return 200, json.dumps({"errorCode": 0, "result": {"topologyArray": [
                {"type": "gateway", "mac": "AA-BB-CC-00-00-01", "name": "gw", "model": "ER605", "statusCategory": 1,
                 "successors": [{"type": "ap", "mac": "AA-BB-CC-00-00-02", "name": "ap1", "model": "EAP650", "statusCategory": 1, "successors": []}]}
            ]}}).encode()
        return 200, json.dumps({"errorCode": -1600, "msg": "unsupported request path"}).encode()


def make_config(**overrides) -> Config:
    base = dict(base_url="https://controller.test:8043", username="admin", password="pw",
                read_only=False, min_interval=0.0)
    base.update(overrides)
    return Config(**base)


def make_client(**overrides):
    fake = FakeController()
    config = make_config(**overrides)
    sleeps = []
    client = OmadaClient(config, transport=fake, sleep=sleeps.append,
                         clock=lambda: 0.0, log_fn=lambda _msg: None)
    return client, fake, sleeps

