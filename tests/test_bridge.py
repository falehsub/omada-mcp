"""Unit tests for omada-mcp -- stdlib only, no network, no controller required.

Run with::

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import http.cookiejar
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from omada_mcp import __version__  # noqa: E402
from omada_mcp import config as config_module  # noqa: E402
from omada_mcp.client import (  # noqa: E402
    BURST_BACKOFF_SECONDS,
    OmadaClient,
    OmadaError,
    build_ssl_context,
    classify_controller_family,
    describe_error,
    explain_error_code,
)
from omada_mcp.config import (  # noqa: E402
    Config,
    ConfigError,
    load_config,
    normalize_base_url,
    parse_env_text,
)
from omada_mcp.cli import main as cli_main  # noqa: E402
from omada_mcp.doctor import run_doctor  # noqa: E402
from omada_mcp.monitor import (  # noqa: E402
    MIN_POLL_INTERVAL_SECONDS,
    export_metrics_once,
    run_watch,
    serve_metrics_http,
)
from omada_mcp.server import Server, configure_streams  # noqa: E402
from omada_mcp.tools import (  # noqa: E402
    TOOL_MAP,
    _findings_healthy,
    normalize_mac,
    project_wlan,
)

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


class EnvTests(unittest.TestCase):
    def _write(self, directory, name, body):
        path = Path(directory) / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_parse_env_text_supports_export_quotes_and_comments(self):
        parsed = parse_env_text(
            "# comment\n"
            "export OMADA_BASE_URL=https://c:8043\n"
            'OMADA_PASSWORD="p#ss word"\n'
            "OMADA_USERNAME=admin  # inline comment\n"
            "IGNORED\n"
            "OMADA_SITE_NAME='Lab Site'\n"
        )
        self.assertEqual(parsed["OMADA_BASE_URL"], "https://c:8043")
        self.assertEqual(parsed["OMADA_PASSWORD"], "p#ss word")
        self.assertEqual(parsed["OMADA_USERNAME"], "admin")
        self.assertEqual(parsed["OMADA_SITE_NAME"], "Lab Site")
        self.assertNotIn("IGNORED", parsed)

    def test_omada_env_file_wins_over_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            explicit = self._write(tmp, "explicit.env",
                                   "OMADA_BASE_URL=https://explicit:8043\n"
                                   "OMADA_USERNAME=u1\nOMADA_PASSWORD=p1\n")
            cwd = Path(tmp) / "work"
            cwd.mkdir()
            (cwd / ".env").write_text("OMADA_USERNAME=from-cwd\n", encoding="utf-8")
            config = load_config(environ={"OMADA_ENV_FILE": str(explicit)}, cwd=cwd)
            self.assertEqual(config.username, "u1")
            self.assertEqual(config.env_file, explicit)

    def test_cwd_env_used_when_no_explicit_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp)
            (cwd / ".env").write_text(
                "OMADA_BASE_URL=controller.test\nOMADA_USERNAME=u2\nOMADA_PASSWORD=p2\n",
                encoding="utf-8")
            config = load_config(environ={}, cwd=cwd)
            self.assertEqual(config.username, "u2")
            self.assertEqual(config.base_url, "https://controller.test:8043")

    def test_xdg_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "omada-mcp"
            cfg_dir.mkdir()
            (cfg_dir / ".env").write_text(
                "OMADA_BASE_URL=https://xdg:8043\nOMADA_USERNAME=u3\nOMADA_PASSWORD=p3\n",
                encoding="utf-8")
            empty_cwd = Path(tmp) / "empty"
            empty_cwd.mkdir()
            config = load_config(environ={"XDG_CONFIG_HOME": tmp}, cwd=empty_cwd)
            self.assertEqual(config.username, "u3")

    def test_environment_overrides_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = self._write(tmp, "e.env",
                                   "OMADA_BASE_URL=https://file:8043\n"
                                   "OMADA_USERNAME=fileuser\nOMADA_PASSWORD=filepass\n")
            config = load_config(
                environ={"OMADA_ENV_FILE": str(env_file), "OMADA_USERNAME": "shelluser"},
                cwd=tmp)
            self.assertEqual(config.username, "shelluser")
            self.assertEqual(config.password, "filepass")
            self.assertEqual(config.sources["OMADA_USERNAME"], "environment")

    def test_explicit_missing_env_file_raises_with_hint(self):
        with self.assertRaises(ConfigError) as ctx:
            load_config(environ={"OMADA_ENV_FILE": "/nonexistent/omada.env"}, cwd="/tmp")
        self.assertIn("OMADA_ENV_FILE", str(ctx.exception))
        self.assertIn("fix", str(ctx.exception))

    def test_missing_required_keys_are_all_listed(self):
        with self.assertRaises(ConfigError) as ctx:
            load_config(environ={}, cwd=tempfile.mkdtemp())
        message = str(ctx.exception)
        for key in ("OMADA_BASE_URL", "OMADA_USERNAME", "OMADA_PASSWORD"):
            self.assertIn(key, message)

    def test_invalid_boolean_names_the_variable(self):
        with self.assertRaises(ConfigError) as ctx:
            load_config(environ={"OMADA_BASE_URL": "https://c:8043", "OMADA_USERNAME": "u",
                                 "OMADA_PASSWORD": "p", "OMADA_VERIFY_SSL": "maybe"},
                        cwd=tempfile.mkdtemp())
        self.assertIn("OMADA_VERIFY_SSL", str(ctx.exception))

    def test_missing_ca_bundle_is_a_config_error(self):
        with self.assertRaises(ConfigError) as ctx:
            load_config(environ={"OMADA_BASE_URL": "https://c:8043", "OMADA_USERNAME": "u",
                                 "OMADA_PASSWORD": "p",
                                 "OMADA_CA_BUNDLE": "/nope/ca.pem"},
                        cwd=tempfile.mkdtemp())
        self.assertIn("OMADA_CA_BUNDLE", str(ctx.exception))

    def test_base_url_normalisation(self):
        self.assertEqual(normalize_base_url("controller.test"), "https://controller.test:8043")
        self.assertEqual(normalize_base_url("https://c.test/"), "https://c.test:8043")
        self.assertEqual(normalize_base_url("https://c.test:8443"), "https://c.test:8443")
        self.assertEqual(normalize_base_url("http://c.test"), "http://c.test:8088")
        with self.assertRaises(ConfigError):
            normalize_base_url("ftp://c.test")
        with self.assertRaises(ConfigError):
            normalize_base_url("https://user:pw@c.test:8043")

    def test_masked_config_hides_password(self):
        config = make_config(password="hunter2")
        masked = config.masked()
        self.assertNotIn("hunter2", json.dumps(masked))
        self.assertEqual(masked["password"], "set (7 chars)")


class ClientTests(unittest.TestCase):
    def test_login_and_first_site_resolution(self):
        client, fake, _ = make_client()
        auth = client.authenticate()
        self.assertEqual(auth.controller_id, CONTROLLER_ID)
        self.assertEqual(auth.controller_version, "5.13.30.8")
        self.assertEqual(client.site.site_id, SITE_ID)
        self.assertEqual(client.site.name, "Test Site")
        self.assertEqual(client.site.total, 1)
        self.assertEqual(auth.privilege, "viewer")  # 6.x reports the int form
        self.assertEqual(fake.logins, 1)

    def test_authenticate_is_cached(self):
        client, fake, _ = make_client()
        client.authenticate()
        client.authenticate()
        self.assertEqual(fake.logins, 1)

    def test_site_resolution_by_name_and_id(self):
        sites = [{"id": "aaa111", "name": "Home"}, {"id": "bbb222", "name": "Lab"}]
        client, _, _ = make_client(site_name="lab")
        client.transport.sites = sites
        self.assertEqual(client.resolve_site().site_id, "bbb222")

        client2, _, _ = make_client(site_id="aaa111")
        client2.transport.sites = sites
        resolved = client2.resolve_site()
        self.assertEqual(resolved.name, "Home")
        self.assertEqual(resolved.index, 0)

    def test_site_name_mismatch_lists_available_sites(self):
        client, _, _ = make_client(site_name="nope")
        with self.assertRaises(OmadaError) as ctx:
            client.resolve_site()
        self.assertIn("Test Site", str(ctx.exception))
        self.assertIn("OMADA_SITE_NAME", ctx.exception.hint)

    def test_token_is_sent_in_query_and_csrf_header(self):
        client, fake, _ = make_client()
        client.authenticate()
        client.api("users/current")
        last = fake.requests[-1]
        self.assertIn(f"token={fake.token}", last["url"])
        self.assertEqual(last["headers"]["Csrf-Token"], fake.token)

    def test_html_response_triggers_single_reauth_and_replay(self):
        client, fake, _ = make_client()
        client.authenticate()
        fake.html_once_for.add(f"sites/{SITE_ID}/devices")
        devices = client.api_result(f"sites/{SITE_ID}/devices")
        self.assertEqual(len(devices), 2)
        self.assertEqual(fake.logins, 2)  # one initial + one recovery

    def test_html_twice_raises_instead_of_looping(self):
        client, fake, _ = make_client()
        client.authenticate()
        fake.html_always_for.add(f"sites/{SITE_ID}/devices")
        with self.assertRaises(OmadaError) as ctx:
            client.api(f"sites/{SITE_ID}/devices")
        self.assertIn("HTML", str(ctx.exception))
        # One initial login + exactly one recovery attempt; no runaway loop.
        self.assertEqual(fake.logins, 2)

    def test_burst_1600_is_retried_once_after_pacing(self):
        client, fake, sleeps = make_client()
        client.authenticate()
        fake.burst_once_for.add(f"sites/{SITE_ID}/devices")
        result = client.api_result(f"sites/{SITE_ID}/devices")
        self.assertEqual(len(result), 2)
        self.assertIn(BURST_BACKOFF_SECONDS, sleeps)

    def test_role_shapes_are_normalised(self):
        from omada_mcp.client import _describe_privilege

        # 6.2: roleName + a privilege object that only carries the site scope
        self.assertEqual(
            _describe_privilege({"roleName": "Viewer",
                                 "privilege": {"all": True, "sites": [{"key": "x"}]}}),
            ("Viewer", "all sites"))
        # 6.2 local account: privilege is just the scope, no role name
        self.assertEqual(
            _describe_privilege({"type": 0,
                                 "privilege": {"all": False, "sites": [{"key": "x"}]}}),
            ("type 0", "1 site(s)"))
        # 5.x: integer privilege
        self.assertEqual(_describe_privilege({"privilege": 1}), ("admin", None))
        self.assertEqual(_describe_privilege({"privilege": 7}), ("level 7", None))
        self.assertEqual(_describe_privilege({}), (None, None))

    def test_error_code_hints(self):
        self.assertIn("16 entries", describe_error(-33726))
        self.assertIn("hex site ID", describe_error(-1505))
        self.assertIn("Admin", describe_error(-41011))
        self.assertIn("-1600", describe_error(-1600))

    def test_ssl_context_honours_verify_flags(self):
        import ssl

        unverified = build_ssl_context(make_config(verify_ssl=False))
        self.assertEqual(unverified.verify_mode, ssl.CERT_NONE)
        self.assertFalse(unverified.check_hostname)

        strict = build_ssl_context(make_config(verify_ssl=True, strict_x509=True))
        self.assertEqual(strict.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(strict.check_hostname)
        # Python 3.13+ enables VERIFY_X509_STRICT by default; older versions do
        # not, and this code never adds it on their behalf.
        if sys.version_info >= (3, 13) and hasattr(ssl, "VERIFY_X509_STRICT"):
            self.assertTrue(strict.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_ssl_context_can_clear_strict_x509(self):
        import ssl

        if not hasattr(ssl, "VERIFY_X509_STRICT"):
            self.skipTest("ssl.VERIFY_X509_STRICT unavailable on this interpreter")
        relaxed = build_ssl_context(make_config(verify_ssl=True, strict_x509=False))
        self.assertFalse(relaxed.verify_flags & ssl.VERIFY_X509_STRICT)
        self.assertEqual(relaxed.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(relaxed.check_hostname)


class ProtocolTests(unittest.TestCase):
    def _server(self, **overrides):
        client, fake, _ = make_client(**overrides)
        return Server(client.config, client=client), fake, client

    def test_initialize_does_not_touch_the_network(self):
        server, fake, _ = self._server()
        result = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                "params": {"protocolVersion": "2024-11-05"}})["result"]
        self.assertEqual(result["serverInfo"]["name"], "omada-mcp")
        self.assertEqual(result["serverInfo"]["version"], __version__)
        self.assertEqual(result["protocolVersion"], "2024-11-05")
        self.assertIn("tools", result["capabilities"])
        self.assertEqual(fake.requests, [])

    def test_initialize_negotiates_supported_protocol(self):
        server, _, _ = self._server()
        result = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                "params": {"protocolVersion": "2025-06-18"}})["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")

    def test_initialize_falls_back_for_unknown_protocol(self):
        server, _, _ = self._server()
        result = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                "params": {"protocolVersion": "1999-01-01"}})["result"]
        self.assertEqual(result["protocolVersion"], "2024-11-05")

    def test_notifications_get_no_response(self):
        server, _, _ = self._server()
        self.assertIsNone(server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.assertIsNone(server.handle({"jsonrpc": "2.0", "method": "notifications/cancelled"}))

    def test_tools_list_annotations(self):
        server, _, _ = self._server()
        tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        self.assertEqual(len(tools), 33)
        self.assertEqual({t["name"] for t in tools},
                         {"list_devices", "list_clients", "list_wifi_clients",
                          "list_wired_clients", "search_clients", "get_device",
                          "get_client", "list_wlans", "list_lan_networks",
                          "list_dhcp_reservations", "list_acls", "list_ip_groups",
                          "list_port_forwards", "list_static_routes",
                          "get_network_services", "list_logs",
                          "get_site_info", "network_audit",
                          "explain_error", "get_config_snapshot",
                          "get_switch_ports", "get_ap_radios", "get_rf_scan",
                          "get_wan_status", "list_vpn_tunnels", "get_topology",
                          "get_security_status", "diagnose_client", "diagnose_wan",
                          "list_port_profiles", "list_wlan_groups",
                          "list_policy_routes", "list_lan_dns_rules"})
        for tool in tools:
            annotations = tool["annotations"]
            self.assertIs(annotations["readOnlyHint"], True, tool["name"])
            self.assertIs(annotations["destructiveHint"], False, tool["name"])
            self.assertIs(annotations["idempotentHint"], True, tool["name"])
            expected_open = tool["name"] != "explain_error"
            self.assertIs(annotations["openWorldHint"], expected_open, tool["name"])
            self.assertEqual(tool["inputSchema"]["type"], "object")
            self.assertIn("outputSchema", tool, tool["name"])
            self.assertEqual(tool["outputSchema"]["type"], "object", tool["name"])
            self.assertTrue(tool["outputSchema"]["properties"], tool["name"])
            self.assertTrue(tool["outputSchema"]["required"], tool["name"])

    def test_read_only_mode_refuses_non_read_only_names(self):
        server, _, _ = self._server(read_only=True)
        response = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "set_client_fixed_ip"}})
        self.assertEqual(response["error"]["code"], -32003)
        self.assertIn("OMADA_READ_ONLY", response["error"]["message"])

    def test_unknown_tool_is_reported_when_writes_are_allowed(self):
        server, _, _ = self._server(read_only=False)
        unknown_resp = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                      "params": {"name": "nonexistent_tool"}})
        self.assertEqual(unknown_resp["error"]["code"], -32601)
        blocked_write = server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                       "params": {"name": "set_client_fixed_ip"}})
        self.assertEqual(blocked_write["error"]["code"], -32003)
        self.assertIn("OMADA_WRITE_TOOLS", blocked_write["error"]["message"])

    def test_read_only_gate_also_blocks_declared_write_tools(self):
        from dataclasses import replace

        spec = replace(TOOL_MAP["list_devices"], name="create_dhcp_reservation", read_only=False)
        TOOL_MAP[spec.name] = spec
        try:
            server, _, _ = self._server(read_only=True)
            response = server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                      "params": {"name": spec.name}})
            self.assertEqual(response["error"]["code"], -32003)
        finally:
            TOOL_MAP.pop(spec.name, None)

    def test_tools_call_reports_auth_failure_as_rpc_error(self):
        secret = "s3cr3t-passphrase"
        server, _, _ = self._server(password=secret)
        response = server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                  "params": {"name": "list_devices"}})
        self.assertEqual(response["error"]["code"], -32002)
        self.assertIn("login rejected", response["error"]["message"])
        self.assertNotIn(secret, json.dumps(response))

    def test_tools_call_happy_path_and_structured_content(self):
        server, _, _ = self._server()
        response = server.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                                  "params": {"name": "list_devices", "arguments": {}}})
        result = response["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["count"], 2)
        text = json.loads(result["content"][0]["text"])
        self.assertEqual(text[0]["model"], "ER605")
        self.assertIsInstance(text[0]["clientCount"], int)

    def test_missing_required_argument_is_invalid_params(self):
        server, _, _ = self._server()
        response = server.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                  "params": {"name": "get_device", "arguments": {}}})
        self.assertEqual(response["error"]["code"], -32602)
        self.assertIn("mac", response["error"]["message"])

    def test_bad_limit_is_rejected(self):
        server, _, _ = self._server()
        response = server.handle({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                                  "params": {"name": "list_clients",
                                             "arguments": {"limit": "many"}}})
        self.assertEqual(response["error"]["code"], -32602)

    def test_unknown_method(self):
        server, _, _ = self._server()
        response = server.handle({"jsonrpc": "2.0", "id": 9, "method": "shutdown"})
        self.assertEqual(response["error"]["code"], -32601)

    def test_parse_error(self):
        server, _, _ = self._server()
        self.assertEqual(server.handle(None)["error"]["code"], -32700)

    def test_stream_reader_handles_pretty_printed_and_concatenated_json(self):
        payload = ('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
                   '{\n  "jsonrpc": "2.0",\n  "id": 2,\n  "method": "tools/list"\n}\n')
        messages = list(Server._read_messages(io.StringIO(payload)))
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[1]["method"], "tools/list")

    def test_malformed_line_does_not_poison_the_stream(self):
        """Regression: one garbage line used to swallow every later request."""
        payload = ('{not json}\n'
                   '{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
                   'garbage {"x": 1}\n'
                   '{"jsonrpc":"2.0","id":3,"method":"ping"}\n')
        messages = list(Server._read_messages(io.StringIO(payload)))
        self.assertEqual(messages[0], None)
        self.assertEqual(messages[1]["id"], 2)
        self.assertEqual(messages[2], None)
        self.assertEqual(messages[-1]["id"], 3)

    def test_serve_answers_parse_error_then_keeps_serving(self):
        server, _, _ = self._server()
        stdin = io.StringIO('{not json}\n{"jsonrpc":"2.0","id":7,"method":"ping"}\n')
        stdout = io.StringIO()
        server.serve(stdin=stdin, stdout=stdout)
        frames = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(frames[0]["error"]["code"], -32700)
        self.assertEqual(frames[1]["id"], 7)

    def test_oversized_incomplete_frame_is_dropped(self):
        original = Server.MAX_FRAME_CHARS
        Server.MAX_FRAME_CHARS = 64
        try:
            payload = '{"a": [' + "1,\n" * 100 + '{"jsonrpc":"2.0","id":5,"method":"ping"}\n'
            messages = list(Server._read_messages(io.StringIO(payload)))
        finally:
            Server.MAX_FRAME_CHARS = original
        self.assertIn(None, messages)

    def test_serve_loop_writes_one_line_per_response(self):
        server, _, _ = self._server()
        stdin = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
                            '{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        stdout = io.StringIO()
        self.assertEqual(server.serve(stdin=stdin, stdout=stdout), 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["result"]["serverInfo"]["name"], "omada-mcp")


class WindowsTests(unittest.TestCase):
    """Windows-specific behaviour, exercised on any OS.

    The failures these prevent are invisible on Linux: a code-page encoding
    error, a ``\r\n`` frame, a config file nobody can find, and a controller
    call routed through a registry proxy.
    """

    def _windows_stream(self, encoding="cp1252"):
        """A TextIOWrapper that mimics the Windows console: legacy code page + CRLF."""
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding=encoding, newline="\r\n",
                                  write_through=True)
        return raw, stream

    def test_console_stream_is_forced_to_utf8_and_lf(self):
        raw, stream = self._windows_stream()
        configure_streams(None, stream, stream)
        stream.write(json.dumps({"ssid": "\u0634\u0628\u0643\u0629 \u0627\u0644\u0645\u0646\u0632\u0644"},
                                ensure_ascii=False))
        stream.flush()
        data = raw.getvalue()
        self.assertNotIn(b"\r", data, "CRLF leaked into a JSON-RPC frame")
        self.assertEqual(data.decode("utf-8").strip(),
                         '{"ssid": "\u0634\u0628\u0643\u0629 \u0627\u0644\u0645\u0646\u0632\u0644"}')

    def test_unconfigured_cp1252_stream_would_have_failed(self):
        """Proves the guard is load-bearing, not decoration."""
        _raw, stream = self._windows_stream()
        with self.assertRaises(UnicodeEncodeError):
            stream.write("\u0634\u0628\u0643\u0629")
            stream.flush()

    def test_server_emits_lf_only_frames(self):
        client, _, _ = make_client()
        server = Server(client.config, client=client)
        raw, stream = self._windows_stream()
        configure_streams(None, stream, stream)
        server.out = stream
        server.handle({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        server._write({"jsonrpc": "2.0", "id": 1, "result": {}})
        stream.flush()
        self.assertNotIn(b"\r\n", raw.getvalue())
        self.assertEqual(stream.encoding.lower().replace("-", ""), "utf8")

    def test_crlf_input_frames_are_parsed(self):
        payload = ('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\r\n'
                   '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\r\n')
        messages = list(Server._read_messages(io.StringIO(payload)))
        self.assertEqual([m["id"] for m in messages], [1, 2])

    def test_env_file_with_utf8_bom_is_parsed(self):
        """PowerShell 5.1 `Set-Content -Encoding utf8` and old Notepad add a BOM."""
        from omada_mcp.config import parse_env_file
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_bytes(b"\xef\xbb\xbfOMADA_BASE_URL=https://win:8043\r\nOMADA_USERNAME=u\r\n")
            values = parse_env_file(env_file)
        self.assertEqual(values.get("OMADA_BASE_URL"), "https://win:8043")
        self.assertEqual(values.get("OMADA_USERNAME"), "u")

    def test_appdata_env_file_is_discovered_on_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            appdata = Path(tmp) / "Roaming"
            (appdata / "omada-mcp").mkdir(parents=True)
            env_file = appdata / "omada-mcp" / ".env"
            env_file.write_text("OMADA_BASE_URL=https://win:8043\n"
                                "OMADA_USERNAME=winuser\nOMADA_PASSWORD=pw\n",
                                encoding="utf-8")
            empty = Path(tmp) / "work"
            empty.mkdir()
            with mock.patch.object(config_module, "_IS_WINDOWS", True):
                config = config_module.load_config(
                    environ={"APPDATA": str(appdata)}, cwd=empty)
            self.assertEqual(config.username, "winuser")
            self.assertEqual(config.env_file, env_file)

    def test_appdata_precedes_posix_config_dir(self):
        with mock.patch.object(config_module, "_IS_WINDOWS", True):
            origins = [origin for origin, _ in config_module.candidate_env_files(
                cwd="/work", environ={"APPDATA": "/roaming"})]
        self.assertEqual(origins, ["cwd/.env", "%APPDATA%/omada-mcp/.env",
                                   "~/.config/omada-mcp/.env"])

    def test_no_appdata_falls_through_without_error(self):
        with mock.patch.object(config_module, "_IS_WINDOWS", True):
            origins = [origin for origin, _ in config_module.candidate_env_files(
                cwd="/work", environ={})]
        self.assertEqual(origins, ["cwd/.env", "~/.config/omada-mcp/.env"])

    def test_system_proxy_is_disabled_by_default(self):
        from omada_mcp.client import UrllibTransport

        transport = UrllibTransport(build_ssl_context(make_config()))
        self.assertEqual(transport.proxy_mode, "disabled")
        self.assertIsInstance(transport.proxy_handler, urllib.request.ProxyHandler)
        self.assertEqual(transport.proxy_handler.proxies, {})

    def test_system_proxy_can_be_enabled_explicitly(self):
        from omada_mcp.client import UrllibTransport

        transport = UrllibTransport(build_ssl_context(make_config()),
                                    use_system_proxy=True)
        self.assertEqual(transport.proxy_mode, "system")

    def test_use_system_proxy_is_configurable(self):
        with self.assertRaises(ConfigError):
            load_config(environ={"OMADA_BASE_URL": "https://c:8043",
                                 "OMADA_USERNAME": "u", "OMADA_PASSWORD": "p",
                                 "OMADA_USE_SYSTEM_PROXY": "sometimes"},
                        cwd=tempfile.mkdtemp())
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(environ={"OMADA_BASE_URL": "https://c:8043",
                                          "OMADA_USERNAME": "u", "OMADA_PASSWORD": "p",
                                          "OMADA_USE_SYSTEM_PROXY": "true"}, cwd=tmp)
        self.assertTrue(config.use_system_proxy)

    def test_doctor_skips_posix_permissions_on_windows(self):
        from omada_mcp import doctor as doctor_module

        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("OMADA_BASE_URL=https://c:8043\nOMADA_USERNAME=u\n"
                                "OMADA_PASSWORD=p\n", encoding="utf-8")
            env_file.chmod(0o644)
            client, _, _ = make_client()
            stream = io.StringIO()
            with mock.patch.object(doctor_module, "_IS_WINDOWS", True):
                rc = doctor_module.run_doctor(
                    config_factory=lambda: config_module.load_config(
                        environ={"OMADA_ENV_FILE": str(env_file)}, cwd=tmp),
                    client_factory=lambda _cfg: client, stream=stream)
        output = stream.getvalue()
        self.assertEqual(rc, 0, output)
        self.assertNotIn("chmod", output)
        self.assertIn("Python", output)  # platform line in the header

    def test_doctor_warns_about_world_readable_env_on_posix(self):
        from omada_mcp import doctor as doctor_module

        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("OMADA_BASE_URL=https://c:8043\nOMADA_USERNAME=u\n"
                                "OMADA_PASSWORD=p\n", encoding="utf-8")
            env_file.chmod(0o644)
            client, _, _ = make_client()
            stream = io.StringIO()
            with mock.patch.object(doctor_module, "_IS_WINDOWS", False):
                doctor_module.run_doctor(
                    config_factory=lambda: config_module.load_config(
                        environ={"OMADA_ENV_FILE": str(env_file)}, cwd=tmp),
                    client_factory=lambda _cfg: client, stream=stream)
        self.assertIn("chmod 600", stream.getvalue())


class ToolTests(unittest.TestCase):
    def _server(self, **overrides):
        client, fake, _ = make_client(**overrides)
        return Server(client.config, client=client), fake, client

    def _call(self, server, name, arguments=None):
        response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": name, "arguments": arguments or {}}})
        self.assertNotIn("error", response, response)
        return response["result"]

    def test_list_wlans_never_leaks_preshared_key(self):
        server, _, _ = self._server()
        result = self._call(server, "list_wlans")
        self.assertNotIn("super-secret-passphrase", json.dumps(result))
        wlan = result["structuredContent"]["items"][0]
        self.assertEqual(wlan["ssid"], "lab")
        self.assertTrue(wlan["hasPresharedKey"])

    def test_project_wlan_drops_unknown_fields(self):
        projected = project_wlan({"ssid": "x", "securityKey": "k", "adminPassword": "p"})
        self.assertNotIn("adminPassword", projected)
        self.assertNotIn("securityKey", projected)

    def test_get_device_accepts_any_mac_format(self):
        server, _, _ = self._server()
        for mac in ("AA-BB-CC-00-00-01", "aabbcc000001", "aa:bb:cc:00:00:01"):
            result = self._call(server, "get_device", {"mac": mac})
            self.assertEqual(result["structuredContent"]["name"], "gw")

    def test_get_device_by_name(self):
        server, _, _ = self._server()
        self.assertEqual(self._call(server, "get_device", {"mac": "ap1"})
                         ["structuredContent"]["mac"], "AA-BB-CC-00-00-02")

    def test_get_client_by_ip_and_hostname(self):
        server, _, _ = self._server()
        self.assertEqual(self._call(server, "get_client", {"mac": "192.168.20.31"})
                         ["structuredContent"]["name"], "laptop")
        self.assertEqual(self._call(server, "get_client", {"mac": "laptop.lan"})
                         ["structuredContent"]["mac"], "AA-BB-CC-11-11-01")

    def test_missing_object_is_a_tool_error_not_a_crash(self):
        server, _, _ = self._server()
        result = self._call(server, "get_device", {"mac": "00:00:00:00:00:99"})
        self.assertTrue(result["isError"])
        self.assertIn("no device matches", result["content"][0]["text"])

    def test_wifi_and_wired_filters(self):
        server, _, _ = self._server()
        wifi = self._call(server, "list_wifi_clients")["structuredContent"]["items"]
        wired = self._call(server, "list_wired_clients")["structuredContent"]["items"]
        self.assertEqual([c["name"] for c in wifi], ["laptop"])
        self.assertEqual([c["name"] for c in wired], ["desktop"])

    def test_clients_are_deduplicated_across_pages(self):
        duplicated = CLIENTS + [dict(CLIENTS[0])]
        server, _, _ = self._server()
        server.client.transport.clients = duplicated
        items = self._call(server, "list_clients")["structuredContent"]["items"]
        self.assertEqual(len(items), 2)

    def test_limit_is_clamped_and_applied(self):
        server, _, _ = self._server()
        items = self._call(server, "list_clients", {"limit": 1})["structuredContent"]["items"]
        self.assertEqual(len(items), 1)

    def test_last_seen_is_utc_iso(self):
        server, _, _ = self._server()
        items = self._call(server, "list_clients")["structuredContent"]["items"]
        self.assertEqual([c["lastSeen"] for c in items if c["lastSeen"]],
                         ["2023-11-14T22:13:20Z"])

    def test_site_info_counts(self):
        server, _, _ = self._server()
        info = self._call(server, "get_site_info")["structuredContent"]
        self.assertEqual(info["name"], "Test Site")
        self.assertEqual(info["deviceCount"], 2)
        self.assertEqual(info["clientCount"], 2)
        self.assertEqual(info["wifiClientCount"], 1)
        self.assertEqual(info["controllerVersion"], "5.13.30.8")

    def test_authenticate_is_reused_across_tool_calls(self):
        server, fake, _ = self._server()
        self._call(server, "list_devices")
        self._call(server, "list_clients")
        self.assertEqual(fake.logins, 1)


class ClientSourceTests(unittest.TestCase):
    """Regressions for issues #1 and #2.

    #1: list_clients and friends read only insight/clients, which omits ssid, ip,
        apName and signal on 6.2.10.x, so monitoring showed blanks the controller
        could have filled.
    #2: search_clients documented VLAN/SSID filtering but rejected both arguments.
    """

    def _server(self, controller=None):
        fake = controller or FakeController()
        client = OmadaClient(make_config(), transport=fake, sleep=lambda _s: None,
                             clock=lambda: 0.0, log_fn=lambda _m: None)
        return Server(client.config, client=client), fake

    def _call(self, server, name, arguments=None):
        response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": name, "arguments": arguments or {}}})
        return response

    def _items(self, server, name, arguments=None):
        result = self._call(server, name, arguments)["result"]
        self.assertFalse(result.get("isError"), result)
        return result["structuredContent"]["items"]

    def test_list_clients_reads_the_rich_endpoint(self):
        server, fake = self._server()
        items = self._items(server, "list_clients")
        wifi = next(c for c in items if c["wireless"])
        self.assertEqual(wifi["ssid"], "lab")
        self.assertEqual(wifi["apName"], "ap1")
        self.assertEqual(wifi["ip"], "192.168.20.31")
        urls = [r["url"] for r in fake.requests]
        self.assertTrue(any("/clients" in u and "insight" not in u for u in urls), urls)
        self.assertFalse(any("insight/clients" in u for u in urls), urls)

    def test_list_clients_falls_back_to_insight_when_rich_endpoint_is_denied(self):
        class DeniedRich(FakeController):
            """Admin-denied /clients, working insight/clients — a Viewer account."""

            def request(self, method, url, headers=None, data=None, timeout=None):
                path = url.split("?", 1)[0]
                if path.endswith("/clients") and "/insight/" not in path:
                    return 200, json.dumps({"errorCode": -1007, "msg": "no permission"}).encode()
                return super().request(method, url, headers=headers, data=data, timeout=timeout)

        server, fake = self._server(DeniedRich())
        items = self._items(server, "list_clients")
        self.assertEqual(len(items), 2)
        self.assertTrue(any("insight/clients" in r["url"] for r in fake.requests))

    def test_search_clients_filters_by_vlan(self):
        server, _ = self._server()
        self.assertEqual([c["name"] for c in self._items(server, "search_clients", {"vlan": 20})],
                         ["laptop"])
        self.assertEqual([c["name"] for c in self._items(server, "search_clients", {"vlan": 1})],
                         ["desktop"])
        self.assertEqual(self._items(server, "search_clients", {"vlan": 99}), [])
        # the declared schema is an integer, so a string is refused before the handler
        self.assertIn("error", self._call(server, "search_clients", {"vlan": "20"}))

    def test_search_clients_filters_by_ssid(self):
        server, _ = self._server()
        self.assertEqual([c["name"] for c in self._items(server, "search_clients", {"ssid": "LAB"})],
                         ["laptop"])
        self.assertEqual([c["name"] for c in self._items(server, "search_clients", {"ssid": "la"})],
                         ["laptop"])
        self.assertEqual(self._items(server, "search_clients", {"ssid": "nope"}), [])

    def test_search_clients_rejects_an_invalid_vlan(self):
        client, _, _ = make_client()
        handler = TOOL_MAP["search_clients"].handler
        for bad in ("abc", True, 9999, -1):
            with self.assertRaises(OmadaError, msg=bad) as ctx:
                handler(client, vlan=bad)
            self.assertIn("vlan", str(ctx.exception).lower())

    def test_search_clients_filters_compose(self):
        server, _ = self._server()
        self.assertEqual(len(self._items(server, "search_clients",
                                        {"vlan": 20, "wireless": True, "guest": False})), 1)
        self.assertEqual(self._items(server, "search_clients",
                                     {"vlan": 20, "wireless": False}), [])


class WriteSchemaContractTests(unittest.TestCase):
    """Issue #4: the advertised schema must accept what the readers return."""

    def test_dhcp_pool_schema_accepts_both_key_shapes(self):
        item = TOOL_MAP["set_vlan_dhcp_pools"].input_schema["properties"]["pools"]["items"]
        props = item["properties"]
        for key in ("ipaddrStart", "ipaddrEnd", "start", "end"):
            self.assertIn(key, props)
        self.assertIn({"required": ["start", "end"]}, item["anyOf"])
        self.assertIn({"required": ["ipaddrStart", "ipaddrEnd"]}, item["anyOf"])

    def test_create_lan_network_pool_schema_accepts_both_key_shapes(self):
        item = TOOL_MAP["create_lan_network"].input_schema["properties"]["pools"]["items"]
        for key in ("ipaddrStart", "ipaddrEnd", "start", "end"):
            self.assertIn(key, item["properties"])
        self.assertIn({"required": ["start", "end"]}, item["anyOf"])
        self.assertIn({"required": ["ipaddrStart", "ipaddrEnd"]}, item["anyOf"])

    def test_pools_safety_accepts_reader_shorthand(self):
        """The handler's own validation takes {start,end}; that is why the schema must too."""
        client, _, _ = make_client()
        from omada_mcp.write_tools import _check_dhcp_pools_safety

        network = {"id": "n1", "name": "Lab", "vlan": 20,
                   "gatewaySubnet": "192.168.20.1/24"}
        got = _check_dhcp_pools_safety(client, network,
                                       [{"start": "192.168.20.2", "end": "192.168.20.179"}], [])
        self.assertEqual(got, [{"ipaddrStart": "192.168.20.2", "ipaddrEnd": "192.168.20.179"}])


class DoctorTests(unittest.TestCase):
    def _run(self, config=None, factory=None, client_factory=None, stream=None):
        stream = stream or io.StringIO()
        rc = run_doctor(
            config_factory=(factory or (lambda: config or make_config())),
            client_factory=client_factory,
            stream=stream,
        )
        return rc, stream.getvalue()

    def test_all_phases_pass(self):
        client, _, _ = make_client()
        rc, output = self._run(client_factory=lambda _cfg: client)
        self.assertEqual(rc, 0, output)
        for phase in ("env", "tls", "login", "site", "tools"):
            self.assertIn(phase, output)
        self.assertIn("Ready", output)
        self.assertIn("password=set (2 chars)", output)

    def test_config_error_is_reported_with_hint(self):
        def factory():
            raise ConfigError("missing required variable(s): OMADA_PASSWORD",
                              hint="add it to ./.env")
        rc, output = self._run(factory=factory)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL", output)
        self.assertIn("fix: add it to ./.env", output)

    def test_bad_credentials_fail_at_login_phase(self):
        client, _, _ = make_client(password="wrong")
        rc, output = self._run(client_factory=lambda _cfg: client)
        self.assertEqual(rc, 1)
        self.assertIn("login", output)
        self.assertIn("FAIL", output)

    def test_unreachable_controller_fails_at_tls_phase(self):
        config = make_config()

        def transport_request(*_args, **_kwargs):
            raise OmadaError("cannot reach https://controller.test:8043: refused",
                             hint="check OMADA_BASE_URL")

        fake = FakeController()
        client = OmadaClient(config, transport=fake, log_fn=lambda _m: None)
        client._transport = type("T", (), {"request": staticmethod(transport_request)})()
        rc, output = self._run(client_factory=lambda _cfg: client)
        self.assertEqual(rc, 1)
        self.assertIn("tls", output)
        self.assertIn("check OMADA_BASE_URL", output)

    def test_read_only_doctor_still_works(self):
        client, _, _ = make_client(read_only=True)
        rc, output = self._run(client_factory=lambda _cfg: client)
        self.assertEqual(rc, 0, output)


class CliTests(unittest.TestCase):
    def test_list_tools_emits_valid_json(self):
        from unittest import mock
        from omada_mcp.cli import main

        with mock.patch.dict(os.environ, {}, clear=True):
            buffer = io.StringIO()
            original = sys.stdout
            sys.stdout = buffer
            try:
                self.assertEqual(main(["--list-tools"]), 0)
            finally:
                sys.stdout = original
            payload = json.loads(buffer.getvalue())
            self.assertEqual(len(payload["tools"]), 33)

            buffer_all = io.StringIO()
            sys.stdout = buffer_all
            try:
                self.assertEqual(main(["--list-tools", "--all"]), 0)
            finally:
                sys.stdout = original
            payload_all = json.loads(buffer_all.getvalue())
            self.assertEqual(len(payload_all["tools"]), 79)

        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "custom.env"
            env_file.write_text(
                "OMADA_READ_ONLY=false\nOMADA_WRITE_TOOLS=set_vlan_isolation,create_ip_group\n",
                encoding="utf-8",
            )
            buf_env = io.StringIO()
            with mock.patch("sys.stdout", buf_env), \
                 mock.patch.dict(os.environ, {"OMADA_ENV_FILE": str(env_file)}, clear=True):
                self.assertEqual(main(["--list-tools"]), 0)
            self.assertEqual(len(json.loads(buf_env.getvalue())["tools"]), 35)

    def test_missing_config_exits_non_zero(self):
        from omada_mcp.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            original_cwd = os.getcwd()
            environ_backup = dict(os.environ)
            for key in list(os.environ):
                if key.startswith("OMADA_"):
                    del os.environ[key]
            # Isolate per-user config dirs and stdin so developer machines with
            # an existing ~/.config/omada-mcp/.env or %APPDATA%\omada-mcp\.env
            # never start the stdio server loop and hang the test suite.
            os.environ["APPDATA"] = tmp
            os.environ["XDG_CONFIG_HOME"] = tmp
            os.environ["HOME"] = tmp
            os.environ["USERPROFILE"] = tmp
            stderr = io.StringIO()
            original_stderr = sys.stderr
            original_stdin = sys.stdin
            sys.stderr = stderr
            sys.stdin = io.StringIO("")
            try:
                os.chdir(tmp)
                code = main([])
            finally:
                os.chdir(original_cwd)
                sys.stderr = original_stderr
                sys.stdin = original_stdin
                os.environ.clear()
                os.environ.update(environ_backup)
            self.assertEqual(code, 2)
            self.assertIn("omada-mcp --doctor", stderr.getvalue())

    def test_normalize_mac_variants(self):
        self.assertEqual(normalize_mac("AABBCCDDEEFF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("aa-bb-cc-dd-ee-ff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("not-a-mac"), "not-a-mac")


class V11FeatureTests(unittest.TestCase):
    def test_tls_server_name_is_configurable_and_masked(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(
                environ={
                    "OMADA_BASE_URL": "https://192.0.2.10:8043",
                    "OMADA_USERNAME": "u",
                    "OMADA_PASSWORD": "p",
                    "OMADA_TLS_SERVER_NAME": "Omada",
                },
                cwd=tmp,
            )
        self.assertEqual(cfg.tls_server_name, "Omada")
        self.assertEqual(cfg.masked()["tls_server_name"], "Omada")

    def test_isolated_environ_does_not_read_host_xdg_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Even if the host machine has ~/.config/omada-mcp/.env, passing
            # an isolated environ={} must not discover it.
            with mock.patch("pathlib.Path.home", return_value=Path(tmp)):
                cfg_dir = Path(tmp) / ".config" / "omada-mcp"
                cfg_dir.mkdir(parents=True)
                (cfg_dir / ".env").write_text(
                    "OMADA_BASE_URL=https://host:8043\nOMADA_USERNAME=u\nOMADA_PASSWORD=p\n",
                    encoding="utf-8",
                )
                with self.assertRaises(ConfigError):
                    load_config(environ={}, cwd=tmp)

    def test_ssl_context_overrides_server_hostname_when_configured(self):
        import ssl

        cfg = make_config(verify_ssl=True, tls_server_name="Omada")
        ctx = build_ssl_context(cfg)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertNotEqual(ctx.wrap_socket.__func__ if hasattr(ctx.wrap_socket, "__func__") else None,
                            ssl.SSLContext.wrap_socket)

    def test_login_30109_does_not_say_session_expired(self):
        msg = describe_error(-30109, "wrong credentials", endpoint="/api/v2/login", method="POST")
        self.assertIn("Invalid username or password", msg)
        self.assertNotIn("Session expired", msg)

        session_msg = describe_error(-30109, "expired", endpoint="sites/abc/devices", method="GET")
        self.assertIn("Session expired", session_msg)

    def test_describe_error_1600_includes_method_context(self):
        get_msg = describe_error(-1600, "unsupported", endpoint="sites/x/devices", method="GET")
        self.assertIn("burst rate-limiting", get_msg)
        del_msg = describe_error(-1600, "unsupported", endpoint="sites/x/profiles/groups/1",
                                 method="DELETE")
        self.assertIn("DELETE", del_msg)

    def test_explain_error_code_catalog_and_unknown(self):
        e33726 = explain_error_code(-33726)
        self.assertTrue(e33726["known"])
        self.assertIn("16 entries", e33726["meaning"])
        self.assertIn("CIDR", e33726["fix"])

        e1600 = explain_error_code(-1600, endpoint="sites/abc/devices")
        self.assertTrue(e1600["ambiguous"])
        self.assertEqual(len(e1600["causes"]), 2)
        self.assertIsNotNone(e1600["endpointContext"])

        unknown = explain_error_code(-999999)
        self.assertFalse(unknown["known"])
        self.assertEqual(unknown["code"], -999999)

    def test_controller_family_classification(self):
        self.assertEqual(classify_controller_family({"controllerVer": "6.2.10.17"}), "software-6.x")
        self.assertEqual(classify_controller_family({"controllerVer": "5.13.30.8"}), "software-5.x")
        self.assertEqual(
            classify_controller_family({"controllerVer": "5.12.7", "hardware": True}),
            "hardware-5.x",
        )
        self.assertEqual(
            classify_controller_family({"controllerVer": "5.9.32", "model": "OC200"}),
            "hardware-5.x",
        )
        self.assertEqual(
            classify_controller_family({}, session_cookie="TPEAP_SESSIONID"),
            "software-5.x",
        )

    def test_tpeap_cookie_and_legacy_login_shape(self):
        fake = FakeController(
            cookie_name="TPEAP_SESSIONID",
            controller_ver="5.13.30.8",
            controller_info_extra={"hardware": True},
            legacy_login_shape=True,
        )
        client = OmadaClient(make_config(), transport=fake, sleep=lambda _s: None,
                             clock=lambda: 0.0, log_fn=lambda _m: None)
        auth = client.authenticate()
        self.assertEqual(auth.session_cookie, "TPEAP_SESSIONID")
        self.assertEqual(auth.controller_family, "hardware-5.x")
        self.assertEqual(auth.controller_id, CONTROLLER_ID)

    def test_list_wlans_expands_v6_groups_and_redacts_psk_setting(self):
        fake = FakeController(
            wlans=[{"id": "grp1", "name": "Default", "primary": True}],
            ssids_by_group={
                "grp1": [
                    {
                        "id": "s1",
                        "name": "corp_wifi",
                        "band": 3,
                        "broadcast": True,
                        "guestNetEnable": False,
                        "security": 3,
                        "vlanSetting": {"mode": 1, "currentVlanId": 10},
                        "pskSetting": {"securityKey": "top-secret-v6-key", "versionPsk": 2},
                        "ppskSetting": {"enabled": False},
                    }
                ]
            },
        )
        client = OmadaClient(make_config(), transport=fake, sleep=lambda _s: None,
                             clock=lambda: 0.0, log_fn=lambda _m: None)
        server = Server(client.config, client=client)
        resp = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "list_wlans", "arguments": {}},
        })
        result = resp["result"]
        self.assertNotIn("top-secret-v6-key", json.dumps(result))
        self.assertNotIn("pskSetting", json.dumps(result))
        item = result["structuredContent"]["items"][0]
        self.assertEqual(item["ssid"], "corp_wifi")
        self.assertEqual(item["vlanId"], 10)
        self.assertEqual(item["wlanGroup"], "Default")
        self.assertTrue(item["hasPresharedKey"])

    def test_explain_error_tool_works_without_controller_auth(self):
        client, fake, _ = make_client(password="wrong")
        server = Server(client.config, client=client)
        resp = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "explain_error", "arguments": {"code": -33726}},
        })
        self.assertNotIn("error", resp)
        sc = resp["result"]["structuredContent"]
        self.assertEqual(sc["code"], -33726)
        self.assertIn("16 entries", sc["meaning"])
        self.assertEqual(fake.requests, [])

    def test_network_audit_is_idempotent_and_reports_findings(self):
        devices = [
            {"mac": "AA-BB-CC-00-00-01", "name": "gw", "type": "gateway", "showModel": "ER7206",
             "ip": "192.0.2.1", "firmwareVersion": "2.3.2", "needUpgrade": True,
             "clientNum": 0, "statusCategory": 1},
            {"mac": "AA-BB-CC-00-00-02", "name": "ap-empty", "type": "ap", "showModel": "EAP650",
             "ip": "192.0.2.2", "firmwareVersion": "1.2.0", "needUpgrade": False,
             "clientNum": 0, "statusCategory": 1},
            {"mac": "AA-BB-CC-00-00-03", "name": "sw-down", "type": "switch", "showModel": "ES220",
             "ip": "192.0.2.3", "firmwareVersion": "1.0.0", "needUpgrade": False,
             "clientNum": 0, "statusCategory": 0, "status": 0},
        ]
        clients = [
            {"mac": "AA-BB-CC-11-11-01", "name": "guest-phone", "wireless": True,
             "guest": True, "vid": 50},
            {"mac": "AA-BB-CC-11-11-02", "name": "rogue-box", "wireless": False,
             "guest": False, "vid": 99},
            {"mac": "AA-BB-CC-11-11-03", "name": "iot-1", "wireless": True,
             "guest": False, "vid": 20},
            {"mac": "AA-BB-CC-11-11-04", "name": "iot-2", "wireless": True,
             "guest": False, "vid": 20},
        ]
        lan_networks = [
            {"id": "n20", "name": "IoT", "vlan": 20, "gatewaySubnet": "192.168.20.1/24",
             "accessControlRule": False, "isolation": False,
             "dhcpSettings": {"enable": True, "ipRangePool": [
                 {"ipaddrStart": "192.168.20.10", "ipaddrEnd": "192.168.20.11"}]}},
            {"id": "n50", "name": "Guest", "vlan": 50, "gatewaySubnet": "192.168.50.1/24",
             "accessControlRule": True, "isolation": False,
             "dhcpSettings": {"enable": False}},
        ]
        fake = FakeController(devices=devices, clients=clients, lan_networks=lan_networks)
        client = OmadaClient(make_config(), transport=fake, sleep=lambda _s: None,
                             clock=lambda: 0.0, log_fn=lambda _m: None)
        server = Server(client.config, client=client)

        r1 = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "network_audit", "arguments": {}},
        })["result"]["structuredContent"]
        r2 = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "network_audit", "arguments": {}},
        })["result"]["structuredContent"]

        self.assertEqual(r1, r2)
        self.assertFalse(r1["healthy"])
        codes = {f["code"] for f in r1["findings"]}
        self.assertEqual(codes, {
            "DEVICE_OFFLINE",
            "DEVICE_FIRMWARE_UPGRADE_AVAILABLE",
            "AP_ZERO_CLIENTS",
            "CLIENT_ON_GUEST_NETWORK",
            "CLIENT_UNEXPECTED_VLAN",
            "VLAN_UNISOLATED",
            "DHCP_POOL_NEAR_EXHAUSTION",
        })

    def test_doctor_json_matches_schema_and_reports_family_and_cookie(self):
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "doctor.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        fake = FakeController(controller_ver="6.2.10.17", cookie_name="TPOMADA_SESSIONID")
        client = OmadaClient(make_config(), transport=fake, sleep=lambda _s: None,
                             clock=lambda: 0.0, log_fn=lambda _m: None)
        stream = io.StringIO()
        rc = run_doctor(config_factory=lambda: client.config,
                        client_factory=lambda _cfg: client,
                        stream=stream, json_output=True)
        self.assertEqual(rc, 0)
        doc = json.loads(stream.getvalue())
        self.assertEqual(set(doc.keys()), set(schema["required"]))
        self.assertEqual(doc["status"], "pass")
        self.assertTrue(doc["ready"])
        self.assertEqual(doc["exitCode"], 0)
        self.assertEqual(doc["controller"]["family"], "software-6.x")
        self.assertEqual(doc["controller"]["sessionCookie"], "TPOMADA_SESSIONID")
        self.assertEqual(doc["summary"]["passed"], 6)
        self.assertEqual(doc["summary"]["failed"], 0)

    def test_doctor_json_failure_sets_exit_code_one(self):
        stream = io.StringIO()

        def bad_cfg():
            raise ConfigError("missing required variable(s): OMADA_PASSWORD", hint="add to .env")

        rc = run_doctor(config_factory=bad_cfg, stream=stream, json_output=True)
        self.assertEqual(rc, 1)
        doc = json.loads(stream.getvalue())
        self.assertEqual(doc["status"], "fail")
        self.assertFalse(doc["ready"])
        self.assertEqual(doc["exitCode"], 1)
        self.assertIsNone(doc["site"])
        self.assertEqual(doc["phases"][0]["status"], "FAIL")

    def test_tools_output_schema_matches_structured_content(self):
        devices_with_switch = list(DEVICES) + [
            {"mac": "AA-BB-CC-00-00-03", "name": "sw1", "type": "switch", "showModel": "SG2210P",
             "ip": "192.168.20.3", "firmwareVersion": "1.0.0", "uptime": "3d", "clientNum": 1,
             "statusCategory": 1},
        ]
        fake = FakeController(devices=devices_with_switch)
        cfg = make_config()
        client = OmadaClient(cfg, transport=fake, sleep=lambda _s: None,
                             clock=lambda: 0.0, log_fn=lambda _m: None)
        server = Server(client.config, client=client)
        descriptors = {
            t["name"]: t
            for t in server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
        }
        calls = [
            ("list_devices", {}),
            ("list_clients", {}),
            ("list_wifi_clients", {}),
            ("list_wired_clients", {}),
            ("search_clients", {}),
            ("get_device", {"mac": "AA-BB-CC-00-00-01"}),
            ("get_client", {"mac": "AA-BB-CC-11-11-01"}),
            ("list_wlans", {}),
            ("list_lan_networks", {}),
            ("list_dhcp_reservations", {}),
            ("list_acls", {}),
            ("list_ip_groups", {}),
            ("list_port_forwards", {}),
            ("list_static_routes", {}),
            ("get_network_services", {}),
            ("list_logs", {}),
            ("get_site_info", {}),
            ("network_audit", {}),
            ("explain_error", {"code": -33726}),
            ("get_config_snapshot", {
                "objects": [
                    "wlans", "devices", "clients", "dhcpReservations",
                    "portForwards", "staticRoutes", "mdnsRules", "services",
                ],
            }),
            ("get_switch_ports", {"mac": "AA-BB-CC-00-00-03"}),
            ("get_ap_radios", {"mac": "AA-BB-CC-00-00-02"}),
            ("get_rf_scan", {"mac": "AA-BB-CC-00-00-02"}),
            ("get_wan_status", {}),
            ("list_vpn_tunnels", {}),
            ("get_topology", {}),
            ("get_security_status", {}),
            ("diagnose_client", {"mac": "AA-BB-CC-11-11-01"}),
            ("diagnose_wan", {}),
            ("list_port_profiles", {}),
            ("list_wlan_groups", {}),
            ("list_policy_routes", {}),
            ("list_lan_dns_rules", {}),
        ]
        self.assertEqual({name for name, _ in calls}, set(descriptors))
        for name, args in calls:
            schema = descriptors[name]["outputSchema"]
            result = server.handle({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": name, "arguments": args},
            })["result"]
            self.assertFalse(result["isError"], name)
            sc = result["structuredContent"]
            self.assertIsInstance(sc, dict, name)
            for req_key in schema["required"]:
                self.assertIn(req_key, sc, f"{name} missing required key {req_key}")
            if name.startswith("list_") and "items" in schema.get("properties", {}) and "required" in schema["properties"]["items"].get("items", {}):
                text_payload = json.loads(result["content"][0]["text"])
                self.assertIsInstance(text_payload, list, name)
                self.assertEqual(sc["count"], len(sc["items"]), name)
                item_schema = schema["properties"]["items"]["items"]
                for item in sc["items"]:
                    for item_req in item_schema["required"]:
                        self.assertIn(item_req, item, f"{name} item missing {item_req}")

    def test_doctor_json_redacts_filesystem_paths(self):
        from omada_mcp import doctor as doctor_module

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_file = tmp_path / "secret-profile.env"
            env_file.write_text(
                "OMADA_BASE_URL=https://controller.test:8043\n"
                "OMADA_USERNAME=admin\n"
                "OMADA_PASSWORD=pw\n",
                encoding="utf-8",
            )
            env_file.chmod(0o644)
            ca_file = tmp_path / "controller-ca.pem"
            ca_file.write_text("-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----\n",
                               encoding="utf-8")

            cfg = load_config(
                environ={"OMADA_ENV_FILE": str(env_file), "OMADA_CA_BUNDLE": str(ca_file)},
                cwd=tmp_path,
            )
            self.assertEqual(cfg.env_origin, "OMADA_ENV_FILE")
            self.assertEqual(cfg.masked()["env_origin"], "OMADA_ENV_FILE")

            fake = FakeController(controller_ver="6.2.10.17", cookie_name="TPOMADA_SESSIONID")
            client = OmadaClient(cfg, transport=fake, sleep=lambda _s: None,
                                 clock=lambda: 0.0, log_fn=lambda _m: None)
            stream = io.StringIO()
            with mock.patch.object(doctor_module, "_IS_WINDOWS", False):
                rc = doctor_module.run_doctor(
                    config_factory=lambda: cfg,
                    client_factory=lambda _c: client,
                    stream=stream,
                    json_output=True,
                )
            self.assertEqual(rc, 0)
            raw_json = stream.getvalue()
            self.assertNotIn(str(tmp_path), raw_json)
            self.assertNotIn("secret-profile.env", raw_json)
            self.assertNotIn("controller-ca.pem", raw_json)
            doc = json.loads(raw_json)
            self.assertTrue(doc["phases"][0]["detail"].startswith("OMADA_ENV_FILE | "))
            self.assertIn("OMADA_CA_BUNDLE", doc["phases"][2]["detail"])

    def test_config_env_origin_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cwd_dir = tmp_path / "work"
            cwd_dir.mkdir()
            (cwd_dir / ".env").write_text(
                "OMADA_BASE_URL=https://cwd:8043\nOMADA_USERNAME=u\nOMADA_PASSWORD=p\n",
                encoding="utf-8",
            )
            self.assertEqual(load_config(environ={}, cwd=cwd_dir).env_origin, "cwd")

            appdata_dir = tmp_path / "roaming"
            (appdata_dir / "omada-mcp").mkdir(parents=True)
            (appdata_dir / "omada-mcp" / ".env").write_text(
                "OMADA_BASE_URL=https://win:8043\nOMADA_USERNAME=u\nOMADA_PASSWORD=p\n",
                encoding="utf-8",
            )
            empty_dir = tmp_path / "empty"
            empty_dir.mkdir()
            with mock.patch.object(config_module, "_IS_WINDOWS", True):
                self.assertEqual(
                    load_config(environ={"APPDATA": str(appdata_dir)}, cwd=empty_dir).env_origin,
                    "appdata",
                )

            xdg_dir = tmp_path / "xdg"
            (xdg_dir / "omada-mcp").mkdir(parents=True)
            (xdg_dir / "omada-mcp" / ".env").write_text(
                "OMADA_BASE_URL=https://xdg:8043\nOMADA_USERNAME=u\nOMADA_PASSWORD=p\n",
                encoding="utf-8",
            )
            with mock.patch.object(config_module, "_IS_WINDOWS", False):
                self.assertEqual(
                    load_config(environ={"XDG_CONFIG_HOME": str(xdg_dir)}, cwd=empty_dir).env_origin,
                    "xdg",
                )

            self.assertEqual(
                load_config(
                    environ={
                        "OMADA_BASE_URL": "https://env:8043",
                        "OMADA_USERNAME": "u",
                        "OMADA_PASSWORD": "p",
                    },
                    cwd=empty_dir,
                ).env_origin,
                "environment",
            )


class Milestone1DiagnosticsTests(unittest.TestCase):
    def _mock_server(self, *, read_only: bool = True):
        from mock_controller import MockController

        ctrl = MockController(username="viewer", password="pw", role="Viewer")
        cfg = make_config(username="viewer", read_only=read_only)
        client = OmadaClient(cfg, transport=ctrl, sleep=lambda _s: None,
                             clock=lambda: 0.0, log_fn=lambda _m: None)
        return Server(cfg, client=client), ctrl

    def _call(self, server: Server, name: str, arguments: dict):
        resp = server.handle({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        assert "error" not in resp, resp
        return resp["result"]["structuredContent"]

    def test_switch_ports_uplink_poe_and_controller_port(self):
        server, _ = self._mock_server()
        res = self._call(server, "get_switch_ports", {"mac": "sw-access"})
        self.assertEqual(res["mac"], "aa:bb:cc:00:00:02")
        self.assertTrue(res["poe"]["supported"])
        self.assertEqual(res["poe"]["totalBudgetW"], 250.0)
        self.assertIn(17, res["uplinkPorts"])
        by_port = {p["port"]: p for p in res["ports"]}
        self.assertTrue(by_port[17]["isUplink"])
        self.assertTrue(by_port[3]["poeDelivering"])
        self.assertGreater(by_port[3]["poePowerW"], 0.0)
        self.assertTrue(by_port[15]["carriesController"])

    def test_ap_radios_resolves_channel_index_and_width_flags(self):
        server, _ = self._mock_server()
        res = self._call(server, "get_ap_radios", {"mac": "AA-BB-CC-00-00-03"})
        by_band = {r["band"]: r for r in res["radios"]}
        self.assertEqual(by_band["5g"]["channelWireValue"], "9")
        self.assertEqual(by_band["5g"]["channel"], 100)
        self.assertEqual(by_band["5g"]["channelWidth"], "160MHz")
        ch36 = next(c for c in by_band["5g"]["availableChannels"] if c["channel"] == 36)
        self.assertEqual(ch36["widths"], ["20MHz", "40MHz", "80MHz", "160MHz"])
        self.assertNotIn("synthetic-test-passphrase-never-leak", json.dumps(res))

        rf = self._call(server, "get_rf_scan", {"mac": "ap-living"})
        self.assertEqual(rf["mac"], "aa:bb:cc:00:00:03")
        self.assertEqual(rf["status"], 1)

    def test_wan_status_and_mask_wan_ip(self):
        server, ctrl = self._mock_server()
        ctrl.gateway_details["AA-BB-CC-00-00-01"]["portConfigs"][1]["portStat"]["ip"] = "203.0.113.42"
        ctrl.gateway_details["AA-BB-CC-00-00-01"]["portConfigs"][1]["portStat"]["wanPortIpv4Config"]["ip"] = "203.0.113.42"
        ctrl.port_state_details["portInfos"][1]["ip"] = "203.0.113.42"
        unmasked = self._call(server, "get_wan_status", {})
        self.assertTrue(unmasked["hasGateway"])
        wan2 = next(p for p in unmasked["ports"] if p["port"] == 2)
        self.assertEqual(wan2["ip"], "203.0.113.42")
        self.assertEqual(wan2["latencyMs"], 96.0)

        masked = self._call(server, "get_wan_status", {"maskWanIp": True})
        wan2_m = next(p for p in masked["ports"] if p["port"] == 2)
        self.assertEqual(wan2_m["ip"], "203.0.***.***")

    def test_vpn_tunnels_redacts_secrets_and_pem_blocks(self):
        server, ctrl = self._mock_server()
        ctrl.vpn_tunnels = [{
            "name": "wg-home",
            "vpnCategory": "wireguard",
            "status": 1,
            "privateKey": "SUPER-SECRET-WG-PRIVKEY",
            "presharedKey": "SUPER-SECRET-WG-PSK",
            "peerConfig": "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----",
        }]
        ctrl.vpn_configs = [{
            "name": "ipsec-site2site",
            "vpnCategory": "vpn",
            "preSharedKey": "IPSEC-PSK-1234",
            "password": "VPN-USER-PASS",
        }]
        res = self._call(server, "list_vpn_tunnels", {})
        raw = json.dumps(res)
        for secret in ("SUPER-SECRET-WG-PRIVKEY", "SUPER-SECRET-WG-PSK", "IPSEC-PSK-1234", "VPN-USER-PASS", "BEGIN PRIVATE KEY"):
            self.assertNotIn(secret, raw)
        self.assertEqual(res["counts"]["upTunnels"], 1)

    def test_topology_and_v5_fallback(self):
        server, ctrl = self._mock_server()
        topo = self._call(server, "get_topology", {})
        self.assertEqual(topo["counts"]["gateways"], 1)
        self.assertEqual(topo["counts"]["switches"], 1)
        self.assertEqual(topo["counts"]["aps"], 2)
        ctrl.topology_v2_supported = False
        topo_v5 = self._call(server, "get_topology", {})
        self.assertEqual(topo_v5["counts"]["aps"], 2)
        self.assertTrue(any("topology-v2" in w for w in topo_v5["warnings"]))

    def test_security_status_and_graceful_degradation_when_hardware_missing(self):
        server, ctrl = self._mock_server()
        sec = self._call(server, "get_security_status", {})
        self.assertIsNotNone(sec["ips"])
        self.assertIsNone(sec["wids"])
        self.assertTrue(any("WIDS" in w for w in sec["warnings"]))

        ctrl.has_gateway = False
        ctrl.devices = [d for d in ctrl.devices if d["type"] != "gateway"]
        ctrl.lan_dns_supported = False
        wan = self._call(server, "get_wan_status", {})
        self.assertFalse(wan["hasGateway"])
        self.assertTrue(wan["warnings"])
        pr = self._call(server, "list_policy_routes", {})
        self.assertFalse(pr["supported"])
        dns = self._call(server, "list_lan_dns_rules", {})
        self.assertFalse(dns["supported"])

    def test_diagnose_client_diagnose_wan_and_enriched_network_audit(self):
        server, ctrl = self._mock_server()
        ctrl.clients["AA-BB-CC-11-11-02"].update({"rssi": -85, "snr": 9, "radioId": 1, "channel": 100})
        ctrl.eap_details["AA-BB-CC-00-00-03"]["radioTraffic5g"].update({"txPkts": 1000, "txRetryPkts": 250})
        ctrl.switch_details["AA-BB-CC-00-00-02"]["poeRemain"] = 10.0
        ctrl.switch_details["AA-BB-CC-00-00-02"]["poeRemainPercent"] = 4.0
        next(r for r in ctrl.switch_insight_counters["AA-BB-CC-00-00-02"] if r["port"] == 3)["rxErrors"] = 7
        ctrl.switch_ports["AA-BB-CC-00-00-02"][0].update({"port": 17, "maxSpeed": 3, "portStatus": {"linkStatus": 1, "linkSpeed": 2, "duplex": 2}})
        ctrl.gateway_details["AA-BB-CC-00-00-01"]["portConfigs"][1]["portStat"]["loss"] = 3.5

        dc = self._call(server, "diagnose_client", {"mac": "AA-BB-CC-11-11-02"})
        codes = {f["code"] for f in dc["findings"]}
        self.assertIn("CLIENT_CRITICAL_RSSI", codes)
        self.assertIn("CLIENT_LOW_SNR", codes)
        self.assertIn("AP_RADIO_HIGH_RETRIES", codes)
        self.assertIsNotNone(dc["parentRadio"])

        dc_wired = self._call(server, "diagnose_client", {"mac": "AA-BB-CC-11-11-01"})
        self.assertIsNotNone(dc_wired["parentSwitchPort"])
        self.assertIn("SWITCH_PORT_PACKET_ERRORS", {f["code"] for f in dc_wired["findings"]})

        dw = self._call(server, "diagnose_wan", {})
        w_codes = {f["code"] for f in dw["findings"]}
        self.assertIn("WAN_PACKET_LOSS", w_codes)

        audit = self._call(server, "network_audit", {})
        a_codes = {f["code"] for f in audit["findings"]}
        self.assertIn("SWITCH_POE_BUDGET_HIGH", a_codes)
        self.assertIn("AP_HIGH_RETRY_RATE", a_codes)
        self.assertIn("WAN_PACKET_LOSS", a_codes)
        # issue #3: the enrichment wrapper must not re-derive health from criticals
        # alone — warnings appended by enrichment keep the audit unhealthy.
        self.assertGreater(audit["counts"]["warnings"], 0)
        self.assertFalse(audit["healthy"])
        self.assertFalse(_findings_healthy([{"severity": "warning"}]))
        self.assertTrue(_findings_healthy([]))
        self.assertTrue(_findings_healthy([{"severity": "info"}]))

    def test_list_acls_backward_compatible_and_ro_token_budget(self):
        server, ctrl = self._mock_server()
        ctrl.switch_acls = [{"id": "sw-a1", "name": "SwitchDeny", "status": True, "policy": 0, "sourceIds": ["1"], "destinationIds": ["2"], "bindingType": 0}]
        gw_only = self._call(server, "list_acls", {})
        self.assertTrue(gw_only["items"])
        sw_only = self._call(server, "list_acls", {"aclType": "switch"})
        self.assertEqual(sw_only["items"][0]["aclType"], "switch")
        ro = server.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/list"})["result"]["tools"]
        approx_tokens = len(json.dumps(ro)) // 4
        self.assertLess(approx_tokens, 25000)


class Milestone3MonitorAndPackagingTests(unittest.TestCase):
    def _mock_client_setup(self, *, username: str = "admin-writer", role: str = "Administrator"):
        from mock_controller import MockController

        ctrl = MockController(username=username, password="pw", role=role)
        cfg = make_config(username=username, read_only=True)

        def _factory(c):
            return OmadaClient(
                c, transport=ctrl, sleep=lambda _s: None,
                clock=lambda: 0.0, log_fn=lambda _m: None,
            )

        return cfg, ctrl, _factory

    def test_watch_single_session_pacing_and_diff_events(self):
        cfg, ctrl, factory = self._mock_client_setup()
        # Narrow VLAN 20 DHCP pool so adding clients crosses >=80% utilization.
        net20 = next(n for n in ctrl.lan_collection if n.get("vlan") == 20)
        net20["dhcpSettings"] = {
            "enable": True,
            "ipRangePool": [{"ipaddrStart": "192.168.20.10", "ipaddrEnd": "192.168.20.19"}],
        }
        ctrl.clients["AA-BB-CC-11-11-02"]["rssi"] = -62

        sleeps = []

        def _on_sleep(sec: float) -> None:
            sleeps.append(sec)
            # Mutate WAN, AP retries, weak client RSSI, and DHCP pool occupancy for tick 2.
            ctrl.gateway_details["AA-BB-CC-00-00-01"]["portConfigs"][1]["portStat"]["internetState"] = 0
            ctrl.eap_details["AA-BB-CC-00-00-03"]["radioTraffic5g"].update({"txPkts": 1000, "txRetryPkts": 320})
            ctrl.clients["AA-BB-CC-11-11-02"]["rssi"] = -82
            for idx in range(4, 10):
                cmac = f"AA-BB-CC-11-11-{idx:02X}"
                ctrl.clients[cmac] = {
                    "mac": cmac, "name": f"sensor-{idx}", "hostName": f"sensor-{idx}",
                    "ip": f"192.168.20.{10 + idx}", "wireless": False,
                    "networkName": "IoT", "networkId": "net-iot-20",
                    "vid": 20, "vlan": 20, "guest": False, "active": True,
                }

        buf = io.StringIO()
        rc = run_watch(
            cfg, interval=0.2, iterations=2, out=buf,
            sleep_fn=_on_sleep, client_factory=factory,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(ctrl.logins, 1)
        self.assertEqual(sleeps, [MIN_POLL_INTERVAL_SECONDS])

        lines = [json.loads(line) for line in buf.getvalue().strip().splitlines()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["event"], "snapshot")
        self.assertNotIn('"pw"', buf.getvalue())
        self.assertEqual(lines[1]["event"], "diff")
        categories = {ch["category"] for ch in lines[1]["changes"]}
        self.assertEqual(
            categories,
            {"wan_failover", "ap_retry_spike", "weak_client_rssi", "dhcp_pool_utilization"},
        )

    def test_export_metrics_once_and_cli_validation(self):
        cfg, ctrl, factory = self._mock_client_setup()
        ctrl.clients["AA-BB-CC-11-11-02"]["rssi"] = -64

        buf = io.StringIO()
        rc = export_metrics_once(cfg, out=buf, client_factory=factory)
        self.assertEqual(rc, 0)
        self.assertEqual(ctrl.logins, 1)
        prom = buf.getvalue()
        for metric in (
            "omada_up",
            "omada_device_up",
            "omada_wan_link_up",
            "omada_wan_failover_active",
            "omada_ap_radio_tx_retry_rate_pct",
            "omada_client_rssi_dbm",
            "omada_dhcp_pool_utilization_ratio",
        ):
            self.assertIn(metric, prom)
        self.assertNotIn("synthetic-test-passphrase", prom)

        # CLI --export-metrics path and invalid flag rejection
        cli_out = io.StringIO()
        cli_err = io.StringIO()
        with mock.patch("omada_mcp.cli.load_config", return_value=cfg), \
             mock.patch("omada_mcp.monitor.OmadaClient", side_effect=factory), \
             mock.patch("sys.stdout", cli_out), \
             mock.patch("sys.stderr", cli_err):
            self.assertEqual(cli_main(["--export-metrics"]), 0)
            self.assertEqual(cli_main(["--watch", "--export-metrics"]), 2)
            self.assertEqual(cli_main(["--watch", "--interval", "0"]), 2)
            self.assertEqual(cli_main(["--metrics-port", "9108"]), 2)
        self.assertIn("omada_up{site=\"Mock Lab Site\"} 1", cli_out.getvalue())

        # Viewer-role fallback via insight/clients + signalLevel% also exports cleanly.
        v_cfg, v_ctrl, v_factory = self._mock_client_setup(username="viewer", role="Viewer")
        v_ctrl.clients["AA-BB-CC-11-11-02"]["signalLevel"] = 45
        v_buf = io.StringIO()
        self.assertEqual(export_metrics_once(v_cfg, out=v_buf, client_factory=v_factory), 0)
        self.assertIn("omada_client_signal_pct", v_buf.getvalue())

    def test_metrics_http_server_caching_and_healthz(self):
        import threading

        cfg, ctrl, factory = self._mock_client_setup()
        httpd = serve_metrics_http(
            cfg, host="127.0.0.1", port=0, min_scrape_interval=60.0,
            client_factory=factory,
        )
        thread = threading.Thread(
            target=httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        try:
            base = f"http://127.0.0.1:{httpd.server_port}"
            with urllib.request.urlopen(base + "/healthz", timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.read().decode("utf-8").strip(), "ok")

            with urllib.request.urlopen(base + "/metrics", timeout=3) as r1:
                self.assertEqual(r1.status, 200)
                self.assertIn("text/plain", r1.headers.get("Content-Type", ""))
                body1 = r1.read().decode("utf-8")
            reqs_after_first = len(ctrl.requests)

            with urllib.request.urlopen(base + "/metrics", timeout=3) as r2:
                self.assertEqual(r2.status, 200)
                body2 = r2.read().decode("utf-8")
            self.assertEqual(body1, body2)
            self.assertEqual(len(ctrl.requests), reqs_after_first)
            self.assertEqual(ctrl.logins, 1)
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)

    def test_dockerfile_non_root_and_env_defaults(self):
        import subprocess

        root = Path(__file__).resolve().parents[1]
        df = (root / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("USER omada", df)
        self.assertIn("PYTHONPATH=/app/src", df)
        self.assertIn("OMADA_READ_ONLY=true", df)
        self.assertIn('ENTRYPOINT ["python", "-m", "omada_mcp"]', df)

        env = dict(os.environ, PYTHONPATH=str(root / "src"))
        out = subprocess.check_output(
            [sys.executable, "-m", "omada_mcp", "--list-tools"],
            env=env, text=True,
        )
        data = json.loads(out)
        self.assertEqual(len(data["tools"]), 33)


class OptimizationTests(unittest.TestCase):
    def test_urllib_transport_connection_reuse_and_cookie_roundtrip(self):
        import http.server
        import threading
        from omada_mcp.client import UrllibTransport

        seen_cookies = []

        class KeepAliveHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):  # noqa: A002
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                body = b'{"errorCode":0,"result":{"token":"t1"}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "TPOMADA_SESSIONID=pool-cookie; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                seen_cookies.append(self.headers.get("Cookie", ""))
                body = b'{"errorCode":0,"result":{"ok":true}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class CountingServer(http.server.ThreadingHTTPServer):
            accepted_connections = 0

            def get_request(self):
                sock, addr = super().get_request()
                CountingServer.accepted_connections += 1
                return sock, addr

        CountingServer.accepted_connections = 0
        httpd = CountingServer(("127.0.0.1", 0), KeepAliveHandler)
        thread = threading.Thread(
            target=httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        transport = UrllibTransport(build_ssl_context(make_config()), timeout=5.0)
        try:
            base = f"http://127.0.0.1:{httpd.server_port}"
            st1, _ = transport.request("POST", base + "/login", data=b"{}")
            self.assertEqual(st1, 200)
            for idx in range(3):
                st, body = transport.request("GET", f"{base}/api/test/{idx}")
                self.assertEqual(st, 200)
                self.assertEqual(json.loads(body)["result"]["ok"], True)

            self.assertEqual(CountingServer.accepted_connections, 1)
            self.assertEqual(transport.connections_created, 1)
            self.assertEqual(transport.requests_reused, 3)
            self.assertEqual(seen_cookies, ["TPOMADA_SESSIONID=pool-cookie"] * 3)
        finally:
            transport.close()
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)

    def test_urllib_transport_stale_socket_recovery_get_vs_non_idempotent_post(self):
        import http.client
        from omada_mcp.client import UrllibTransport

        transport = UrllibTransport(build_ssl_context(make_config()), timeout=5.0)
        try:
            def make_resp(status, payload, headers_dict=None):
                resp = mock.MagicMock()
                resp.status = status
                resp.read.return_value = payload
                resp.headers = None
                resp.msg = None
                resp.will_close = False
                return resp

            conn1 = mock.MagicMock()
            conn1.sock = object()
            # First GET succeeds; second GET on same pooled conn gets RemoteDisconnected.
            conn1.getresponse.side_effect = [
                make_resp(200, b'{"errorCode":0,"result":1}'),
                http.client.RemoteDisconnected("peer closed idle socket"),
            ]
            conn2 = mock.MagicMock()
            conn2.sock = object()
            conn2.getresponse.side_effect = [
                make_resp(200, b'{"errorCode":0,"result":2}'),
                # Post-send disconnect during POST must NOT replay!
                http.client.RemoteDisconnected("dropped after POST transmit"),
            ]

            with mock.patch("http.client.HTTPSConnection", side_effect=[conn1, conn2]) as ctor:
                st1, b1 = transport.request("GET", "https://omada.local:8043/api/one")
                self.assertEqual(st1, 200)
                self.assertEqual(json.loads(b1)["result"], 1)

                st2, b2 = transport.request("GET", "https://omada.local:8043/api/two")
                self.assertEqual(st2, 200)
                self.assertEqual(json.loads(b2)["result"], 2)
                self.assertEqual(ctor.call_count, 2)

                with self.assertRaises(OmadaError) as ctx:
                    transport.request(
                        "POST",
                        "https://omada.local:8043/api/write",
                        data=b'{"x":1}',
                    )
                self.assertIn("not replayed automatically", ctx.exception.hint)
                # Ensure POST was transmitted once only on conn2 and ctor was NOT called a 3rd time.
                self.assertEqual(ctor.call_count, 2)
                post_calls = [c for c in conn2.request.call_args_list if c.args[0] == "POST"]
                self.assertEqual(len(post_calls), 1)
        finally:
            transport.close()

    def test_urllib_transport_proxied_fallback_uses_opener(self):
        from omada_mcp.client import UrllibTransport

        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:8888", "NO_PROXY": ""}, clear=False):
            transport = UrllibTransport(build_ssl_context(make_config()), use_system_proxy=True)
        try:
            self.assertEqual(transport.proxy_mode, "system")
            fake_resp = mock.MagicMock()
            fake_resp.getcode.return_value = 200
            fake_resp.read.return_value = b'{"ok":true}'
            with mock.patch.object(transport.opener, "open", return_value=fake_resp) as open_mock, \
                 mock.patch("http.client.HTTPSConnection") as pool_ctor:
                st, body = transport.request("GET", "https://omada.local:8043/api/info")
            self.assertEqual(st, 200)
            self.assertEqual(body, b'{"ok":true}')
            open_mock.assert_called_once()
            pool_ctor.assert_not_called()
        finally:
            transport.close()

    def test_scoped_cache_deduplicates_multi_switch_audit_without_cross_call_staleness(self):
        from mock_controller import MockController
        from omada_mcp.server import Server

        ctrl = MockController(username="admin", password="pw", role="Administrator")
        ctrl.devices.extend([
            {
                "mac": "11-22-33-44-55-02", "name": "sw-dist", "type": "switch",
                "model": "TL-SG3428MP", "showModel": "TL-SG3428MP", "status": 1,
                "poeSupport": True, "poeTotalPower": 384.0, "poeRemain": 320.0,
            },
            {
                "mac": "AA-BB-CC-00-00-02", "name": "ap-office", "type": "ap",
                "model": "EAP670", "showModel": "EAP670", "status": 1,
            },
        ])
        cfg = make_config(username="admin", read_only=True)
        client = OmadaClient(
            cfg, transport=ctrl, sleep=lambda _s: None,
            clock=lambda: 0.0, log_fn=lambda _m: None,
        )
        client.authenticate()
        ctrl.requests.clear()

        server = Server(cfg, client=client)
        res = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "network_audit", "arguments": {}},
        })["result"]
        self.assertFalse(res["isError"])

        endpoints = [req["path"] for req in ctrl.requests]
        for site_wide in (
            "/setting/lan/profiles",
            "/insight/switch/detail",
            "/insight/switch/port/poe",
            "/devices",
        ):
            hits = [ep for ep in endpoints if ep.endswith(site_wide)]
            self.assertEqual(len(hits), 1, f"expected 1 request for {site_wide}, got {hits}")
        self.assertLess(len(endpoints), 25)

        # Outside scoped_cache, consecutive tool calls never see stale cached devices.
        r1 = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "list_devices", "arguments": {}},
        })["result"]["structuredContent"]
        ctrl.devices.append({
            "mac": "AA-BB-CC-00-00-09", "name": "ap-hall", "type": "ap",
            "model": "EAP670", "showModel": "EAP670", "status": 1,
        })
        r2 = server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "list_devices", "arguments": {}},
        })["result"]["structuredContent"]
        self.assertEqual(r2["count"], r1["count"] + 1)

        # Mutating returned dicts inside scoped_cache must not poison the cached copy.
        with client.scoped_cache():
            p1 = client.api_result(f"sites/{client.site.site_id}/devices")
            p1["data"].clear()
            p2 = client.api_result(f"sites/{client.site.site_id}/devices")
            self.assertGreater(len(p2["data"]), 0)

    def test_schema_mode_slim_vs_full_categories_and_compact_output(self):
        from mock_controller import MockController
        from omada_mcp.cli import main as cli_main
        from omada_mcp.config import VALID_TOOL_CATEGORIES
        from omada_mcp.server import Server
        from omada_mcp.tools import TOOLS, TOOL_MAP, tool_descriptors

        for tool in TOOLS:
            self.assertIn(tool.category, VALID_TOOL_CATEGORIES)

        for mode in ("slim", "full"):
            all_descs = tool_descriptors(include_all=True, schema_mode=mode)
            self.assertEqual(len(all_descs), len(TOOLS))
            for desc in all_descs:
                self.assertEqual(desc["outputSchema"]["type"], "object", f"{mode}:{desc['name']}")
                self.assertTrue(desc["outputSchema"]["properties"], f"{mode}:{desc['name']}")
                self.assertTrue(desc["outputSchema"]["required"], f"{mode}:{desc['name']}")
                # Input schema properties and required constraints preserved identically.
                orig_in = TOOL_MAP[desc["name"]].input_schema
                self.assertEqual(
                    set((desc["inputSchema"].get("properties") or {}).keys()),
                    set((orig_in.get("properties") or {}).keys()),
                )
                self.assertEqual(desc["inputSchema"].get("required"), orig_in.get("required"))

        slim_ro = tool_descriptors(schema_mode="slim")
        full_ro = tool_descriptors(schema_mode="full")
        slim_all = tool_descriptors(include_all=True, schema_mode="slim")
        full_all = tool_descriptors(include_all=True, schema_mode="full")

        sz = lambda obj: len(json.dumps({"tools": obj}, separators=(",", ":"), ensure_ascii=False))
        self.assertLessEqual(sz(slim_ro), int(sz(full_ro) * 0.55))
        self.assertLessEqual(sz(slim_all), int(sz(full_all) * 0.62))

        # Slim descriptions snap on complete sentences/words (~110 chars) without mid-word cuts.
        slim_by_name = {d["name"]: d for d in slim_all}
        for d in slim_all:
            desc = d["description"]
            self.assertLessEqual(len(desc), 110, d["name"])
            if desc.endswith("…"):
                self.assertTrue(
                    len(desc) < 2 or not desc[-2].isalnum() or " " not in desc[:-1] or
                    TOOL_MAP[d["name"]].description.strip()[len(desc) - 1 : len(desc)] in (" ", "", ".", ",", ";", ":", "("),
                    f"mid-word cut in slim description for {d['name']}: {desc!r}",
                )
        self.assertEqual(
            slim_by_name["update_switch_port"]["description"],
            "Configure switch port status, name, port profile, PoE, speed/duplex, VLAN overrides, or isolation.",
        )
        self.assertNotIn("VLAN overr…", slim_by_name["update_switch_port"]["description"])
        self.assertGreater(len(slim_by_name["explain_error"]["description"]), 60)

        # Slim inputSchema retains enums and <=45-char code hints on integer/string-code params.
        self.assertEqual(
            slim_by_name["create_ssid"]["inputSchema"]["properties"]["security"]["enum"],
            ["open", "wpa-psk", "wpa2-psk", "wpa-wpa2-psk", "wpa3-sae"],
        )
        self.assertEqual(
            slim_by_name["create_switch_acl"]["inputSchema"]["properties"]["source"]["properties"]["type"]["enum"],
            ["network", "ip_group", "port_group", "mac_group"],
        )
        self.assertEqual(
            slim_by_name["create_eap_acl"]["inputSchema"]["properties"]["source"]["properties"]["type"]["enum"],
            ["network", "ip_group", "port_group", "mac_group", "ssid"],
        )
        for tool_name, path in (
            ("list_ip_groups", ("groupType",)),
            ("create_gateway_acl", ("policy",)),
            ("create_gateway_acl", ("source", "properties", "type")),
            ("update_switch_port", ("linkSpeed",)),
            ("upsert_port_profile", ("poeMode",)),
            ("update_ap_radio", ("channelWidth",)),
            ("update_ap_radio", ("txPowerLevel",)),
            ("upsert_policy_route", ("sourceType",)),
            ("upsert_lan_dns_rule", ("ruleType",)),
            ("create_switch_acl", ("bindingType",)),
        ):
            cur = slim_by_name[tool_name]["inputSchema"]["properties"]
            for idx, seg in enumerate(path):
                cur = cur[seg] if idx == 0 else cur[seg]
            hint = cur.get("description", "")
            self.assertTrue(hint, f"missing code hint for {tool_name}.{'.'.join(path)}")
            self.assertLessEqual(len(hint), 45, f"hint >45 chars for {tool_name}.{'.'.join(path)}: {hint!r}")

        diag_switch = tool_descriptors(categories=("diagnostics", "switch"))
        self.assertTrue(diag_switch)
        self.assertTrue(all(TOOL_MAP[d["name"]].category in ("diagnostics", "switch") for d in diag_switch))
        with self.assertRaises(ConfigError):
            tool_descriptors(categories=("nonexistent",))

        with mock.patch.dict(os.environ, {
            "OMADA_BASE_URL": "omada.local",
            "OMADA_USERNAME": "u",
            "OMADA_PASSWORD": "p",
            "OMADA_SCHEMA_MODE": "badmode",
        }, clear=True):
            with self.assertRaises(ConfigError):
                load_config(cwd=tempfile.gettempdir())

        # CLI --list-tools --compact emits single-line compact JSON.
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf), \
             mock.patch.dict(os.environ, {"OMADA_SCHEMA_MODE": "slim", "OMADA_TOOL_CATEGORIES": "switch"}, clear=False):
            rc = cli_main(["--list-tools", "--compact"])
        self.assertEqual(rc, 0)
        line = buf.getvalue().strip()
        self.assertNotIn("\n", line)
        parsed = json.loads(line)
        self.assertEqual({t["name"] for t in parsed["tools"]}, {"get_switch_ports", "list_port_profiles"})

        # OMADA_COMPACT_OUTPUT=true vs false and get_switch_ports(includeDownPorts=False, compact=True).
        ctrl = MockController(username="admin", password="pw", role="Administrator")
        cfg_compact = make_config(username="admin", read_only=True)
        client = OmadaClient(
            cfg_compact, transport=ctrl, sleep=lambda _s: None,
            clock=lambda: 0.0, log_fn=lambda _m: None,
        )
        srv_compact = Server(cfg_compact, client=client)
        r_full = srv_compact.handle({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "get_switch_ports", "arguments": {"mac": "sw-access"}},
        })["result"]
        r_trimmed = srv_compact.handle({
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": {
                "name": "get_switch_ports",
                "arguments": {"mac": "sw-access", "includeDownPorts": False, "compact": True},
            },
        })["result"]
        self.assertNotIn("\n", r_full["content"][0]["text"])
        self.assertLess(len(r_trimmed["content"][0]["text"]), len(r_full["content"][0]["text"]))
        sc_trimmed = r_trimmed["structuredContent"]
        self.assertTrue(all(p["linkUp"] for p in sc_trimmed["ports"]))
        self.assertNotIn("cableTest", sc_trimmed["ports"][0])
        self.assertEqual(sc_trimmed["poe"], r_full["structuredContent"]["poe"])

        with mock.patch.dict(os.environ, {
            "OMADA_BASE_URL": "omada.local",
            "OMADA_USERNAME": "u",
            "OMADA_PASSWORD": "p",
            "OMADA_COMPACT_OUTPUT": "false",
        }, clear=True):
            cfg_pretty = load_config(cwd=tempfile.gettempdir())
        self.assertTrue(cfg_pretty.read_only)
        self.assertTrue(Config(base_url="https://omada.local:8043", username="u", password="p").read_only)

        # CLI --list-tools also stays read-only by default even if OMADA_WRITE_TOOLS is set.
        buf_ro = io.StringIO()
        with mock.patch("sys.stdout", buf_ro), \
             mock.patch.dict(os.environ, {"OMADA_WRITE_TOOLS": "set_client_fixed_ip"}, clear=True):
            self.assertEqual(cli_main(["--list-tools"]), 0)
        self.assertEqual(len(json.loads(buf_ro.getvalue())["tools"]), 33)

        buf_wr = io.StringIO()
        with mock.patch("sys.stdout", buf_wr), \
             mock.patch.dict(
                 os.environ,
                 {"OMADA_READ_ONLY": "false", "OMADA_WRITE_TOOLS": "set_client_fixed_ip"},
                 clear=True,
             ):
            self.assertEqual(cli_main(["--list-tools"]), 0)
        self.assertEqual(len(json.loads(buf_wr.getvalue())["tools"]), 34)
        srv_pretty = Server(cfg_pretty, client=client)
        r_pretty = srv_pretty.handle({
            "jsonrpc": "2.0", "id": 12, "method": "tools/call",
            "params": {"name": "get_switch_ports", "arguments": {"mac": "sw-access"}},
        })["result"]
        self.assertIn("\n", r_pretty["content"][0]["text"])
        self.assertEqual(r_pretty["structuredContent"], r_full["structuredContent"])


if __name__ == "__main__":
    unittest.main()
