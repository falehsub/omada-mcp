"""Unit tests for omada-mcp -- stdlib only, no network, no controller required.

Run with::

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from omada_mcp import __version__  # noqa: E402
from omada_mcp.client import (  # noqa: E402
    BURST_BACKOFF_SECONDS,
    OmadaClient,
    OmadaError,
    build_ssl_context,
    describe_error,
)
from omada_mcp.config import (  # noqa: E402
    Config,
    ConfigError,
    load_config,
    normalize_base_url,
    parse_env_text,
)
from omada_mcp.doctor import run_doctor  # noqa: E402
from omada_mcp.server import Server  # noqa: E402
from omada_mcp.tools import TOOL_MAP, normalize_mac, project_wlan  # noqa: E402

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


class FakeController:
    """Minimal stateful stand-in for the controller's Web API v2."""

    def __init__(self, username="admin", password="pw", sites=None, devices=None,
                 clients=None, wlans=None, token="tok-abc123"):
        self.username = username
        self.password = password
        self.token = token
        self.sites = sites if sites is not None else [{"id": SITE_ID, "name": "Test Site"}]
        self.devices = devices if devices is not None else DEVICES
        self.clients = clients if clients is not None else CLIENTS
        self.wlans = wlans if wlans is not None else WLANS
        self.requests = []
        self.logins = 0
        self.html_once_for = set()   # endpoint fragments answered with HTML exactly once
        self.html_always_for = set()  # fragments answered with HTML every time
        self.burst_once_for = set()  # endpoint fragments answered with -1600 once

    # transport protocol
    def request(self, method, url, headers=None, data=None, timeout=None):
        self.requests.append({"method": method, "url": url,
                              "headers": dict(headers or {}), "body": data})
        path = url.split("?")[0]
        if path.endswith("/api/info"):
            return 200, json.dumps({
                "errorCode": 0,
                "result": {"omadacId": CONTROLLER_ID, "controllerVer": "5.13.30.8"},
            }).encode()
        if path.endswith("/api/v2/login"):
            self.logins += 1
            payload = json.loads(data or b"{}")
            if payload.get("username") != self.username or payload.get("password") != self.password:
                return 200, json.dumps({"errorCode": -30109, "msg": "wrong credentials"}).encode()
            return 200, json.dumps({"errorCode": 0, "result": {"token": self.token}}).encode()

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
        if fragment.startswith(site_prefix + "/setting/wlans"):
            return 200, json.dumps({"errorCode": 0, "result": {"data": self.wlans}}).encode()
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
        self.assertEqual(len(tools), 8)
        self.assertEqual({t["name"] for t in tools},
                         {"list_devices", "list_clients", "list_wifi_clients",
                          "list_wired_clients", "get_device", "get_client",
                          "list_wlans", "get_site_info"})
        for tool in tools:
            annotations = tool["annotations"]
            self.assertIs(annotations["readOnlyHint"], True, tool["name"])
            self.assertIs(annotations["destructiveHint"], False, tool["name"])
            self.assertIs(annotations["idempotentHint"], True, tool["name"])
            self.assertIs(annotations["openWorldHint"], True, tool["name"])
            self.assertEqual(tool["inputSchema"]["type"], "object")

    def test_read_only_mode_refuses_non_read_only_names(self):
        server, _, _ = self._server(read_only=True)
        response = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "set_client_fixed_ip"}})
        self.assertEqual(response["error"]["code"], -32003)
        self.assertIn("OMADA_READ_ONLY", response["error"]["message"])

    def test_unknown_tool_is_reported_when_writes_are_allowed(self):
        server, _, _ = self._server(read_only=False)
        response = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "set_client_fixed_ip"}})
        self.assertEqual(response["error"]["code"], -32601)

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

    def test_serve_loop_writes_one_line_per_response(self):
        server, _, _ = self._server()
        stdin = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
                            '{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        stdout = io.StringIO()
        self.assertEqual(server.serve(stdin=stdin, stdout=stdout), 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["result"]["serverInfo"]["name"], "omada-mcp")


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
        from omada_mcp.cli import main

        buffer = io.StringIO()
        original = sys.stdout
        sys.stdout = buffer
        try:
            self.assertEqual(main(["--list-tools"]), 0)
        finally:
            sys.stdout = original
        payload = json.loads(buffer.getvalue())
        self.assertEqual(len(payload["tools"]), 8)

    def test_missing_config_exits_non_zero(self):
        from omada_mcp.cli import main

        tmp = tempfile.mkdtemp()
        original_cwd = os.getcwd()
        environ_backup = dict(os.environ)
        for key in list(os.environ):
            if key.startswith("OMADA_"):
                del os.environ[key]
        stderr = io.StringIO()
        original = sys.stderr
        sys.stderr = stderr
        try:
            os.chdir(tmp)
            code = main([])
        finally:
            os.chdir(original_cwd)
            sys.stderr = original
            os.environ.clear()
            os.environ.update(environ_backup)
        self.assertEqual(code, 2)
        self.assertIn("omada-mcp --doctor", stderr.getvalue())

    def test_normalize_mac_variants(self):
        self.assertEqual(normalize_mac("AABBCCDDEEFF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("aa-bb-cc-dd-ee-ff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("not-a-mac"), "not-a-mac")


if __name__ == "__main__":
    unittest.main()
