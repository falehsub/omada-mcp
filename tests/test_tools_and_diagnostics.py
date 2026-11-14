"""Read tool projection, v1.1 filters, and Milestone 1 diagnostic tests."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fake_controller import (  # noqa: E402
    CLIENTS,
    CONTROLLER_ID,
    DEVICES,
    FakeController,
    make_client,
    make_config,
)

from omada_mcp import config as config_module  # noqa: E402
from omada_mcp.client import (  # noqa: E402
    OmadaClient,
    build_ssl_context,
    classify_controller_family,
    describe_error,
    explain_error_code,
)
from omada_mcp.config import (  # noqa: E402
    ConfigError,
    load_config,
)
from omada_mcp.doctor import run_doctor  # noqa: E402
from omada_mcp.server import Server  # noqa: E402
from omada_mcp.tools import (  # noqa: E402
    _findings_healthy,
    project_wlan,
)


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
        # Even if the host machine has ~/.config/omada-mcp/.env, passing
        # an isolated environ={} must not discover it.
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch("pathlib.Path.home", return_value=Path(tmp)),
        ):
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

