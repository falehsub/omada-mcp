"""Web API v2 client, JSON-RPC stdio protocol, source, and write-schema tests."""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fake_controller import (  # noqa: E402
    CONTROLLER_ID,
    SITE_ID,
    FakeController,
    make_client,
    make_config,
)

from omada_mcp import __version__  # noqa: E402
from omada_mcp.client import (  # noqa: E402
    BURST_BACKOFF_SECONDS,
    OmadaClient,
    OmadaError,
    build_ssl_context,
    describe_error,
)
from omada_mcp.server import Server  # noqa: E402
from omada_mcp.tools import (  # noqa: E402
    TOOL_MAP,
)


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

