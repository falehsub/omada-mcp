"""Monitor, watch/metrics export, packaging, and context-optimization tests."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fake_controller import (  # noqa: E402
    make_config,
)

from omada_mcp.cli import main as cli_main  # noqa: E402
from omada_mcp.client import (  # noqa: E402
    BURST_BACKOFF_SECONDS,
    OmadaClient,
    OmadaError,
    build_ssl_context,
)
from omada_mcp.config import (  # noqa: E402
    Config,
    ConfigError,
    load_config,
)
from omada_mcp.monitor import (  # noqa: E402
    MIN_POLL_INTERVAL_SECONDS,
    export_metrics_once,
    run_watch,
    serve_metrics_http,
)
from omada_mcp.server import Server  # noqa: E402
from omada_mcp.tools import (  # noqa: E402
    TOOL_MAP,
)


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
        from omada_mcp.tools import TOOLS, tool_descriptors

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

        def sz(obj):
            return len(json.dumps({"tools": obj}, separators=(",", ":"), ensure_ascii=False))
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
        }, clear=True), self.assertRaises(ConfigError):
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

    def test_adaptive_pacing_gateway_fastpath_and_schema_bounds(self):
        from mock_controller import MockController

        from omada_mcp.config import DEFAULT_MIN_INTERVAL
        from omada_mcp.write_tools import _parse_ssid_security

        self.assertEqual(DEFAULT_MIN_INTERVAL, 0.05)

        # 1. Adaptive pacing steps up from 0.05s to 0.25s when a GET encounters -1600
        ctrl = MockController(username="admin", password="pw", role="Administrator")
        sleeps = []
        now = [100.0]

        def clock_fn():
            return now[0]

        def sleep_fn(sec):
            sleeps.append(round(sec, 3))
            now[0] += sec

        cfg = make_config(username="admin", read_only=False, min_interval=0.05)
        object.__setattr__(cfg, "write_tools", ("create_ssid", "create_lan_network"))
        client = OmadaClient(cfg, transport=ctrl, sleep=sleep_fn, clock=clock_fn, log_fn=lambda _: None)
        client.authenticate()
        sleeps.clear()
        ctrl.burst_once_for.add(("GET", "setting/upnp"))
        client.api_result(f"sites/{client.site.site_id}/setting/upnp")
        self.assertEqual(client._adaptive_min_interval, 0.25)
        client.api_result(f"sites/{client.site.site_id}/setting/upnp")
        self.assertIn(0.25, sleeps)

        # 2. Gateway-absent fast-path skips live tunnel stat probes
        ctrl.has_gateway = False
        ctrl.devices = [d for d in ctrl.devices if d["type"] != "gateway"]
        ctrl.requests.clear()
        srv = Server(cfg, client=client)
        dw = srv.handle({
            "jsonrpc": "2.0", "id": 20, "method": "tools/call",
            "params": {"name": "diagnose_wan", "arguments": {}},
        })["result"]["structuredContent"]
        self.assertFalse(dw["wan"]["hasGateway"])
        paths = [r["path"] for r in ctrl.requests]
        self.assertFalse(any("stats/vpn" in p or "dashboard/vpnTunnelStats" in p for p in paths))

        # 3. Schema bounds (minimum/maximum/enum) enforced with -32602
        bad_min = srv.handle({
            "jsonrpc": "2.0", "id": 21, "method": "tools/call",
            "params": {"name": "create_lan_network", "arguments": {"name": "BadVlan", "vlan": 0}},
        })
        self.assertEqual(bad_min["error"]["code"], -32602)

        bad_max = srv.handle({
            "jsonrpc": "2.0", "id": 22, "method": "tools/call",
            "params": {"name": "create_lan_network", "arguments": {"name": "BadVlan", "vlan": 5000}},
        })
        self.assertEqual(bad_max["error"]["code"], -32602)

        bad_enum = srv.handle({
            "jsonrpc": "2.0", "id": 23, "method": "tools/call",
            "params": {"name": "create_ssid", "arguments": {"name": "BadSec", "security": "wep-broken"}},
        })
        self.assertEqual(bad_enum["error"]["code"], -32602)

        # 4. _parse_ssid_security checks security mode before psk length
        with self.assertRaises(OmadaError) as ctx:
            _parse_ssid_security("wep-broken", None)
        self.assertIn("unsupported SSID security", str(ctx.exception))

    def test_logs_hours_zero_uses_time_start_one(self):
        from mock_controller import MockController

        ctrl = MockController(username="admin", password="pw", role="Administrator")
        cfg = make_config(username="admin", read_only=True, min_interval=0.0)
        client = OmadaClient(cfg, transport=ctrl, sleep=lambda _s: None, clock=lambda: 0.0, log_fn=lambda _m: None)
        client.authenticate()
        srv = Server(cfg, client=client)

        for cat in ("alerts", "events"):
            ctrl.requests.clear()
            res = srv.handle({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "list_logs", "arguments": {"category": cat, "hours": 0}},
            })["result"]["structuredContent"]
            self.assertGreaterEqual(res["count"], 1, cat)
            log_req = next(r for r in ctrl.requests if f"logs/{cat}" in r["path"])
            self.assertIn("filters.timeStart=1&", log_req["query"])
            self.assertNotIn("filters.timeStart=0&", log_req["query"])

        # Verify MockController reproduces Omada 6.2 behavior when timeStart=0&timeEnd=0 is sent.
        raw_zero = client.api_result(
            f"sites/{client.site.site_id}/logs/events?filters.timeStart=0&filters.timeEnd=0"
        )
        self.assertEqual(raw_zero["totalRows"], 0)
        self.assertEqual(raw_zero["data"], [])

    def test_double_1600_negative_cache_ttl_and_bypass(self):
        from mock_controller import MockController

        ctrl = MockController(username="admin", password="pw", role="Administrator")
        now = [100.0]
        sleeps = []
        cfg = make_config(username="admin", read_only=True, min_interval=0.0)
        client = OmadaClient(
            cfg,
            transport=ctrl,
            sleep=lambda s: (sleeps.append(s), now.__setitem__(0, now[0] + s)),
            clock=lambda: now[0],
            log_fn=lambda _m: None,
        )
        client.authenticate()
        ctrl.requests.clear()
        sleeps.clear()

        ep = f"sites/{client.site.site_id}/cmd/getSpeedTestResult"
        first = client.api(ep)
        self.assertEqual(first["errorCode"], -1600)
        self.assertEqual(len(ctrl.requests), 2)  # initial + 1 burst retry
        self.assertEqual(sleeps, [BURST_BACKOFF_SECONDS])

        # Within TTL (<300s), repeated probes hit the negative cache without HTTP or sleep.
        ctrl.requests.clear()
        sleeps.clear()
        second = client.api(ep)
        self.assertEqual(second["errorCode"], -1600)
        self.assertEqual(len(ctrl.requests), 0)
        self.assertEqual(sleeps, [])

        # Explicit uncached read and write-verification bypass ignore the negative cache.
        uncached = client.api(ep, use_cache=False)
        self.assertEqual(uncached["errorCode"], -1600)
        self.assertEqual(len(ctrl.requests), 2)

        ctrl.requests.clear()
        client._cache_bypass_depth += 1
        try:
            bypassed = client.api(ep)
        finally:
            client._cache_bypass_depth -= 1
        self.assertEqual(bypassed["errorCode"], -1600)
        self.assertEqual(len(ctrl.requests), 2)

        # Past TTL (>=300s), negative cache expires and re-probes.
        now[0] += 301.0
        ctrl.requests.clear()
        sleeps.clear()
        expired = client.api(ep)
        self.assertEqual(expired["errorCode"], -1600)
        self.assertEqual(len(ctrl.requests), 2)

        # Any mutation invalidates the negative cache immediately.
        ctrl.requests.clear()
        client._negative_cache[(client.controller_id or "", ep)] = (now[0], {"errorCode": -1600})
        client.api(f"sites/{client.site.site_id}/setting/upnp", method="PATCH", data={"enable": False})
        self.assertNotIn((client.controller_id or "", ep), client._negative_cache)

    def test_ap_radios_per_band_client_count_and_viewer_honesty(self):
        from mock_controller import MockController

        ctrl = MockController(username="admin", password="pw", role="Administrator")
        ctrl.clients["AA-BB-CC-11-11-02"].update({
            "wireless": True, "apMac": "AA-BB-CC-00-00-03", "apName": "ap-living", "radioId": 1,
        })
        ctrl.clients["AA-BB-CC-11-11-03"] = {
            "mac": "AA-BB-CC-11-11-03", "name": "iot-plug", "hostName": "iot-plug",
            "ip": "192.168.20.99", "wireless": True, "active": True, "ssid": "LabWiFi",
            "apMac": "AA-BB-CC-00-00-03", "apName": "ap-living", "radioId": 0,
            "networkName": "IoT", "vid": 20, "signalLevel": 75, "rssi": -60,
        }
        cfg = make_config(username="admin", read_only=True, min_interval=0.0)
        client = OmadaClient(cfg, transport=ctrl, sleep=lambda _s: None, clock=lambda: 0.0, log_fn=lambda _m: None)
        client.authenticate()
        srv = Server(cfg, client=client)

        res = srv.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "get_ap_radios", "arguments": {"mac": "AA-BB-CC-00-00-03"}},
        })["result"]["structuredContent"]
        by_band = {r["band"]: r for r in res["radios"]}
        self.assertEqual(by_band["2g"]["clientCount"], 1)
        self.assertEqual(by_band["5g"]["clientCount"], 1)

        # Viewer fallback: insight/clients on 6.2.10.x strips radioId/apName; return None honestly.
        ctrl_v = MockController(username="viewer", password="pw", role="Viewer")
        ctrl_v.clients["AA-BB-CC-11-11-02"].update({"wireless": True})
        cfg_v = make_config(username="viewer", read_only=True, min_interval=0.0)
        client_v = OmadaClient(cfg_v, transport=ctrl_v, sleep=lambda _s: None, clock=lambda: 0.0, log_fn=lambda _m: None)
        client_v.authenticate()
        srv_v = Server(cfg_v, client=client_v)
        res_v = srv_v.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_ap_radios", "arguments": {"mac": "AA-BB-CC-00-00-03"}},
        })["result"]["structuredContent"]
        for r in res_v["radios"]:
            self.assertIsNone(r["clientCount"])

    def test_client_projection_preserves_extended_telemetry(self):
        from mock_controller import MockController

        ctrl = MockController(username="admin", password="pw", role="Administrator")
        ctrl.clients["AA-BB-CC-11-11-02"].update({
            "wireless": True, "rssi": -62, "signalLevel": 68, "snr": 31,
            "txRate": 866700, "rxRate": 780000, "uptime": 3600,
            "connectType": "wifi5", "radioId": 1, "channel": 100,
        })
        cfg = make_config(username="admin", read_only=True, min_interval=0.0)
        client = OmadaClient(cfg, transport=ctrl, sleep=lambda _s: None, clock=lambda: 0.0, log_fn=lambda _m: None)
        client.authenticate()
        srv = Server(cfg, client=client)

        got = srv.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "get_client", "arguments": {"mac": "AA-BB-CC-11-11-02"}},
        })["result"]["structuredContent"]
        self.assertEqual(got["rssi"], -62)
        self.assertEqual(got["signalLevel"], 68)
        self.assertEqual(got["snr"], 31)
        self.assertEqual(got["txRate"], 866700)
        self.assertEqual(got["rxRate"], 780000)
        self.assertEqual(got["uptime"], 3600)
        self.assertEqual(got["connectType"], "wifi5")
        self.assertEqual(got["radioId"], 1)
        self.assertEqual(got["channel"], 100)

