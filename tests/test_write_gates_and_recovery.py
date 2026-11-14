"""Write config, CIDR packing, protocol fail-closed gates, recovery, and snapshot tests."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SRC = ROOT / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from mock_controller import MockController, MockControllerHTTPServer  # noqa: E402
from write_harness import call_tool, make_write_config, make_write_env, unwrap_ok  # noqa: E402

from omada_mcp import config as config_mod  # noqa: E402
from omada_mcp.client import (  # noqa: E402
    ERROR_CATALOG,
    OmadaClient,
    OmadaError,
    explain_error_code,
)
from omada_mcp.config import (  # noqa: E402
    WRITE_TOOL_NAMES,
    ConfigError,
    default_snapshot_dir,
    load_config,
    parse_management_cidrs,
    parse_write_tools,
)
from omada_mcp.doctor import run_doctor  # noqa: E402
from omada_mcp.server import Server  # noqa: E402
from omada_mcp.tools import TOOL_MAP, TOOLS, tool_descriptors  # noqa: E402
from omada_mcp.write_tools import (  # noqa: E402
    pack_ip_entries,
)


class WriteConfigTests(unittest.TestCase):
    def test_tool_name_sets_match_tools_module(self):
        ro_names = {t.name for t in TOOLS if t.read_only}
        wr_names = {t.name for t in TOOLS if not t.read_only}
        self.assertEqual(len(ro_names), 33)
        self.assertEqual(len(wr_names), 47)
        self.assertEqual(config_mod._READ_ONLY_TOOL_NAMES, ro_names)
        self.assertEqual(set(WRITE_TOOL_NAMES), wr_names)
        self.assertEqual(len(TOOLS), 80)

    def test_parse_write_tools_validation(self):
        self.assertEqual(parse_write_tools(None), ())
        self.assertEqual(parse_write_tools("  "), ())
        self.assertEqual(
            parse_write_tools("set_client_fixed_ip, release_client_fixed_ip, set_client_fixed_ip"),
            ("set_client_fixed_ip", "release_client_fixed_ip"),
        )
        for bad in ("*", "set_*", "all", "ALL", "set_client_fixed_ip, ", "list_devices", "get_config_snapshot", "bogus_tool"):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                parse_write_tools(bad)

    def test_snapshot_dir_and_management_cidrs(self):
        self.assertEqual(parse_management_cidrs(""), ())
        self.assertEqual(
            parse_management_cidrs("192.168.10.50, 10.99.5.42/24"),
            ("192.168.10.50/32", "10.99.5.0/24"),
        )
        with self.assertRaises(ConfigError):
            parse_management_cidrs("not-an-ip")

        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(
                environ={
                    "OMADA_BASE_URL": "https://192.168.10.10:8043",
                    "OMADA_USERNAME": "admin-writer",
                    "OMADA_PASSWORD": "pw",
                    "OMADA_WRITE_TOOLS": "set_client_fixed_ip",
                    "OMADA_SNAPSHOT_DIR": tmp,
                    "OMADA_WRITE_INTERVAL_SECONDS": "2.5",
                    "OMADA_MANAGEMENT_CIDRS": "192.168.10.50",
                },
                cwd=Path(tmp),
            )
            self.assertEqual(cfg.write_tools, ("set_client_fixed_ip",))
            self.assertEqual(cfg.snapshot_dir, Path(tmp))
            self.assertEqual(cfg.snapshot_origin, "OMADA_SNAPSHOT_DIR")
            self.assertEqual(cfg.write_min_interval, 2.5)
            self.assertEqual(cfg.management_cidrs, ("192.168.10.50/32",))
            masked = cfg.masked()
            self.assertEqual(masked["password"], "set (2 chars)")
            self.assertEqual(masked["write_tools"], ["set_client_fixed_ip"])
            self.assertEqual(masked["management_cidrs"], ["192.168.10.50/32"])

        with mock.patch.object(config_mod, "_IS_WINDOWS", False):
            posix_snap = default_snapshot_dir({"XDG_STATE_HOME": "/tmp/xdg-state"})
            self.assertEqual(posix_snap, Path("/tmp/xdg-state/omada-mcp/snapshots"))
        with mock.patch.object(config_mod, "_IS_WINDOWS", True):
            win_snap = default_snapshot_dir({"LOCALAPPDATA": r"C:\Users\demo\AppData\Local"})
            self.assertEqual(win_snap, Path(r"C:\Users\demo\AppData\Local") / "omada-mcp" / "snapshots")
        isolated_snap = default_snapshot_dir({})
        self.assertEqual(isolated_snap.name, "snapshots")


class PackIpEntriesTests(unittest.TestCase):
    def test_pack_range_and_cidrs(self):
        packed = pack_ip_entries(ip_range="192.168.20.180-199")
        self.assertEqual(
            packed,
            [
                {"ip": "192.168.20.180", "mask": 30, "description": ""},
                {"ip": "192.168.20.184", "mask": 29, "description": ""},
                {"ip": "192.168.20.192", "mask": 29, "description": ""},
            ],
        )

    def test_pack_enforces_16_entry_limit_with_minus_33726(self):
        seventeen = [f"192.168.50.{i * 2}/32" for i in range(1, 18)]
        with self.assertRaises(OmadaError) as ctx:
            pack_ip_entries(cidrs=seventeen)
        self.assertEqual(ctx.exception.code, -33726)

    def test_error_catalog_includes_33717_and_41011(self):
        self.assertIn(-33717, ERROR_CATALOG)
        info = explain_error_code(-33717)
        self.assertTrue(info["known"])
        self.assertIn("ACL", info["meaning"])
        info_perm = explain_error_code(-41011)
        self.assertIn("device", info_perm["meaning"].lower())

    def test_error_catalog_includes_v62_real_controller_codes(self):
        for code in (-1007, -33598, -33601):
            self.assertIn(code, ERROR_CATALOG)
            info = explain_error_code(code)
            self.assertTrue(info["known"])
        self.assertIn("viewer", explain_error_code(-1007)["meaning"].lower())
        self.assertIn("isolation", explain_error_code(-33598)["meaning"].lower())
        self.assertIn("destination", explain_error_code(-33601)["meaning"].lower())


class GateAndProtocolTests(unittest.TestCase):
    def test_read_only_gate_refuses_before_arg_validation_and_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True, write_tools=WRITE_TOOL_NAMES)
            # Missing required arguments on purpose: gate must fire first (-32003, not -32602).
            resp = call_tool(server, "set_client_fixed_ip", {})
            self.assertEqual(resp["error"]["code"], -32003)
            self.assertEqual(ctrl.requests, [])
            self.assertEqual(tool_descriptors(server.config), tool_descriptors())

    def test_empty_allowlist_refuses_before_arg_validation_and_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=False, write_tools=())
            resp = call_tool(server, "set_acl_rule_status", {})
            self.assertEqual(resp["error"]["code"], -32003)
            self.assertIn("OMADA_WRITE_TOOLS", resp["error"]["message"])
            self.assertEqual(ctrl.requests, [])

    def test_partial_allowlist_and_strict_argument_checking(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(
                tmp, read_only=False, write_tools=("set_client_fixed_ip",)
            )
            listed = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
            self.assertEqual(len(listed), 34)
            names = {t["name"] for t in listed}
            self.assertIn("set_client_fixed_ip", names)
            self.assertNotIn("release_client_fixed_ip", names)

            # Un-allowlisted write tool refused before transport
            blocked = call_tool(server, "release_client_fixed_ip", {"mac": "AA-BB-CC-11-11-01"})
            self.assertEqual(blocked["error"]["code"], -32003)
            self.assertEqual(ctrl.requests, [])

            # Unexpected snake_case argument gets camelCase hint
            bad_key = call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.55",
                "dry_run": False,
            })
            self.assertEqual(bad_key["error"]["code"], -32602)
            self.assertIn("dryRun", bad_key["error"]["data"]["hint"])

            # String "false" for boolean dryRun must fail with -32602 (never coerced to bool("false")==True)
            bad_bool = call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.55",
                "dryRun": "false",
            })
            self.assertEqual(bad_bool["error"]["code"], -32602)

            # dryRun=False without confirm refuses before auth/transport
            no_confirm = call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.55",
                "dryRun": False,
            })
            self.assertEqual(no_confirm["error"]["code"], -32602)
            self.assertEqual(ctrl.requests, [])

            # Wrong confirm fails in-band WITHOUT leaking expected target-id
            wrong_confirm = call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.55",
                "dryRun": False,
                "confirm": "set_client_fixed_ip:wrong-target",
            })
            self.assertTrue(wrong_confirm["result"]["isError"])
            err_text = wrong_confirm["result"]["content"][0]["text"]
            self.assertNotIn("aa:bb:cc:11:11:01", err_text.lower())
            self.assertEqual(ctrl.write_request_count, 0)

    def test_write_annotations_match_safety_tiers(self):
        expected = {
            "get_config_snapshot": (True, False, True),
            "search_clients": (True, False, True),
            "list_lan_networks": (True, False, True),
            "list_dhcp_reservations": (True, False, True),
            "list_acls": (True, False, True),
            "list_ip_groups": (True, False, True),
            "list_port_forwards": (True, False, True),
            "list_static_routes": (True, False, True),
            "get_network_services": (True, False, True),
            "list_logs": (True, False, True),
            "get_switch_ports": (True, False, True),
            "get_ap_radios": (True, False, True),
            "get_rf_scan": (True, False, True),
            "get_wan_status": (True, False, True),
            "list_vpn_tunnels": (True, False, True),
            "get_topology": (True, False, True),
            "get_security_status": (True, False, True),
            "diagnose_client": (True, False, True),
            "diagnose_wan": (True, False, True),
            "list_port_profiles": (True, False, True),
            "list_wlan_groups": (True, False, True),
            "list_policy_routes": (True, False, True),
            "list_lan_dns_rules": (True, False, True),
            "set_client_fixed_ip": (False, False, True),
            "release_client_fixed_ip": (False, False, True),
            "create_ip_group": (False, False, False),
            "set_vlan_dhcp_pools": (False, True, True),
            "set_vlan_isolation": (False, True, True),
            "replace_ip_group": (False, True, False),
            "create_gateway_acl": (False, True, False),
            "set_acl_rule_status": (False, True, True),
            "upsert_dhcp_reservation": (False, False, True),
            "delete_dhcp_reservation": (False, True, True),
            "create_lan_network": (False, False, False),
            "update_lan_network": (False, True, True),
            "delete_lan_network": (False, True, True),
            "update_gateway_acl": (False, True, True),
            "delete_gateway_acl": (False, True, True),
            "delete_ip_group": (False, True, True),
            "create_ssid": (False, False, False),
            "update_ssid": (False, True, True),
            "delete_ssid": (False, True, True),
            "upsert_port_forward": (False, True, True),
            "delete_port_forward": (False, True, True),
            "upsert_static_route": (False, True, True),
            "delete_static_route": (False, True, True),
            "upsert_mdns_rule": (False, False, True),
            "delete_mdns_rule": (False, True, True),
            "set_upnp": (False, True, True),
            "set_client_blocked": (False, True, True),
            "reconnect_client": (False, False, False),
            "update_client": (False, False, True),
            "update_device": (False, False, True),
            "reboot_device": (False, True, False),
            "rollback_from_snapshot": (False, True, False),
            "update_switch_port": (False, False, True),
            "cycle_poe_port": (False, True, False),
            "upsert_port_profile": (False, False, True),
            "delete_port_profile": (False, True, True),
            "update_ap_radio": (False, False, True),
            "start_rf_scan": (False, True, False),
            "assign_ap_wlan_group": (False, False, True),
            "upsert_policy_route": (False, False, True),
            "delete_policy_route": (False, True, True),
            "upsert_lan_dns_rule": (False, False, True),
            "delete_lan_dns_rule": (False, True, True),
            "create_switch_acl": (False, False, False),
            "create_eap_acl": (False, False, False),
            "set_client_lock_to_ap": (False, False, True),
            "set_client_rate_limit": (False, False, True),
        }
        for name, (ro, dest, idemp) in expected.items():
            t = TOOL_MAP[name]
            self.assertEqual((t.read_only, t.destructive, t.idempotent), (ro, dest, idemp), name)
        self.assertEqual(set(TOOL_MAP) - set(expected), {
            "list_devices", "list_clients", "list_wifi_clients", "list_wired_clients",
            "get_device", "get_client", "list_wlans", "get_site_info",
            "network_audit", "explain_error",
        })


class WriteClientAndRecoveryTests(unittest.TestCase):
    def test_client_write_gate_pacing_snapshot_and_audit_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, ctrl, sleeps = make_write_env(tmp, write_min_interval=1.25)

            # Direct Python client gate rejects non-allowlisted tool
            cfg_ro = make_write_config(tmp_dir=tmp, read_only=True)
            c_ro = OmadaClient(cfg_ro, transport=ctrl, sleep=sleeps.append, clock=lambda: 0.0, log_fn=lambda _: None)
            with self.assertRaises(OmadaError):
                c_ro.write(
                    "sites/s1/clients/AA-BB-CC-11-11-01",
                    method="PATCH",
                    data={},
                    tool_name="set_client_fixed_ip",
                    target="aa:bb:cc:11:11:01",
                )

            # Apply two sequential writes and verify pacing + snapshots + audit.jsonl
            r1 = unwrap_ok(call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.55",
                "dryRun": False,
                "confirm": "set_client_fixed_ip:aa:bb:cc:11:11:01",
            }))
            self.assertTrue(r1["applied"])
            snap1 = Path(tmp) / r1["snapshot"]
            self.assertTrue(snap1.exists())

            r2 = unwrap_ok(call_tool(server, "release_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "dryRun": False,
                "confirm": "release_client_fixed_ip:aa:bb:cc:11:11:01",
            }))
            self.assertTrue(r2["applied"])
            self.assertIn(1.25, sleeps)

            audit_path = Path(tmp) / "audit.jsonl"
            self.assertTrue(audit_path.exists())
            records = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual([rec["tool"] for rec in records], ["set_client_fixed_ip", "release_client_fixed_ip"])
            self.assertTrue(all(rec["verified"] for rec in records))
            self.assertTrue(all(rec["result"] == "success" for rec in records))
            self.assertTrue(all(rec["account"] == "admin-writer" for rec in records))
            self.assertTrue(all(rec["snapshot"] for rec in records))

            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(Path(tmp).stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(snap1.stat().st_mode), 0o600)

    def test_html_on_200_non_get_skips_duplicate_write_if_already_applied(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            applied_then_html = [False]
            orig_request = ctrl.request

            def wrapped_request(method, url, headers=None, data=None, timeout=None):
                if method == "PATCH" and "/clients/" in url and not applied_then_html[0]:
                    applied_then_html[0] = True
                    payload = json.loads(data.decode("utf-8"))
                    ctrl.requests.append({
                        "method": method, "url": url, "path": url, "query": "",
                        "headers": headers or {}, "body": payload,
                    })
                    ctrl.clients["AA-BB-CC-11-11-01"]["ipSetting"] = dict(payload["ipSetting"])
                    ctrl.cookie_jar.clear()
                    return 200, b"<!DOCTYPE html><html>Login</html>"
                return orig_request(method, url, headers=headers, data=data, timeout=timeout)

            _client._transport = type("_T", (), {"request": staticmethod(wrapped_request), "cookie_jar": ctrl.cookie_jar})()
            res = unwrap_ok(call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.57",
                "dryRun": False,
                "confirm": "set_client_fixed_ip:aa:bb:cc:11:11:01",
            }))
            self.assertTrue(res["applied"])
            # Only ONE PATCH hit the controller because reauth_prepare saw desired ipSetting already active
            self.assertEqual(ctrl.write_request_count, 1)

    def test_html_on_200_non_get_reauths_and_checks_state_without_blind_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Simulate session expiry right on PATCH clients/
            ctrl.html_once_for.add(("PATCH", "clients/"))
            res = unwrap_ok(call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.55",
                "dryRun": False,
                "confirm": "set_client_fixed_ip:aa:bb:cc:11:11:01",
            }))
            self.assertTrue(res["applied"])
            self.assertGreaterEqual(ctrl.logins, 2)

    def test_burst_1600_is_never_retried_on_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.burst_once_for.add(("PATCH", "clients/"))
            resp = call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.55",
                "dryRun": False,
                "confirm": "set_client_fixed_ip:aa:bb:cc:11:11:01",
            })
            self.assertTrue(resp["result"]["isError"])
            self.assertIn("-1600", resp["result"]["content"][0]["text"])
            # Exactly one PATCH attempt — write must never auto-retry on -1600.
            self.assertEqual(ctrl.write_request_count, 1)


class SnapshotAndDoctorTests(unittest.TestCase):
    def test_get_config_snapshot_merges_two_endpoints_and_redacts_wlans(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True)
            snap = unwrap_ok(call_tool(server, "get_config_snapshot", {}))
            self.assertEqual(snap["objects"], ["networks", "acls", "groups", "wlans", "devices"])
            self.assertNotIn("clients", snap)
            self.assertFalse(snap["acls"]["aclDisableReliable"])
            self.assertTrue(snap["acls"]["aclDisable"])
            self.assertEqual(len(snap["groups"]["ipGroups"]), 2)
            self.assertEqual(len(snap["groups"]["otherGroups"]), 1)
            self.assertEqual(len(snap["networks"]), 4)
            guest = next(n for n in snap["networks"] if n["id"] == "net-guest-30")
            self.assertIs(guest["accessControlRule"], False)
            self.assertTrue(guest["dhcpSettings"]["ipRangePool"])
            dumped = json.dumps(snap)
            self.assertNotIn("synthetic-test-passphrase-never-leak", dumped)
            self.assertNotIn("synthetic-guest-secret-never-leak", dumped)

            # Optional clients slice
            snap_clients = unwrap_ok(call_tool(server, "get_config_snapshot", {
                "objects": ["clients"],
            }))
            self.assertEqual(len(snap_clients["clients"]), 3)
            self.assertEqual(ctrl.write_request_count, 0)

    def test_doctor_write_phase_pass_and_viewer_warn_with_zero_writes(self):
        import io

        schema = json.loads((ROOT / "schemas" / "doctor.schema.json").read_text(encoding="utf-8"))
        allowed_phases = set(schema["properties"]["phases"]["items"]["properties"]["name"]["enum"])

        with tempfile.TemporaryDirectory() as tmp:
            secret_dir = str(Path(tmp) / "private-snap-vault")
            ctrl_admin = MockController(role="Administrator")
            cfg_admin = make_write_config(
                tmp_dir=secret_dir,
                read_only=False,
                write_tools=("set_client_fixed_ip",),
            )
            client_admin = OmadaClient(cfg_admin, transport=ctrl_admin, sleep=lambda _: None,
                                       clock=lambda: 0.0, log_fn=lambda _: None)
            stream = io.StringIO()
            rc = run_doctor(
                config_factory=lambda: cfg_admin,
                client_factory=lambda _c: client_admin,
                stream=stream,
                json_output=True,
            )
            self.assertEqual(rc, 0)
            self.assertEqual(ctrl_admin.write_request_count, 0)
            doc = json.loads(stream.getvalue())
            self.assertNotIn("private-snap-vault", stream.getvalue())
            write_phase = next(p for p in doc["phases"] if p["name"] == "write")
            self.assertEqual(write_phase["status"], "PASS")
            self.assertIn("OMADA_SNAPSHOT_DIR", write_phase["detail"])
            self.assertTrue({p["name"] for p in doc["phases"]}.issubset(allowed_phases))

            # Viewer role with write tools enabled emits WARN
            ctrl_viewer = MockController(username="admin-writer", role="Viewer")
            cfg_viewer = make_write_config(
                tmp_dir=secret_dir,
                read_only=False,
                write_tools=("set_client_fixed_ip",),
            )
            client_viewer = OmadaClient(cfg_viewer, transport=ctrl_viewer, sleep=lambda _: None,
                                        clock=lambda: 0.0, log_fn=lambda _: None)
            stream_v = io.StringIO()
            rc_v = run_doctor(
                config_factory=lambda: cfg_viewer,
                client_factory=lambda _c: client_viewer,
                stream=stream_v,
                json_output=True,
            )
            self.assertEqual(rc_v, 0)
            self.assertEqual(ctrl_viewer.write_request_count, 0)
            doc_v = json.loads(stream_v.getvalue())
            write_phase_v = next(p for p in doc_v["phases"] if p["name"] == "write")
            self.assertEqual(write_phase_v["status"], "WARN")
            self.assertIn("-1007", write_phase_v["detail"])
            self.assertIn("-41011", write_phase_v["detail"])

    def test_viewer_write_returns_minus_1007(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.role = "Viewer"
            resp = call_tool(server, "create_ip_group", {
                "name": "viewer-denied",
                "cidrs": ["192.168.20.200/32"],
                "dryRun": False,
                "confirm": "create_ip_group:viewer-denied",
            })
            self.assertTrue(resp["result"]["isError"])
            self.assertIn("-1007", resp["result"]["content"][0]["text"])

    def test_create_gateway_acl_rejects_network_dest_on_lan_to_wan_and_uses_put(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            bad = call_tool(server, "create_gateway_acl", {
                "name": "invalid-wan-dest",
                "policy": "deny",
                "source": {"type": "ip_group", "ids": ["lab-devices"]},
                "destination": {"type": "network", "ids": ["Default"]},
                "direction": {"lanToWan": True, "lanToLan": False},
            })
            self.assertTrue(bad["result"]["isError"])
            self.assertIn("-33601", bad["result"]["content"][0]["text"])
            self.assertEqual(ctrl.write_request_count, 0)

            created_grp = unwrap_ok(call_tool(server, "create_ip_group", {
                "name": "v62-group-id-only",
                "cidrs": ["192.168.20.210/32"],
                "dryRun": False,
                "confirm": "create_ip_group:v62-group-id-only",
            }))
            gid = created_grp["after"]["groupId"]
            self.assertEqual(created_grp["after"]["id"], gid)

            toggled = unwrap_ok(call_tool(server, "set_acl_rule_status", {
                "rule": "acl-002",
                "status": False,
                "dryRun": False,
                "confirm": "set_acl_rule_status:acl-002",
            }))
            self.assertTrue(toggled["applied"])
            self.assertIs(toggled["after"]["status"], False)
            acl_writes = [r for r in ctrl.requests if "setting/firewall/acls/acl-002" in r["path"]]
            self.assertTrue(any(r["method"] == "PUT" for r in acl_writes))
            self.assertFalse(any(r["method"] == "PATCH" for r in acl_writes))

    def test_loopback_http_server_e2e(self):
        with tempfile.TemporaryDirectory() as tmp, MockControllerHTTPServer() as srv:
            cfg = make_write_config(
                tmp_dir=tmp,
                base_url=srv.base_url,
                read_only=False,
                write_tools=("set_client_fixed_ip",),
            )
            server = Server(cfg)
            res = unwrap_ok(call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.56",
                "dryRun": False,
                "confirm": "set_client_fixed_ip:aa:bb:cc:11:11:01",
            }))
            self.assertTrue(res["applied"])
            self.assertEqual(res["after"]["ip"], "192.168.20.56")

