"""Comprehensive offline tests for v1.2 write-support contracts, flows, and fault injection."""

from __future__ import annotations

import copy
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
TESTS = Path(__file__).resolve().parent
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from mock_controller import MockController, MockControllerHTTPServer  # noqa: E402
from omada_mcp import config as config_mod  # noqa: E402
from omada_mcp.client import (  # noqa: E402
    ERROR_CATALOG,
    OmadaClient,
    OmadaError,
    explain_error_code,
)
from omada_mcp.config import (  # noqa: E402
    Config,
    ConfigError,
    WRITE_TOOL_NAMES,
    default_snapshot_dir,
    load_config,
    parse_management_cidrs,
    parse_write_tools,
)
from omada_mcp.doctor import run_doctor  # noqa: E402
from omada_mcp.server import Server  # noqa: E402
from omada_mcp.tools import TOOL_MAP, TOOLS, tool_descriptors  # noqa: E402
from omada_mcp.write_tools import (  # noqa: E402
    CLIENT_VOLATILE_KEYS,
    WRITE_ENVELOPE_SCHEMA,
    pack_ip_entries,
)


def make_write_config(
    *,
    tmp_dir: str,
    base_url: str = "https://192.168.10.10:8043",
    read_only: bool = False,
    write_tools: tuple[str, ...] = WRITE_TOOL_NAMES,
    management_cidrs: tuple[str, ...] = (),
    write_min_interval: float = 0.0,
) -> Config:
    return Config(
        base_url=base_url,
        username="admin-writer",
        password="pw",
        verify_ssl=False,
        read_only=read_only,
        write_tools=write_tools,
        snapshot_dir=Path(tmp_dir),
        snapshot_origin="OMADA_SNAPSHOT_DIR",
        write_min_interval=write_min_interval,
        management_cidrs=management_cidrs,
        min_interval=0.0,
        timeout=5.0,
    )


def make_write_env(
    tmp_dir: str,
    *,
    role: str = "Administrator",
    read_only: bool = False,
    write_tools: tuple[str, ...] = WRITE_TOOL_NAMES,
    management_cidrs: tuple[str, ...] = (),
    write_min_interval: float = 0.0,
    controller_url: str = "https://192.168.10.10:8043",
):
    ctrl = MockController(role=role)
    cfg = make_write_config(
        tmp_dir=tmp_dir,
        base_url=controller_url,
        read_only=read_only,
        write_tools=write_tools,
        management_cidrs=management_cidrs,
        write_min_interval=write_min_interval,
    )
    now = [100.0]
    sleeps = []

    def fake_clock() -> float:
        return now[0]

    def fake_sleep(sec: float) -> None:
        sleeps.append(sec)
        now[0] += sec

    client = OmadaClient(
        cfg,
        transport=ctrl,
        sleep=fake_sleep,
        clock=fake_clock,
        log_fn=lambda _msg: None,
    )
    server = Server(cfg, client=client)
    return server, client, ctrl, sleeps


def call_tool(server: Server, name: str, arguments: dict | None = None, req_id: int = 1) -> dict:
    return server.handle({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })


def unwrap_ok(resp: dict) -> dict:
    assert "error" not in resp, f"unexpected RPC error: {resp.get('error')}"
    res = resp["result"]
    assert not res.get("isError"), f"unexpected tool error: {res}"
    return res["structuredContent"]


class WriteConfigTests(unittest.TestCase):
    def test_tool_name_sets_match_tools_module(self):
        ro_names = {t.name for t in TOOLS if t.read_only}
        wr_names = {t.name for t in TOOLS if not t.read_only}
        self.assertEqual(len(ro_names), 20)
        self.assertEqual(len(wr_names), 31)
        self.assertEqual(config_mod._READ_ONLY_TOOL_NAMES, ro_names)
        self.assertEqual(set(WRITE_TOOL_NAMES), wr_names)
        self.assertEqual(len(TOOLS), 51)

    def test_parse_write_tools_validation(self):
        self.assertEqual(parse_write_tools(None), ())
        self.assertEqual(parse_write_tools("  "), ())
        self.assertEqual(
            parse_write_tools("set_client_fixed_ip, release_client_fixed_ip, set_client_fixed_ip"),
            ("set_client_fixed_ip", "release_client_fixed_ip"),
        )
        for bad in ("*", "set_*", "all", "ALL", "set_client_fixed_ip, ", "list_devices", "get_config_snapshot", "bogus_tool"):
            with self.subTest(bad=bad):
                with self.assertRaises(ConfigError):
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
            self.assertEqual(len(listed), 21)
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


class FlowAClientFixedIpTests(unittest.TestCase):
    def test_set_and_release_client_fixed_ip_strips_volatiles_and_warns_lease_delay(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)

            preview = unwrap_ok(call_tool(server, "set_client_fixed_ip", {
                "mac": "AA:BB:CC:11:11:01",
                "ip": "192.168.20.55",
            }))
            self.assertTrue(preview["dryRun"])
            self.assertFalse(preview["applied"])
            self.assertEqual(preview["confirmToken"], "set_client_fixed_ip:aa:bb:cc:11:11:01")
            self.assertEqual(ctrl.write_request_count, 0)
            self.assertTrue(any("lease" in w.lower() for w in preview["warnings"]))

            applied = unwrap_ok(call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.55",
                "dryRun": False,
                "confirm": preview["confirmToken"],
            }))
            self.assertTrue(applied["applied"])
            self.assertEqual(applied["after"]["ip"], "192.168.20.55")
            self.assertTrue(applied["after"]["useFixedAddr"])
            self.assertEqual(applied["after"]["netId"], "net-iot-20")

            patch_reqs = [r for r in ctrl.requests if r["method"] == "PATCH" and "/clients/" in r["path"]]
            self.assertEqual(len(patch_reqs), 1)
            sent_keys = set(patch_reqs[0]["body"].keys())
            self.assertEqual(sent_keys & CLIENT_VOLATILE_KEYS, set())
            self.assertEqual(patch_reqs[0]["body"]["ipSetting"]["netId"], "net-iot-20")

            # Live IP intentionally remains at old lease until renewal
            self.assertEqual(ctrl.clients["AA-BB-CC-11-11-01"]["ip"], "192.168.20.50")

            rel = unwrap_ok(call_tool(server, "release_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "dryRun": False,
                "confirm": "release_client_fixed_ip:aa:bb:cc:11:11:01",
            }))
            self.assertFalse(rel["after"]["useFixedAddr"])

    def test_device_mac_unsupported_fixed_ip_and_controller_ip_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)

            # Managed device MAC
            dev_resp = call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-00-00-01",
                "ip": "192.168.10.90",
            })
            self.assertTrue(dev_resp["result"]["isError"])
            self.assertIn("device", dev_resp["result"]["content"][0]["text"].lower())

            # supportFixedIp: false client
            unsup_resp = call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-03",
                "ip": "192.168.20.99",
            })
            self.assertTrue(unsup_resp["result"]["isError"])
            self.assertIn("supportFixedIp", unsup_resp["result"]["content"][0]["text"])

            # Reserved controller IP refused before writing
            ctrl_ip_resp = call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.10.10",
                "vlan": 1,
            })
            self.assertTrue(ctrl_ip_resp["result"]["isError"])
            self.assertIn("controller", ctrl_ip_resp["result"]["content"][0]["text"].lower())
            self.assertEqual(ctrl.write_request_count, 0)


class FlowBVlanTests(unittest.TestCase):
    def test_two_endpoint_vlan_isolation_and_ipv6_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)

            # Lab VLAN 40 starts without lanNetworkIpv6Config; tool must inject proto=none so controller accepts it.
            lab_res = unwrap_ok(call_tool(server, "set_vlan_isolation", {
                "vlan": 40,
                "isolation": True,
                "dryRun": False,
                "confirm": "set_vlan_isolation:net-lab-40",
            }))
            self.assertTrue(lab_res["verified"])
            self.assertTrue(lab_res["after"]["isolation"])
            self.assertTrue(lab_res["after"]["collectionIsolation"])
            self.assertIs(lab_res["after"]["accessControlRule"], False)

            # Verify collection and interface both updated
            col_40 = next(n for n in ctrl.lan_collection if n["id"] == "net-lab-40")
            iface_40 = next(n for n in ctrl.lan_interfaces if n["id"] == "net-lab-40")
            self.assertTrue(col_40["isolation"])
            self.assertTrue(iface_40["isolation"])
            self.assertEqual(iface_40["lanNetworkIpv6Config"], {"proto": "none", "enable": 0})

    def test_omada62_lan_normalization_and_overlapping_before_pool_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.omada62_lan_normalization = True
            # Simulate factory-default DHCP pool overlapping gateway 192.168.40.1
            iface_40 = next(n for n in ctrl.lan_interfaces if n["id"] == "net-lab-40")
            iface_40["dhcpSettings"]["ipRangePool"] = [
                {"ipaddrStart": "192.168.40.1", "ipaddrEnd": "192.168.40.254"}
            ]
            new_pools = [{"ipaddrStart": "192.168.40.50", "ipaddrEnd": "192.168.40.200"}]
            res = unwrap_ok(call_tool(server, "set_vlan_dhcp_pools", {
                "vlan": 40,
                "pools": new_pools,
                "dryRun": False,
                "confirm": "set_vlan_dhcp_pools:net-lab-40",
            }))
            self.assertTrue(res["applied"])
            self.assertTrue(res["verified"])
            self.assertEqual(res["after"]["ipRangePool"], new_pools)
            self.assertIsNone(res["rollback"])
            self.assertTrue(any("rollback" in w.lower() for w in res["warnings"]))

    def test_silent_noop_and_collection_desync_fail_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.silent_noop_for.add(("PATCH", "setting/lan/networks/net-guest-30"))
            resp = call_tool(server, "set_vlan_isolation", {
                "vlan": 30,
                "isolation": True,
                "dryRun": False,
                "confirm": "set_vlan_isolation:net-guest-30",
            })
            self.assertTrue(resp["result"]["isError"])
            self.assertIn("silently ignored or altered", resp["result"]["content"][0]["text"].lower())
            audit_rows = [json.loads(line) for line in (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(audit_rows[-1]["result"], "verification_failed")
            self.assertFalse(audit_rows[-1]["verified"])

        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.drop_collection_isolation_sync = True
            resp = call_tool(server, "set_vlan_isolation", {
                "vlan": 30,
                "isolation": True,
                "dryRun": False,
                "confirm": "set_vlan_isolation:net-guest-30",
            })
            self.assertTrue(resp["result"]["isError"])
            self.assertIn("collection isolation", resp["result"]["content"][0]["text"].lower())

    def test_dhcp_pools_update_and_collateral_drift_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            new_pools = [{"ipaddrStart": "192.168.30.100", "ipaddrEnd": "192.168.30.180"}]
            res = unwrap_ok(call_tool(server, "set_vlan_dhcp_pools", {
                "vlan": 30,
                "pools": new_pools,
                "dryRun": False,
                "confirm": "set_vlan_dhcp_pools:net-guest-30",
            }))
            self.assertTrue(res["verified"])
            self.assertEqual(res["after"]["ipRangePool"], new_pools)

        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.corrupt_dhcp_on_patch = True
            resp = call_tool(server, "set_vlan_dhcp_pools", {
                "vlan": 30,
                "pools": [{"ipaddrStart": "192.168.30.100", "ipaddrEnd": "192.168.30.180"}],
                "dryRun": False,
                "confirm": "set_vlan_dhcp_pools:net-guest-30",
            })
            self.assertTrue(resp["result"]["isError"])
            self.assertIn("drift", resp["result"]["content"][0]["text"].lower())

    def test_vlan_anti_stranding_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(
                tmp, management_cidrs=("192.168.40.10/32",)
            )
            # Isolating management VLAN containing controller 192.168.10.10 refused
            r1 = call_tool(server, "set_vlan_isolation", {"vlan": 1, "isolation": True})
            self.assertTrue(r1["result"]["isError"])
            self.assertIn("controller", r1["result"]["content"][0]["text"].lower())

            # Isolating management_cidr VLAN 40 refused
            r2 = call_tool(server, "set_vlan_isolation", {"vlan": 40, "isolation": True})
            self.assertTrue(r2["result"]["isError"])
            self.assertIn("management", r2["result"]["content"][0]["text"].lower())

            # DHCP pool overlapping controller IP 192.168.10.10 refused
            r3 = call_tool(server, "set_vlan_dhcp_pools", {
                "vlan": 1,
                "pools": [{"ipaddrStart": "192.168.10.5", "ipaddrEnd": "192.168.10.50"}],
            })
            self.assertTrue(r3["result"]["isError"])
            self.assertIn("controller", r3["result"]["content"][0]["text"].lower())

            # DHCP pool overlapping gateway 192.168.20.1 refused
            r4 = call_tool(server, "set_vlan_dhcp_pools", {
                "vlan": 20,
                "pools": [{"ipaddrStart": "192.168.20.1", "ipaddrEnd": "192.168.20.50"}],
            })
            self.assertTrue(r4["result"]["isError"])
            self.assertIn("gateway", r4["result"]["content"][0]["text"].lower())
            self.assertEqual(ctrl.write_request_count, 0)


class FlowCIpGroupsAndAclTests(unittest.TestCase):
    def test_create_and_replace_unreferenced_ip_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)

            created = unwrap_ok(call_tool(server, "create_ip_group", {
                "name": "block-targets",
                "ipRange": "192.168.20.200-203",
                "dryRun": False,
                "confirm": "create_ip_group:block-targets",
            }))
            self.assertTrue(created["applied"])
            self.assertEqual(created["after"]["ipList"], [
                {"ip": "192.168.20.200", "mask": 30, "description": ""}
            ])

            # Replace unreferenced group (shared-printers): DELETE + POST
            replaced = unwrap_ok(call_tool(server, "replace_ip_group", {
                "group": "shared-printers",
                "cidrs": ["192.168.20.50/32", "192.168.20.51/32"],
                "dryRun": False,
                "confirm": "replace_ip_group:grp-printers-02",
            }))
            self.assertTrue(replaced["applied"])
            self.assertEqual(len(replaced["steps"]), 2)
            self.assertNotEqual(replaced["after"]["id"], "grp-printers-02")

    def test_replace_referenced_ip_group_runs_6_step_tmp_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)

            preview = unwrap_ok(call_tool(server, "replace_ip_group", {
                "group": "lab-devices",
                "cidrs": ["192.168.20.180/30"],
            }))
            self.assertEqual(len(preview["steps"]), 6)
            self.assertEqual(preview["confirmToken"], "replace_ip_group:grp-devices-01")

            applied = unwrap_ok(call_tool(server, "replace_ip_group", {
                "group": "lab-devices",
                "cidrs": ["192.168.20.180/30"],
                "dryRun": False,
                "confirm": preview["confirmToken"],
            }))
            self.assertTrue(applied["applied"])
            self.assertEqual(len(applied["steps"]), 6)
            new_group_id = applied["after"]["id"]
            self.assertNotEqual(new_group_id, "grp-devices-01")
            acl2 = next(r for r in ctrl.acls if r["id"] == "acl-002")
            self.assertEqual(acl2["sourceIds"], [new_group_id])
            self.assertFalse(any("__tmp_" in g["name"] for g in ctrl.groups))

    def test_replace_ip_group_mid_swap_failure_reports_recovery_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Fail on 2nd ACL PUT (re-pointing acl-002 from tmp group back to recreated group)
            put_count = [0]

            def fail_repoint_final(method: str, path: str, _body):
                if method == "PUT" and "setting/firewall/acls/acl-002" in path:
                    put_count[0] += 1
                    if put_count[0] == 2:
                        return 200, {"errorCode": -1600, "msg": "Simulated mid-swap ACL failure"}
                return None

            ctrl.next_fault_hook = fail_repoint_final
            resp = call_tool(server, "replace_ip_group", {
                "group": "lab-devices",
                "cidrs": ["192.168.20.180/30"],
                "dryRun": False,
                "confirm": "replace_ip_group:grp-devices-01",
            })
            self.assertTrue(resp["result"]["isError"])
            text = resp["result"]["content"][0]["text"]
            self.assertIn("failed mid-operation", text.lower())
            self.assertIn("recreate_group", text.lower())

    def test_create_gateway_acl_and_toggle_status_with_acl_disable_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)

            # Anti-stranding refuses blocking controller-mgmt -> controller-mgmt
            bad_acl = call_tool(server, "create_gateway_acl", {
                "name": "self-lockout",
                "policy": "deny",
                "source": {"type": "network", "ids": ["Default"]},
                "destination": {"type": "network", "ids": ["Default"]},
                "direction": {"lanToWan": False, "lanToLan": True},
            })
            self.assertTrue(bad_acl["result"]["isError"])
            self.assertIn("controller", bad_acl["result"]["content"][0]["text"].lower())

            # Create Guest -> Default deny rule safely
            created = unwrap_ok(call_tool(server, "create_gateway_acl", {
                "name": "block-guest-to-iot",
                "policy": "deny",
                "source": {"type": "network", "ids": ["Guest"]},
                "destination": {"type": "network", "ids": ["IoT"]},
                "direction": {"lanToWan": False, "lanToLan": True},
                "dryRun": False,
                "confirm": "create_gateway_acl:block-guest-to-iot",
            }))
            self.assertTrue(created["applied"])
            self.assertTrue(any("aclDisable" in w for w in created["warnings"]))
            # aclDisable on controller remains untouched (True)
            self.assertTrue(ctrl.acl_disable)

            # Toggle existing rule status without touching aclDisable
            toggled = unwrap_ok(call_tool(server, "set_acl_rule_status", {
                "rule": "deny-guest-to-mgmt",
                "status": False,
                "dryRun": False,
                "confirm": "set_acl_rule_status:acl-001",
            }))
            self.assertFalse(toggled["after"]["status"])
            self.assertTrue(ctrl.acl_disable)
            self.assertTrue(any("aclDisable" in w for w in toggled["warnings"]))


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
        with tempfile.TemporaryDirectory() as tmp:
            with MockControllerHTTPServer() as srv:
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


class PaginationAndReauthTests(unittest.TestCase):
    def test_json_minus_30109_triggers_reauth_for_get_and_safe_check_for_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, ctrl, _ = make_write_env(tmp)
            client.authenticate()
            self.assertEqual(ctrl.logins, 1)

            # GET session expiry via JSON -30109 triggers one reauth and replays cleanly
            ctrl.expired_once_for.add(("GET", "setting/upnp"))
            services = unwrap_ok(call_tool(server, "get_network_services", {}))
            self.assertEqual(ctrl.logins, 2)
            self.assertIsNotNone(services["upnp"])

            # Non-GET session expiry via JSON -30109 reauths and checks live state before deciding
            ctrl.expired_once_for.add(("PUT", "setting/upnp"))
            applied = unwrap_ok(call_tool(server, "set_upnp", {
                "enable": True,
                "dryRun": False,
                "confirm": f"set_upnp:{client.site.site_id}",
            }))
            self.assertTrue(applied["applied"])
            self.assertIs(applied["after"]["enable"], True)
            self.assertEqual(ctrl.logins, 3)

            # If another worker/request already flipped UPnP, reauth_prepare detects it without duplicate PUT
            ctrl.next_fault_hook = None
            def _expire_after_apply(method, full_path, _body):
                if method == "PUT" and "setting/upnp" in full_path:
                    ctrl.upnp["enable"] = False
                    ctrl.cookie_jar.clear()
                    ctrl.next_fault_hook = None
                    return 200, {"errorCode": -30109, "msg": "Session expired."}
                return None

            ctrl.next_fault_hook = _expire_after_apply
            puts_before = sum(1 for r in ctrl.requests if r["method"] == "PUT" and "setting/upnp" in r["path"])
            recovered = unwrap_ok(call_tool(server, "set_upnp", {
                "enable": False,
                "dryRun": False,
                "confirm": f"set_upnp:{client.site.site_id}",
            }))
            puts_after = sum(1 for r in ctrl.requests if r["method"] == "PUT" and "setting/upnp" in r["path"])
            self.assertIs(recovered["after"]["enable"], False)
            self.assertEqual(puts_after, puts_before + 1)

    def test_multi_page_pagination_beyond_100_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, ctrl, _ = make_write_env(tmp)
            ctrl.devices = [
                {
                    "mac": f"AA-BB-CC-01-{i // 256:02X}-{i % 256:02X}",
                    "name": f"ap-{i:03d}",
                    "type": "ap",
                    "model": "EAP650",
                    "ip": f"192.168.10.{100 + (i % 100)}",
                    "firmwareVersion": "1.0.0",
                    "uptime": "1d",
                    "clientNum": 1,
                    "status": 1,
                    "statusCategory": 1,
                    "needUpgrade": False,
                }
                for i in range(105)
            ]
            ctrl.acls = [
                {
                    "id": f"acl-p-{i}",
                    "index": i,
                    "name": f"rule-{i:03d}",
                    "status": True,
                    "policy": 1,
                    "sourceType": 0,
                    "sourceIds": ["net-iot-20"],
                    "destinationType": 2,
                    "destinationIds": [],
                    "direction": {"lanToWan": True, "lanToLan": False},
                    "protocols": [256],
                }
                for i in range(105)
            ]
            devs = call_tool(server, "list_devices", {})["result"]["structuredContent"]
            acls = call_tool(server, "list_acls", {})["result"]["structuredContent"]
            self.assertEqual(devs["count"], 105)
            self.assertEqual(acls["count"], 105)

            # Duplicate-page guard: if server ignores currentPage and repeats page 1, paginate stops instead of looping
            client.authenticate()
            ctrl.next_fault_hook = lambda m, p, _b: (
                (200, {"errorCode": 0, "result": {"data": [{"id": "dup"}], "totalRows": 500}})
                if m == "GET" and "setting/profiles/groups" in p else None
            )
            rows, _ = client.paginate(f"sites/{client.site.site_id}/setting/profiles/groups", page_size=1)
            ctrl.next_fault_hook = None
            self.assertEqual(len(rows), 1)


class ExpandedReadToolsTests(unittest.TestCase):
    def test_search_clients_filters_and_viewer_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.clients["AA-BB-CC-11-11-02"]["active"] = False

            all_hits = unwrap_ok(call_tool(server, "search_clients", {}))
            self.assertEqual(all_hits["count"], 3)

            inactive_hits = unwrap_ok(call_tool(server, "search_clients", {"active": False}))
            self.assertEqual(inactive_hits["count"], 1)
            self.assertEqual(inactive_hits["items"][0]["mac"], "AA-BB-CC-11-11-02")

            q_hits = unwrap_ok(call_tool(server, "search_clients", {"query": "aabbcc111103"}))
            self.assertEqual(q_hits["count"], 1)
            self.assertEqual(q_hits["items"][0]["name"], "legacy-bridge")

            # Viewer role gets -1007 on clients endpoint -> seamless fallback to insight/clients
            ctrl.role = "Viewer"
            viewer_hits = unwrap_ok(call_tool(server, "search_clients", {"guest": True}))
            self.assertEqual(viewer_hits["count"], 1)
            self.assertEqual(viewer_hits["items"][0]["mac"], "AA-BB-CC-11-11-02")

    def test_network_services_logs_and_extended_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, _ctrl, _ = make_write_env(tmp)
            services = unwrap_ok(call_tool(server, "get_network_services", {}))
            self.assertIn("upnp", services)
            self.assertEqual(services["mdns"]["profileCount"], 2)

            for cat in ("alerts", "events", "audit"):
                logs = unwrap_ok(call_tool(server, "list_logs", {"category": cat, "hours": 0}))
                self.assertEqual(logs["count"], 1, cat)
                self.assertEqual(logs["items"][0]["category"], cat)

            snap = unwrap_ok(call_tool(server, "get_config_snapshot", {
                "objects": ["dhcpreservations", "portForwards", "staticRoutes", "mdnsRules", "services"],
            }))
            self.assertIn("dhcpReservations", snap)
            self.assertIn("portForwards", snap)
            self.assertIn("staticRoutes", snap)
            self.assertIn("mdnsRules", snap)
            self.assertIn("services", snap)


class DhcpLanAclGroupWriteTests(unittest.TestCase):
    def test_dhcp_reservation_and_lan_lifecycle_and_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Create LAN interface
            lan_dry = unwrap_ok(call_tool(server, "create_lan_network", {
                "name": "Lab50",
                "vlan": 50,
                "purpose": "interface",
                "gatewaySubnet": "192.168.50.1/24",
            }))
            self.assertTrue(lan_dry["dryRun"])
            lan_created = unwrap_ok(call_tool(server, "create_lan_network", {
                "name": "Lab50",
                "vlan": 50,
                "purpose": "interface",
                "gatewaySubnet": "192.168.50.1/24",
                "dryRun": False,
                "confirm": lan_dry["confirmToken"],
            }))
            self.assertTrue(lan_created["applied"])

            # Update LAN DNS/DHCP/name settings with Omada 6.2.x normalization quirks active
            ctrl.omada62_lan_normalization = True
            upd_dry = unwrap_ok(call_tool(server, "update_lan_network", {
                "vlan": 50,
                "name": "Lab50Up",
                "leaseTime": 240,
                "dnsMode": "manual",
                "dnsServers": ["1.1.1.1", "9.9.9.9"],
                "igmpSnoopEnable": True,
            }))
            upd_res = unwrap_ok(call_tool(server, "update_lan_network", {
                "vlan": 50,
                "name": "Lab50Up",
                "leaseTime": 240,
                "dnsMode": "manual",
                "dnsServers": ["1.1.1.1", "9.9.9.9"],
                "igmpSnoopEnable": True,
                "dryRun": False,
                "confirm": upd_dry["confirmToken"],
            }))
            self.assertTrue(upd_res["applied"])
            self.assertEqual(upd_res["after"]["dhcpSettings"]["priDns"], "1.1.1.1")
            self.assertEqual(upd_res["after"]["dhcpSettings"]["sndDns"], "9.9.9.9")
            lans_after = unwrap_ok(call_tool(server, "list_lan_networks", {}))["items"]
            lab50 = next(n for n in lans_after if n["vlan"] == 50)
            self.assertEqual(lab50["name"], "Lab50Up")
            self.assertEqual(lab50["leaseTime"], 240)
            self.assertTrue(lab50["dhcpPools"])
            ctrl.omada62_lan_normalization = False

            # Upsert + update + delete offline DHCP reservation
            res_dry = unwrap_ok(call_tool(server, "upsert_dhcp_reservation", {
                "mac": "AA:BB:CC:50:00:01",
                "ip": "192.168.50.42",
                "vlan": 50,
                "description": "lab-host",
            }))
            unwrap_ok(call_tool(server, "upsert_dhcp_reservation", {
                "mac": "AA:BB:CC:50:00:01",
                "ip": "192.168.50.42",
                "vlan": 50,
                "description": "lab-host",
                "dryRun": False,
                "confirm": res_dry["confirmToken"],
            }))
            listed = unwrap_ok(call_tool(server, "list_dhcp_reservations", {"vlan": 50}))
            self.assertEqual(listed["count"], 1)

            # Out-of-subnet IP is refused
            bad_ip = call_tool(server, "upsert_dhcp_reservation", {
                "mac": "AA:BB:CC:50:00:01",
                "ip": "192.168.99.42",
                "vlan": 50,
            })
            self.assertTrue(bad_ip["result"]["isError"])

            # Silent no-op on reservation update fails verification
            ctrl.silent_noop_for.add(("PUT", "setting/service/dhcp/"))
            noop_res = call_tool(server, "upsert_dhcp_reservation", {
                "mac": "AA:BB:CC:50:00:01",
                "ip": "192.168.50.43",
                "vlan": 50,
                "dryRun": False,
                "confirm": res_dry["confirmToken"],
            })
            ctrl.silent_noop_for.clear()
            self.assertTrue(noop_res["result"]["isError"])

            del_res_dry = unwrap_ok(call_tool(server, "delete_dhcp_reservation", {"mac": "AA:BB:CC:50:00:01"}))
            unwrap_ok(call_tool(server, "delete_dhcp_reservation", {
                "mac": "AA:BB:CC:50:00:01",
                "dryRun": False,
                "confirm": del_res_dry["confirmToken"],
            }))
            self.assertEqual(unwrap_ok(call_tool(server, "list_dhcp_reservations", {"vlan": 50}))["count"], 0)

            # Deleting primary/management LAN network refused
            blocked_del = call_tool(server, "delete_lan_network", {"vlan": 1})
            self.assertTrue(blocked_del["result"]["isError"])

            # Deleting Lab50 succeeds
            del_lan_dry = unwrap_ok(call_tool(server, "delete_lan_network", {"vlan": 50}))
            unwrap_ok(call_tool(server, "delete_lan_network", {
                "vlan": 50,
                "dryRun": False,
                "confirm": del_lan_dry["confirmToken"],
            }))
            self.assertFalse(any(n["vlan"] == 50 for n in unwrap_ok(call_tool(server, "list_lan_networks", {}))["items"]))

    def test_update_and_delete_gateway_acl_and_delete_ip_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, _ctrl, _ = make_write_env(tmp)
            grp = unwrap_ok(call_tool(server, "create_ip_group", {
                "name": "grp-del-test",
                "cidrs": ["192.168.20.150/32"],
                "dryRun": False,
                "confirm": "create_ip_group:grp-del-test",
            }))
            gid = grp["after"]["groupId"]
            acl_dry = unwrap_ok(call_tool(server, "create_gateway_acl", {
                "name": "acl-del-test",
                "policy": "deny",
                "source": {"type": "ip_group", "ids": [gid]},
                "destination": {"type": "port_group", "ids": ["grp-ports-99"]},
                "direction": {"lanToWan": True, "lanToLan": False},
            }))
            unwrap_ok(call_tool(server, "create_gateway_acl", {
                "name": "acl-del-test",
                "policy": "deny",
                "source": {"type": "ip_group", "ids": [gid]},
                "destination": {"type": "port_group", "ids": ["grp-ports-99"]},
                "direction": {"lanToWan": True, "lanToLan": False},
                "dryRun": False,
                "confirm": acl_dry["confirmToken"],
            }))

            # Deleting referenced IP group is pre-blocked (-33717 context)
            ref_err = call_tool(server, "delete_ip_group", {"group": gid})
            self.assertTrue(ref_err["result"]["isError"])
            self.assertIn("-33717", ref_err["result"]["content"][0]["text"])

            # Update ACL rule syslog/name via PUT
            u_dry = unwrap_ok(call_tool(server, "update_gateway_acl", {
                "rule": "acl-del-test",
                "syslog": True,
                "name": "acl-del-renamed",
            }))
            u_res = unwrap_ok(call_tool(server, "update_gateway_acl", {
                "rule": "acl-del-test",
                "syslog": True,
                "name": "acl-del-renamed",
                "dryRun": False,
                "confirm": u_dry["confirmToken"],
            }))
            self.assertIs(u_res["after"]["syslog"], True)

            # Delete ACL then group succeeds
            d_acl_dry = unwrap_ok(call_tool(server, "delete_gateway_acl", {"rule": "acl-del-renamed"}))
            unwrap_ok(call_tool(server, "delete_gateway_acl", {
                "rule": "acl-del-renamed",
                "dryRun": False,
                "confirm": d_acl_dry["confirmToken"],
            }))
            d_grp_dry = unwrap_ok(call_tool(server, "delete_ip_group", {"group": gid}))
            unwrap_ok(call_tool(server, "delete_ip_group", {
                "group": gid,
                "dryRun": False,
                "confirm": d_grp_dry["confirmToken"],
            }))
            self.assertFalse(any(g["id"] == gid for g in unwrap_ok(call_tool(server, "list_ip_groups", {}))["items"]))


class SsidAndGatewayServiceWriteTests(unittest.TestCase):
    def test_ssid_crud_never_leaks_psk_in_output_or_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, _ctrl, _ = make_write_env(tmp)
            secret_a = "UltraSecretPass123!"
            secret_b = "RotatedSecretPass456!"
            c_dry = call_tool(server, "create_ssid", {
                "name": "Lab-Test-WiFi",
                "bands": ["2g", "5g"],
                "security": "wpa2-psk",
                "psk": secret_a,
                "vlanId": 20,
            })
            self.assertNotIn(secret_a, json.dumps(c_dry))
            c_res = call_tool(server, "create_ssid", {
                "name": "Lab-Test-WiFi",
                "bands": ["2g", "5g"],
                "security": "wpa2-psk",
                "psk": secret_a,
                "vlanId": 20,
                "dryRun": False,
                "confirm": c_dry["result"]["structuredContent"]["confirmToken"],
            })
            self.assertNotIn(secret_a, json.dumps(c_res))

            u_dry = unwrap_ok(call_tool(server, "update_ssid", {
                "ssid": "Lab-Test-WiFi",
                "psk": secret_b,
                "clearVlan": True,
                "guest": True,
            }))
            self.assertNotIn(secret_a, json.dumps(u_dry))
            self.assertNotIn(secret_b, json.dumps(u_dry))
            u_res = call_tool(server, "update_ssid", {
                "ssid": "Lab-Test-WiFi",
                "psk": secret_b,
                "clearVlan": True,
                "guest": True,
                "dryRun": False,
                "confirm": u_dry["confirmToken"],
            })
            self.assertNotIn(secret_a, json.dumps(u_res))
            self.assertNotIn(secret_b, json.dumps(u_res))

            d_dry = unwrap_ok(call_tool(server, "delete_ssid", {"ssid": "Lab-Test-WiFi"}))
            unwrap_ok(call_tool(server, "delete_ssid", {
                "ssid": "Lab-Test-WiFi",
                "dryRun": False,
                "confirm": d_dry["confirmToken"],
            }))

            for fpath in Path(tmp).rglob("*"):
                if fpath.is_file():
                    raw_txt = fpath.read_text(encoding="utf-8")
                    self.assertNotIn(secret_a, raw_txt, str(fpath))
                    self.assertNotIn(secret_b, raw_txt, str(fpath))

    def test_port_forward_static_route_mdns_and_upnp(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, _ctrl, _ = make_write_env(tmp)
            pf_dry = unwrap_ok(call_tool(server, "upsert_port_forward", {
                "name": "HTTPS-Lab",
                "externalPort": "8443",
                "forwardIp": "192.168.20.50",
                "forwardPort": "443",
                "protocol": "tcp",
            }))
            unwrap_ok(call_tool(server, "upsert_port_forward", {
                "name": "HTTPS-Lab",
                "externalPort": "8443",
                "forwardIp": "192.168.20.50",
                "forwardPort": "443",
                "protocol": "tcp",
                "dryRun": False,
                "confirm": pf_dry["confirmToken"],
            }))
            self.assertEqual(unwrap_ok(call_tool(server, "list_port_forwards", {}))["count"], 1)
            pf_del_dry = unwrap_ok(call_tool(server, "delete_port_forward", {"rule": "HTTPS-Lab"}))
            unwrap_ok(call_tool(server, "delete_port_forward", {
                "rule": "HTTPS-Lab",
                "dryRun": False,
                "confirm": pf_del_dry["confirmToken"],
            }))
            self.assertEqual(unwrap_ok(call_tool(server, "list_port_forwards", {}))["count"], 0)

            sr_dry = unwrap_ok(call_tool(server, "upsert_static_route", {
                "name": "RemoteSub",
                "destination": "172.16.10.0/24",
                "nextHop": "192.168.20.254",
            }))
            unwrap_ok(call_tool(server, "upsert_static_route", {
                "name": "RemoteSub",
                "destination": "172.16.10.0/24",
                "nextHop": "192.168.20.254",
                "dryRun": False,
                "confirm": sr_dry["confirmToken"],
            }))
            self.assertEqual(unwrap_ok(call_tool(server, "list_static_routes", {}))["count"], 1)
            sr_del_dry = unwrap_ok(call_tool(server, "delete_static_route", {"rule": "RemoteSub"}))
            unwrap_ok(call_tool(server, "delete_static_route", {
                "rule": "RemoteSub",
                "dryRun": False,
                "confirm": sr_del_dry["confirmToken"],
            }))

            mdns_dry = unwrap_ok(call_tool(server, "upsert_mdns_rule", {
                "name": "AirPlay-IoT",
                "profiles": ["AirPlay"],
                "serviceNetworks": ["20"],
                "clientNetworks": ["1"],
            }))
            unwrap_ok(call_tool(server, "upsert_mdns_rule", {
                "name": "AirPlay-IoT",
                "profiles": ["AirPlay"],
                "serviceNetworks": ["20"],
                "clientNetworks": ["1"],
                "dryRun": False,
                "confirm": mdns_dry["confirmToken"],
            }))
            self.assertEqual(unwrap_ok(call_tool(server, "get_network_services", {}))["mdns"]["ruleCount"], 1)
            mdns_del_dry = unwrap_ok(call_tool(server, "delete_mdns_rule", {"rule": "AirPlay-IoT"}))
            unwrap_ok(call_tool(server, "delete_mdns_rule", {
                "rule": "AirPlay-IoT",
                "dryRun": False,
                "confirm": mdns_del_dry["confirmToken"],
            }))

            upnp_res = unwrap_ok(call_tool(server, "set_upnp", {
                "enable": True,
                "dryRun": False,
                "confirm": f"set_upnp:{client.site.site_id}",
            }))
            self.assertIs(upnp_res["after"]["enable"], True)


class ClientAndDeviceOpsTests(unittest.TestCase):
    def test_client_block_reconnect_rename_and_device_ops(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Refuses managed device MAC (-41011)
            dev_blk = call_tool(server, "set_client_blocked", {"mac": "AA-BB-CC-00-00-01", "blocked": True})
            self.assertTrue(dev_blk["result"]["isError"])

            # Block & unblock client
            blk_dry = unwrap_ok(call_tool(server, "set_client_blocked", {"mac": "AA-BB-CC-11-11-01", "blocked": True}))
            blk = unwrap_ok(call_tool(server, "set_client_blocked", {
                "mac": "AA-BB-CC-11-11-01",
                "blocked": True,
                "dryRun": False,
                "confirm": blk_dry["confirmToken"],
            }))
            self.assertIs(blk["after"]["blocked"], True)
            unblk = unwrap_ok(call_tool(server, "set_client_blocked", {
                "mac": "AA-BB-CC-11-11-01",
                "blocked": False,
                "dryRun": False,
                "confirm": blk_dry["confirmToken"],
            }))
            self.assertIs(unblk["after"]["blocked"], False)

            # Reconnect wireless client + refuse wired client
            ctrl.clients["AA-BB-CC-11-11-01"]["wireless"] = False
            wired_rec = call_tool(server, "reconnect_client", {"mac": "AA-BB-CC-11-11-01"})
            self.assertTrue(wired_rec["result"]["isError"])

            rec_dry = unwrap_ok(call_tool(server, "reconnect_client", {"mac": "AA-BB-CC-11-11-02"}))
            rec = unwrap_ok(call_tool(server, "reconnect_client", {
                "mac": "AA-BB-CC-11-11-02",
                "dryRun": False,
                "confirm": rec_dry["confirmToken"],
            }))
            self.assertTrue(rec["applied"])

            # Rename client
            ren_dry = unwrap_ok(call_tool(server, "update_client", {"mac": "AA-BB-CC-11-11-01", "name": "workstation-1"}))
            ren = unwrap_ok(call_tool(server, "update_client", {
                "mac": "AA-BB-CC-11-11-01",
                "name": "workstation-1",
                "dryRun": False,
                "confirm": ren_dry["confirmToken"],
            }))
            self.assertEqual(ren["after"]["name"], "workstation-1")

            # Rename device, LED setting, locate blink, and reboot
            dev_dry = unwrap_ok(call_tool(server, "update_device", {
                "mac": "ap-living",
                "name": "ap-kitchen",
                "ledSetting": "off",
                "locate": True,
            }))
            dev_res = unwrap_ok(call_tool(server, "update_device", {
                "mac": "ap-living",
                "name": "ap-kitchen",
                "ledSetting": "off",
                "locate": True,
                "dryRun": False,
                "confirm": dev_dry["confirmToken"],
            }))
            self.assertEqual(dev_res["after"]["name"], "ap-kitchen")
            self.assertIs(dev_res["after"]["locateEnable"], True)

            reb_dry = unwrap_ok(call_tool(server, "reboot_device", {"mac": "ap-kitchen"}))
            reb = unwrap_ok(call_tool(server, "reboot_device", {
                "mac": "ap-kitchen",
                "dryRun": False,
                "confirm": reb_dry["confirmToken"],
            }))
            self.assertTrue(reb["applied"])

            unknown_dev = call_tool(server, "update_device", {"mac": "AA-BB-CC-99-99-99", "name": "ghost"})
            self.assertTrue(unknown_dev["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
