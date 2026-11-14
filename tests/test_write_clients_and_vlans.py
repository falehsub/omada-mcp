"""Write Flow A (fixed IP), Flow B (VLAN), Flow C (groups/ACL), and pagination/reauth tests."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SRC = ROOT / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from write_harness import call_tool, make_write_env, unwrap_ok  # noqa: E402

from omada_mcp.write_tools import (  # noqa: E402
    CLIENT_VOLATILE_KEYS,
)


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

            # Repeating an already-converged reservation is an idempotent no-op (zero extra PATCH)
            repeat_dry = unwrap_ok(call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.55",
            }))
            self.assertEqual(repeat_dry["diff"], {})
            repeat_commit = unwrap_ok(call_tool(server, "set_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.55",
                "dryRun": False,
                "confirm": repeat_dry["confirmToken"],
            }))
            self.assertTrue(repeat_commit["applied"])
            self.assertTrue(repeat_commit["verified"])
            self.assertIsNone(repeat_commit["snapshot"])
            self.assertEqual(repeat_commit["diff"], {})
            self.assertEqual(
                len([r for r in ctrl.requests if r["method"] == "PATCH" and "/clients/" in r["path"]]),
                1,
            )

            # Live IP intentionally remains at old lease until renewal
            self.assertEqual(ctrl.clients["AA-BB-CC-11-11-01"]["ip"], "192.168.20.50")

            rel = unwrap_ok(call_tool(server, "release_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "dryRun": False,
                "confirm": "release_client_fixed_ip:aa:bb:cc:11:11:01",
            }))
            self.assertFalse(rel["after"]["useFixedAddr"])

    def test_release_client_fixed_ip_deletes_the_static_reservation_row(self):
        """Issue #5: release must clear the row, not just flip useFixedAddr."""
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.dhcp_reservations = [{
                "id": "dhcp-seed-1", "mac": "AA-BB-CC-11-11-01", "ip": "192.168.20.50",
                "netId": "net-iot-20", "status": False, "description": "",
            }]

            preview = unwrap_ok(call_tool(server, "release_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
            }))
            self.assertTrue(any("reservation row" in w.lower() for w in preview["warnings"]))

            released = unwrap_ok(call_tool(server, "release_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "dryRun": False,
                "confirm": "release_client_fixed_ip:aa:bb:cc:11:11:01",
            }))
            self.assertTrue(released["applied"])
            self.assertFalse(released["after"]["useFixedAddr"])
            self.assertEqual(ctrl.dhcp_reservations, [])
            self.assertTrue(any("reservation row removed" in w for w in released["warnings"]))
            self.assertTrue(any(r["method"] == "DELETE" and "/setting/service/dhcp/" in r["path"]
                                for r in ctrl.requests))

    def test_release_without_a_static_row_does_not_claim_a_removal(self):
        """No row to clean up is not a removal: the warning must not lie."""
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.dhcp_reservations = []

            released = unwrap_ok(call_tool(server, "release_client_fixed_ip", {
                "mac": "AA-BB-CC-11-11-01",
                "dryRun": False,
                "confirm": "release_client_fixed_ip:aa:bb:cc:11:11:01",
            }))
            self.assertTrue(released["applied"])
            self.assertFalse(any("row removed" in w for w in released["warnings"]),
                             released["warnings"])
            self.assertFalse(any(r["method"] == "DELETE" for r in ctrl.requests))

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

