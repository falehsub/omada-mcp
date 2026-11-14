"""Milestone 2 policy route/LAN DNS/ACL/client/rollback and cache-safety tests."""

from __future__ import annotations

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

from omada_mcp.config import (  # noqa: E402
    WRITE_TOOL_NAMES,
)


class Milestone2RoutingDnsAclClientAndRollbackTests(unittest.TestCase):
    def test_policy_route_and_lan_dns_lifecycle_and_hardware_fallbacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Missing gateway refuses policy route cleanly (-1007)
            ctrl.has_gateway = False
            no_gw = call_tool(server, "upsert_policy_route", {
                "name": "IoT-WAN2",
                "interfaceIds": ["2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            })
            self.assertTrue(no_gw["result"]["isError"])
            self.assertIn("-1007", no_gw["result"]["content"][0]["text"])
            ctrl.has_gateway = True

            # Create, update, delete policy route
            pr_dry = unwrap_ok(call_tool(server, "upsert_policy_route", {
                "name": "IoT-WAN2",
                "sourceType": 0,
                "sourceIds": ["net-iot-20"],
                "destinationType": 0,
                "destinationIds": ["net-lab-40"],
                "interfaceIds": ["2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            }))
            pr = unwrap_ok(call_tool(server, "upsert_policy_route", {
                "name": "IoT-WAN2",
                "sourceType": 0,
                "sourceIds": ["net-iot-20"],
                "destinationType": 0,
                "destinationIds": ["net-lab-40"],
                "interfaceIds": ["2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "dryRun": False,
                "confirm": pr_dry["confirmToken"],
            }))
            rid = pr["after"]["id"]
            self.assertEqual(pr["after"]["name"], "IoT-WAN2")

            pr_del_dry = unwrap_ok(call_tool(server, "delete_policy_route", {"routeId": rid}))
            pr_del = unwrap_ok(call_tool(server, "delete_policy_route", {
                "routeId": rid,
                "dryRun": False,
                "confirm": pr_del_dry["confirmToken"],
            }))
            self.assertTrue(pr_del["applied"])
            self.assertEqual(ctrl.policy_routes, [])

            # Unsupported LAN DNS controller returns clear error (-41011)
            ctrl.lan_dns_supported = False
            unsup = call_tool(server, "upsert_lan_dns_rule", {
                "name": "nas-host",
                "domain": "nas.lab.arpa",
                "ipAddresses": ["192.168.10.20"],
            })
            self.assertTrue(unsup["result"]["isError"])
            self.assertIn("not supported", unsup["result"]["content"][0]["text"].lower())
            ctrl.lan_dns_supported = True

            # Create, update, delete LAN DNS record
            dns_dry = unwrap_ok(call_tool(server, "upsert_lan_dns_rule", {
                "name": "nas-host",
                "domain": "nas.lab.arpa",
                "ipAddresses": ["192.168.10.20"],
            }))
            dns = unwrap_ok(call_tool(server, "upsert_lan_dns_rule", {
                "name": "nas-host",
                "domain": "nas.lab.arpa",
                "ipAddresses": ["192.168.10.20"],
                "dryRun": False,
                "confirm": dns_dry["confirmToken"],
            }))
            did = dns["after"]["id"]
            self.assertEqual(dns["after"]["domain"], "nas.lab.arpa")

            dns_up_dry = unwrap_ok(call_tool(server, "upsert_lan_dns_rule", {
                "ruleId": did,
                "name": "nas-host",
                "domain": "nas.lab.arpa",
                "ipAddresses": ["192.168.10.21"],
                "customTtl": True,
                "ttl": 120,
            }))
            dns_up = unwrap_ok(call_tool(server, "upsert_lan_dns_rule", {
                "ruleId": did,
                "name": "nas-host",
                "domain": "nas.lab.arpa",
                "ipAddresses": ["192.168.10.21"],
                "customTtl": True,
                "ttl": 120,
                "dryRun": False,
                "confirm": dns_up_dry["confirmToken"],
            }))
            self.assertEqual(dns_up["after"]["ttl"], 120)

            dns_del_dry = unwrap_ok(call_tool(server, "delete_lan_dns_rule", {"ruleId": did}))
            dns_del = unwrap_ok(call_tool(server, "delete_lan_dns_rule", {
                "ruleId": did,
                "dryRun": False,
                "confirm": dns_del_dry["confirmToken"],
            }))
            self.assertTrue(dns_del["applied"])

    def test_switch_acl_and_eap_acl_create_and_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            sw_dry = unwrap_ok(call_tool(server, "create_switch_acl", {
                "name": "Deny-IoT-To-Lab-L2",
                "policy": "deny",
                "source": {"type": "network", "ids": ["IoT"]},
                "destination": {"type": "network", "ids": ["Lab"]},
                "bindingType": "vlan",
                "networkId": "net-iot-20",
                "etherType": "0x0800",
            }))
            sw = unwrap_ok(call_tool(server, "create_switch_acl", {
                "name": "Deny-IoT-To-Lab-L2",
                "policy": "deny",
                "source": {"type": "network", "ids": ["IoT"]},
                "destination": {"type": "network", "ids": ["Lab"]},
                "bindingType": "vlan",
                "networkId": "net-iot-20",
                "etherType": "0x0800",
                "dryRun": False,
                "confirm": sw_dry["confirmToken"],
            }))
            self.assertTrue(any(r.get("name") == "Deny-IoT-To-Lab-L2" for r in ctrl.switch_acls))
            self.assertEqual(sw["after"]["type"], 1)

            eap_dry = unwrap_ok(call_tool(server, "create_eap_acl", {
                "name": "Isolate-Guest-SSID",
                "policy": "deny",
                "source": {"type": "ssid", "ids": ["Lab-Guest"]},
                "destination": {"type": "network", "ids": ["Lab"]},
            }))
            eap = unwrap_ok(call_tool(server, "create_eap_acl", {
                "name": "Isolate-Guest-SSID",
                "policy": "deny",
                "source": {"type": "ssid", "ids": ["Lab-Guest"]},
                "destination": {"type": "network", "ids": ["Lab"]},
                "dryRun": False,
                "confirm": eap_dry["confirmToken"],
            }))
            self.assertTrue(any(r.get("name") == "Isolate-Guest-SSID" for r in ctrl.eap_acls))
            self.assertEqual(eap["after"]["type"], 2)

            # Toggle, update, and delete switch + EAP ACLs (both explicit aclType and auto-detected)
            sw_id = str(sw["after"]["id"])
            sw_tog_dry = unwrap_ok(call_tool(server, "set_acl_rule_status", {
                "rule": sw_id,
                "aclType": "switch",
                "status": False,
            }))
            sw_tog = unwrap_ok(call_tool(server, "set_acl_rule_status", {
                "rule": sw_id,
                "aclType": "switch",
                "status": False,
                "dryRun": False,
                "confirm": sw_tog_dry["confirmToken"],
            }))
            self.assertIs(sw_tog["after"]["status"], False)
            self.assertEqual(sw_tog["after"]["aclType"], "switch")

            eap_id = str(eap["after"]["id"])
            eap_upd_dry = unwrap_ok(call_tool(server, "update_gateway_acl", {
                "rule": "Isolate-Guest-SSID",
                "syslog": True,
                "name": "Isolate-Guest-SSID-v2",
            }))
            eap_upd = unwrap_ok(call_tool(server, "update_gateway_acl", {
                "rule": "Isolate-Guest-SSID",
                "syslog": True,
                "name": "Isolate-Guest-SSID-v2",
                "dryRun": False,
                "confirm": eap_upd_dry["confirmToken"],
            }))
            self.assertEqual(eap_upd["after"]["name"], "Isolate-Guest-SSID-v2")
            self.assertIs(eap_upd["after"]["syslog"], True)

            sw_del_dry = unwrap_ok(call_tool(server, "delete_gateway_acl", {
                "rule": sw_id,
                "aclType": "switch",
            }))
            sw_del = unwrap_ok(call_tool(server, "delete_gateway_acl", {
                "rule": sw_id,
                "aclType": "switch",
                "dryRun": False,
                "confirm": sw_del_dry["confirmToken"],
            }))
            self.assertTrue(sw_del["applied"])
            self.assertFalse(any(r.get("id") == sw_id for r in ctrl.switch_acls))
            sw_rb_sid = Path(sw_del["snapshot"]).name
            sw_rb_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": sw_rb_sid}))
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": sw_rb_sid,
                "dryRun": False,
                "confirm": sw_rb_dry["confirmToken"],
            }))
            self.assertTrue(any(r.get("name") == "Deny-IoT-To-Lab-L2" for r in ctrl.switch_acls))

            eap_del_dry = unwrap_ok(call_tool(server, "delete_gateway_acl", {"rule": eap_id}))
            unwrap_ok(call_tool(server, "delete_gateway_acl", {
                "rule": eap_id,
                "dryRun": False,
                "confirm": eap_del_dry["confirmToken"],
            }))
            self.assertFalse(any(r.get("id") == eap_id for r in ctrl.eap_acls))

    def test_client_lock_to_ap_and_rate_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Refuses managed device MAC and missing apMacs when enabled=True
            no_aps = call_tool(server, "set_client_lock_to_ap", {"clientMac": "AA-BB-CC-11-11-02", "enabled": True})
            self.assertTrue(no_aps["result"]["isError"])

            lk_dry = unwrap_ok(call_tool(server, "set_client_lock_to_ap", {
                "clientMac": "AA-BB-CC-11-11-02",
                "enabled": True,
                "apMacs": ["ap-living"],
            }))
            lk = unwrap_ok(call_tool(server, "set_client_lock_to_ap", {
                "clientMac": "AA-BB-CC-11-11-02",
                "enabled": True,
                "apMacs": ["ap-living"],
                "dryRun": False,
                "confirm": lk_dry["confirmToken"],
            }))
            self.assertIs(lk["after"]["enable"], True)
            self.assertEqual(
                ctrl.clients["AA-BB-CC-11-11-02"]["clientLockToApSetting"]["aps"],
                ["AA-BB-CC-00-00-03"],
            )

            # Rate limit via profile name (must survive CLIENT_VOLATILE_KEYS stripping)
            rl_dry = unwrap_ok(call_tool(server, "set_client_rate_limit", {
                "clientMac": "AA-BB-CC-11-11-02",
                "enabled": True,
                "rateLimitProfileName": "Guest-10M",
            }))
            rl = unwrap_ok(call_tool(server, "set_client_rate_limit", {
                "clientMac": "AA-BB-CC-11-11-02",
                "enabled": True,
                "rateLimitProfileName": "Guest-10M",
                "dryRun": False,
                "confirm": rl_dry["confirmToken"],
            }))
            self.assertIs(rl["after"]["rateLimit"]["enable"], True)
            self.assertEqual(rl["after"]["rateLimit"]["rateLimitId"], "rl-prof-1")

            # Custom Kbps limit
            cu_dry = unwrap_ok(call_tool(server, "set_client_rate_limit", {
                "clientMac": "AA-BB-CC-11-11-02",
                "enabled": True,
                "downLimitKbps": 4000,
                "upLimitKbps": 1000,
            }))
            cu = unwrap_ok(call_tool(server, "set_client_rate_limit", {
                "clientMac": "AA-BB-CC-11-11-02",
                "enabled": True,
                "downLimitKbps": 4000,
                "upLimitKbps": 1000,
                "dryRun": False,
                "confirm": cu_dry["confirmToken"],
            }))
            self.assertEqual(cu["after"]["rateLimit"]["downLimit"], 4000)

    def test_rollback_from_snapshot_path_traversal_diff_and_verified_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # 1. Path traversal / non-.json rejected with 0 requests
            for bad in ("../escape.json", "/etc/passwd.json", "sub/a.json", "notjson.txt"):
                res = call_tool(server, "rollback_from_snapshot", {"snapshotId": bad})
                self.assertTrue(res["result"]["isError"], bad)
            self.assertEqual(ctrl.write_request_count, 0)

            # 2. Rollback switch port update
            sp_dry = unwrap_ok(call_tool(server, "update_switch_port", {
                "deviceMac": "sw-access",
                "port": 4,
                "name": "Temp-Port4",
                "poeEnabled": False,
            }))
            sp_res = unwrap_ok(call_tool(server, "update_switch_port", {
                "deviceMac": "sw-access",
                "port": 4,
                "name": "Temp-Port4",
                "poeEnabled": False,
                "dryRun": False,
                "confirm": sp_dry["confirmToken"],
            }))
            sp_sid = Path(sp_res["snapshot"]).name
            rb_sp_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": sp_sid}))
            self.assertTrue(rb_sp_dry["dryRun"])
            self.assertEqual(rb_sp_dry["before"]["name"], "Temp-Port4")
            self.assertEqual(rb_sp_dry["after"]["name"], "Port4")
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": sp_sid,
                "dryRun": False,
                "confirm": rb_sp_dry["confirmToken"],
            }))
            p4 = next(p for p in ctrl.switch_ports["AA-BB-CC-00-00-02"] if p["port"] == 4)
            self.assertEqual(p4["name"], "Port4")

            # 3. Rollback AP radio change (with colons in target!)
            ap_dry = unwrap_ok(call_tool(server, "update_ap_radio", {
                "deviceMac": "ap-living",
                "band": "5g",
                "channel": 40,
            }))
            ap_res = unwrap_ok(call_tool(server, "update_ap_radio", {
                "deviceMac": "ap-living",
                "band": "5g",
                "channel": 40,
                "dryRun": False,
                "confirm": ap_dry["confirmToken"],
            }))
            ap_sid = Path(ap_res["snapshot"]).name
            rb_ap_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": ap_sid}))
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": ap_sid,
                "dryRun": False,
                "confirm": rb_ap_dry["confirmToken"],
            }))
            self.assertEqual(str(ctrl.eap_details["AA-BB-CC-00-00-03"]["radioSetting5g"]["channel"]), "9")

            # 4. Rollback update_lan_network (nested collection/interface snapshot shape)
            lan_dry = unwrap_ok(call_tool(server, "update_lan_network", {
                "vlan": 20,
                "name": "IoT-Renamed",
            }))
            lan_res = unwrap_ok(call_tool(server, "update_lan_network", {
                "vlan": 20,
                "name": "IoT-Renamed",
                "dryRun": False,
                "confirm": lan_dry["confirmToken"],
            }))
            lan_sid = Path(lan_res["snapshot"]).name
            rb_lan_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": lan_sid}))
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": lan_sid,
                "dryRun": False,
                "confirm": rb_lan_dry["confirmToken"],
            }))
            iot_net = next(n for n in ctrl.lan_collection if n["id"] == "net-iot-20")
            self.assertEqual(iot_net["name"], "IoT")

            # 5. Rollback create_switch_acl (deletes created ACL)
            acl_dry = unwrap_ok(call_tool(server, "create_switch_acl", {
                "name": "Temp-Switch-ACL",
                "policy": "deny",
                "source": {"type": "network", "ids": ["IoT"]},
                "destination": {"type": "network", "ids": ["Lab"]},
            }))
            acl_res = unwrap_ok(call_tool(server, "create_switch_acl", {
                "name": "Temp-Switch-ACL",
                "policy": "deny",
                "source": {"type": "network", "ids": ["IoT"]},
                "destination": {"type": "network", "ids": ["Lab"]},
                "dryRun": False,
                "confirm": acl_dry["confirmToken"],
            }))
            acl_sid = Path(acl_res["snapshot"]).name
            rb_acl_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": acl_sid}))
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": acl_sid,
                "dryRun": False,
                "confirm": rb_acl_dry["confirmToken"],
            }))
            self.assertFalse(any(r.get("name") == "Temp-Switch-ACL" for r in ctrl.switch_acls))

    def test_m2_read_only_and_allowlist_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            ro_srv, _c1, ctrl1, _ = make_write_env(tmp, read_only=True, write_tools=WRITE_TOOL_NAMES)
            for name, args in (
                ("rollback_from_snapshot", {"snapshotId": "x.json"}),
                ("update_switch_port", {"deviceMac": "sw", "port": 1}),
                ("update_ap_radio", {"deviceMac": "ap", "band": "5g"}),
                ("upsert_lan_dns_rule", {"name": "a", "domain": "a.local"}),
            ):
                resp = call_tool(ro_srv, name, args)
                self.assertEqual(resp["error"]["code"], -32003)
            self.assertEqual(ctrl1.write_request_count, 0)

            limited_srv, _c2, ctrl2, _ = make_write_env(tmp, read_only=False, write_tools=("set_upnp",))
            for name, args in (
                ("cycle_poe_port", {"deviceMac": "sw", "port": 3}),
                ("create_switch_acl", {"name": "a", "policy": "deny", "source": {}, "destination": {}}),
            ):
                resp = call_tool(limited_srv, name, args)
                self.assertEqual(resp["error"]["code"], -32003)
            self.assertEqual(ctrl2.write_request_count, 0)


class WriteScopedCacheSafetyTests(unittest.TestCase):
    def test_write_clears_and_bypasses_scoped_cache_for_read_back_and_reauth(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, ctrl, _ = make_write_env(
                tmp, read_only=False, write_tools=("set_client_fixed_ip",),
            )
            client.authenticate()
            # Simulate a caller opening scoped_cache and reading live client state first.
            with client.scoped_cache():
                before_cached = client.api_result(
                    f"sites/{client.site.site_id}/clients/AA-BB-CC-11-11-01"
                )
                self.assertFalse(
                    bool((before_cached.get("ipSetting") or {}).get("useFixedAddr"))
                )
                req_before_write = len(ctrl.requests)

                # Mutate via MCP tool (commit): write() MUST clear cache AND bypass it on read_back!
                dry = unwrap_ok(call_tool(server, "set_client_fixed_ip", {
                    "mac": "AA-BB-CC-11-11-01",
                    "ip": "192.168.20.55",
                }))
                committed = unwrap_ok(call_tool(server, "set_client_fixed_ip", {
                    "mac": "AA-BB-CC-11-11-01",
                    "ip": "192.168.20.55",
                    "dryRun": False,
                    "confirm": dry["confirmToken"],
                }))
                self.assertTrue(committed["verified"])
                self.assertGreater(len(ctrl.requests), req_before_write)

                # Subsequent GET inside the same cache scope sees post-write controller state (cache was cleared).
                after_live = client.api_result(
                    f"sites/{client.site.site_id}/clients/AA-BB-CC-11-11-01"
                )
                self.assertTrue(after_live["ipSetting"]["useFixedAddr"])
                self.assertEqual(after_live["ipSetting"]["ip"], "192.168.20.55")

