"""Expanded read tools, DHCP/LAN/ACL/group writes, and SSID/service write tests."""

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

from omada_mcp.tools import tool_descriptors  # noqa: E402


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
            # Create LAN interface with controller-named pools; the schema also accepts
            # the {start, end} shorthand that list_lan_networks returns.
            create_schema = next(t["inputSchema"] for t in tool_descriptors(server.config) if t["name"] == "create_lan_network")
            items = create_schema["properties"]["pools"]["items"]
            self.assertEqual(
                {frozenset(opt["required"]) for opt in items["anyOf"]},
                {frozenset({"ipaddrStart", "ipaddrEnd"}), frozenset({"start", "end"})},
            )
            lan_dry = unwrap_ok(call_tool(server, "create_lan_network", {
                "name": "Lab50",
                "vlan": 50,
                "purpose": "interface",
                "gatewaySubnet": "192.168.50.1/24",
                "pools": [{"ipaddrStart": "192.168.50.50", "ipaddrEnd": "192.168.50.150"}],
            }))
            self.assertTrue(lan_dry["dryRun"])
            lan_created = unwrap_ok(call_tool(server, "create_lan_network", {
                "name": "Lab50",
                "vlan": 50,
                "purpose": "interface",
                "gatewaySubnet": "192.168.50.1/24",
                "pools": [{"ipaddrStart": "192.168.50.50", "ipaddrEnd": "192.168.50.150"}],
                "dryRun": False,
                "confirm": lan_dry["confirmToken"],
            }))
            self.assertTrue(lan_created["applied"])

            # Backwards-compatible {start, end} pool alias also normalizes cleanly
            lan51_dry = unwrap_ok(call_tool(server, "create_lan_network", {
                "name": "Lab51",
                "vlan": 51,
                "purpose": "interface",
                "gatewaySubnet": "192.168.51.1/24",
                "pools": [{"start": "192.168.51.50", "end": "192.168.51.150"}],
            }))
            lan51 = unwrap_ok(call_tool(server, "create_lan_network", {
                "name": "Lab51",
                "vlan": 51,
                "purpose": "interface",
                "gatewaySubnet": "192.168.51.1/24",
                "pools": [{"start": "192.168.51.50", "end": "192.168.51.150"}],
                "dryRun": False,
                "confirm": lan51_dry["confirmToken"],
            }))
            self.assertEqual(
                lan51["after"]["dhcpSettings"]["ipRangePool"],
                [{"ipaddrStart": "192.168.51.50", "ipaddrEnd": "192.168.51.150"}],
            )

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

            # Omada v6.2 omits 'biDirectional' on ACL rule read-back (uses stateMode instead):
            # update_gateway_acl must warn and still verify when target_rule lacks biDirectional.
            live_rule = next(r for r in _ctrl.acls if r["name"] == "acl-del-renamed")
            live_rule.pop("biDirectional", None)
            orig_req = _ctrl.request

            def _req_v62(method, url, headers=None, data=None, timeout=None):
                res = orig_req(method, url, headers=headers, data=data, timeout=timeout)
                for r in _ctrl.acls:
                    r.pop("biDirectional", None)
                return res

            _ctrl.request = _req_v62
            try:
                b_dry = unwrap_ok(call_tool(server, "update_gateway_acl", {
                    "rule": "acl-del-renamed",
                    "biDirectional": True,
                }))
                self.assertTrue(any("biDirectional" in w for w in b_dry["warnings"]))
                b_res = unwrap_ok(call_tool(server, "update_gateway_acl", {
                    "rule": "acl-del-renamed",
                    "biDirectional": True,
                    "dryRun": False,
                    "confirm": b_dry["confirmToken"],
                }))
                self.assertTrue(b_res["verified"])
            finally:
                _ctrl.request = orig_req

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
            self.assertEqual(upnp_res["after"]["wanPortIds"], ["wan-port-1"])
            self.assertTrue(upnp_res["after"]["networkIds"])

            # Disabling UPnP sends only {"enable": False}; rollback restores wanPortIds + networkIds
            upnp_off = unwrap_ok(call_tool(server, "set_upnp", {
                "enable": False,
                "dryRun": False,
                "confirm": f"set_upnp:{client.site.site_id}",
            }))
            self.assertIs(upnp_off["after"]["enable"], False)
            rb_sid = Path(upnp_off["snapshot"]).name
            rb_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": rb_sid}))
            rb_done = unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": rb_sid,
                "dryRun": False,
                "confirm": rb_dry["confirmToken"],
            }))
            self.assertIs(rb_done["after"]["enable"], True)
            self.assertEqual(rb_done["after"]["wanPortIds"], ["wan-port-1"])

