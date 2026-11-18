"""Regression tests for guarded inventory and evidence-aware snapshot diffs."""

from __future__ import annotations

import json
import tempfile
import unittest
from urllib.parse import urlsplit

from write_harness import call_confirmed, call_tool, make_write_env, unwrap_ok


class Wave1CompletenessTests(unittest.TestCase):
    def test_fallback_only_lag_membership_blocks_switch_port_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            switch_mac = ctrl.switch_insight_detail[0]["mac"]
            ctrl.switch_insight_detail[0]["lags"] = [{"lagId": 2, "portList": [4]}]

            def no_primary_lags(method, path, _body):
                if method == "GET" and urlsplit(path).path.endswith("/lags"):
                    return 200, {"errorCode": -1600, "msg": "Unavailable"}
                return None

            ctrl.next_fault_hook = no_primary_lags
            ports = unwrap_ok(call_tool(server, "get_switch_ports", {"mac": switch_mac}))
            port = next(row for row in ports["ports"] if row["port"] == 4)
            self.assertIs(port["isLagMember"], True)
            self.assertEqual(port["lagId"], 2)
            self.assertEqual(ports["collectionStatus"]["lags"], "complete")
            before = ctrl.write_request_count
            response = call_tool(server, "update_switch_port", {
                "deviceMac": switch_mac, "port": 4, "enabled": False,
            })
            self.assertTrue(response["result"]["isError"])
            self.assertIn("lag member", response["result"]["content"][0]["text"].lower())
            self.assertEqual(ctrl.write_request_count, before)

    def test_unavailable_lags_do_not_imply_nonmembership(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            switch_mac = ctrl.switch_insight_detail[0]["mac"]

            def no_lag_sources(method, path, _body):
                if method == "GET" and urlsplit(path).path.endswith(("/lags", "/insight/switch/detail")):
                    return 200, {"errorCode": -1007, "msg": "Forbidden"}
                return None

            ctrl.next_fault_hook = no_lag_sources
            ports = unwrap_ok(call_tool(server, "get_switch_ports", {"mac": switch_mac}))
            port = next(row for row in ports["ports"] if row["port"] == 4)
            self.assertIsNone(port["isLagMember"])
            self.assertEqual(ports["collectionStatus"]["lags"], "unavailable")
            before = ctrl.write_request_count
            response = call_tool(server, "update_switch_port", {
                "deviceMac": switch_mac, "port": 4, "enabled": False, "allowUplinkMutation": True,
            })
            self.assertTrue(response["result"]["isError"])
            self.assertIn("incomplete", response["result"]["content"][0]["text"].lower())
            self.assertEqual(ctrl.write_request_count, before)

    def test_repeated_port_profile_pages_stop_dependent_mutations(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, ctrl, _ = make_write_env(tmp)
            fixtures = [{"id": f"fixture-profile-{index}", "name": f"Fixture {index}"} for index in range(100)]
            arguments = {"name": "Test candidate"}
            preview = unwrap_ok(call_tool(server, "upsert_port_profile", arguments))

            def repeat_profiles(method, path, _body):
                if method == "GET" and urlsplit(path).path.endswith("/setting/lan/profiles"):
                    return 200, {"errorCode": 0, "result": {"data": fixtures, "totalRows": 150}}
                return None

            ctrl.next_fault_hook = repeat_profiles
            site = client.current_site()
            rows, meta = client.paginate(f"sites/{site.site_id}/setting/lan/profiles")
            self.assertEqual(len(rows), 100)
            page = (meta or {})["_pagination"]
            self.assertIs(page["truncated"], True)
            self.assertEqual(page["status"], "partial")
            self.assertIn("repeat", page["truncationReason"].lower())

            before = ctrl.write_request_count
            response = call_tool(server, "upsert_port_profile", {
                **arguments, "dryRun": False, "confirm": preview["confirmToken"],
            })
            self.assertTrue(response["result"]["isError"])
            self.assertIn("incomplete", response["result"]["content"][0]["text"].lower())
            self.assertEqual(ctrl.write_request_count, before)

    def test_switch_guard_requires_port_role_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            switch_mac = ctrl.switch_insight_detail[0]["mac"]

            def no_port_role_sources(method, path, _body):
                endpoint = urlsplit(path).path
                if method == "GET" and (
                    endpoint.endswith(("/topology", "/topology-v2"))
                    or ("/cable-test/switches/" in endpoint and endpoint.endswith("/ports"))
                ):
                    return 200, {"errorCode": -1007, "msg": "Forbidden"}
                return None

            ctrl.next_fault_hook = no_port_role_sources
            port_data = unwrap_ok(call_tool(server, "get_switch_ports", {"mac": switch_mac}))
            self.assertEqual(port_data["collectionStatus"]["topology"], "unavailable")
            self.assertEqual(port_data["collectionStatus"]["portDownlinks"], "unavailable")
            before = ctrl.write_request_count
            response = call_tool(server, "cycle_poe_port", {"deviceMac": switch_mac, "port": 4})
            self.assertTrue(response["result"]["isError"])
            self.assertIn("topology inventory is incomplete", response["result"]["content"][0]["text"])
            self.assertEqual(ctrl.write_request_count, before)

    def test_only_comparable_sections_contribute_to_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.vpn_configs = [{"id": "fixture-vpn", "status": True}]
            ctrl.wireguard_configs = [{"id": "fixture-wg", "name": "Fixture WG"}]
            ctrl.ddns["data"] = [{"id": "fixture-ddns", "domainName": "fixture.example"}]
            ctrl.poe_schedules = [{"id": "fixture-poe", "name": "Fixture PoE", "status": True}]
            objects = ["vpns", "wireguard", "ddns", "poeSchedules"]
            baseline = unwrap_ok(call_tool(server, "get_config_snapshot", {"objects": objects}))
            self.assertEqual({section: baseline["sectionStatus"][section]["status"] for section in objects},
                             dict.fromkeys(objects, "ok"))

            def unavailable_and_partial(method, path, _body):
                if method != "GET":
                    return None
                endpoint = urlsplit(path).path
                if endpoint.endswith("/setting/vpns"):
                    return 200, {"errorCode": -1007, "msg": "Forbidden"}
                if endpoint.endswith("/setting/service/poeSchedules"):
                    return 200, {"errorCode": 0, "result": {"data": [], "totalRows": 2}}
                return None

            ctrl.next_fault_hook = unavailable_and_partial
            ctrl.wireguard_configs.clear()
            current = unwrap_ok(call_tool(server, "get_config_snapshot", {
                "objects": ["vpns", "wireguard", "poeSchedules"],
            }))
            self.assertNotIn("vpns", current)
            self.assertNotIn("poeSchedules", current)
            self.assertEqual(current["sectionStatus"]["ddns"], {
                "status": "skipped", "reason": "section was not requested",
            })
            self.assertEqual(current["wireguard"], [])
            self.assertEqual(current["sectionStatus"]["wireguard"]["status"], "ok")
            delta = unwrap_ok(call_tool(server, "diff_config_snapshots", {"baseline": baseline, "current": current}))
            self.assertEqual(delta["sectionsCompared"], ["wireguard"])
            self.assertEqual(delta["summary"]["removed"], 1)
            self.assertEqual(delta["sections"]["wireguard"]["removed"][0]["value"]["id"], "fixture-wg")
            self.assertEqual({section: info["current"]["status"] for section, info in delta["sectionsSkipped"].items()},
                             {"vpns": "unavailable", "ddns": "skipped", "poeSchedules": "partial"})

    def test_snapshot_and_legacy_diff_only_expose_typed_configuration_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            marker = "synthetic-private-marker"
            ctrl.vpn_configs = [{"id": "fixture-vpn", "status": True, "unrecognized": {"key": marker}}]
            ctrl.wireguard_configs = [{"id": "fixture-wg", "privateKey": marker, "localIp": "192.0.2.1/24"}]
            ctrl.wireguard_peers = [{
                "id": "fixture-peer", "allowAddress": [{"opaque": marker}, "192.0.2.2/32"], "presharedKey": marker,
            }]
            ctrl.ddns["data"] = [{"id": "fixture-ddns", "domainName": "fixture.example", "password": marker}]
            objects = ["vpns", "wireguard", "wireguardPeers", "ddns"]
            snapshot = unwrap_ok(call_tool(server, "get_config_snapshot", {"objects": objects}))
            self.assertNotIn(marker, json.dumps(snapshot))
            self.assertEqual(snapshot["vpns"], [{"id": "fixture-vpn", "status": True}])
            self.assertEqual(snapshot["ddns"], [{"id": "fixture-ddns", "domainName": "fixture.example"}])
            self.assertEqual(snapshot["wireguardPeers"][0]["allowAddress"][-1], "192.0.2.2/32")

            baseline = {"objects": objects, **{section: snapshot[section] for section in objects}}
            baseline["vpns"] = [{"id": "fixture-vpn", "unrecognized": {"key": marker}, "status": True}]
            current = {**baseline, "vpns": [], "warnings": ["vpns skipped: permission denied"]}
            delta = unwrap_ok(call_tool(server, "diff_config_snapshots", {"baseline": baseline, "current": current}))
            self.assertFalse(delta["hasChanges"])
            self.assertIn("vpns", delta["sectionsSkipped"])
            current["warnings"] = []
            delta = unwrap_ok(call_tool(server, "diff_config_snapshots", {"baseline": baseline, "current": current}))
            self.assertEqual(delta["summary"]["removed"], 1)
            self.assertNotIn(marker, json.dumps(delta))

    def test_switch_port_reauth_checks_requested_duplex_before_replaying(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.expired_once_for.add(("PATCH", "/ports/4"))
            result = unwrap_ok(call_confirmed(server, "update_switch_port", {
                "deviceMac": "sw-access", "port": 4, "duplex": "half",
            }))
            self.assertEqual(result["after"]["duplex"], "half")
            self.assertTrue(result["verified"])
            self.assertEqual(ctrl.logins, 2)

    def test_existing_lag_does_not_verify_an_ignored_lacp_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            switch_mac = ctrl.switch_insight_detail[0]["mac"]
            ctrl.silent_noop_for.add(("PATCH", "/lags/1"))
            response = call_confirmed(server, "upsert_switch_lag", {
                "mac": switch_mac, "lagId": 1, "ports": [1, 2], "lagType": "static",
            })
            self.assertTrue(response["result"]["isError"])
            self.assertIn("lagtype", response["result"]["content"][0]["text"].lower())
            self.assertEqual(response["result"]["structuredContent"]["outcome"], "uncertain")

    def test_mirroring_does_not_verify_when_controller_ignores_source_lag(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            switch_mac = ctrl.switch_insight_detail[0]["mac"]

            def ignore_mirrored_lags(method, path, body):
                endpoint = urlsplit(path)
                if method == "PATCH" and endpoint.path.endswith("/ports/4"):
                    status, wire = ctrl._dispatch(method, endpoint.path, endpoint.query, {
                        key: value for key, value in body.items() if key != "mirroredLags"
                    })
                    return status, json.loads(wire)
                return None

            ctrl.next_fault_hook = ignore_mirrored_lags
            response = call_confirmed(server, "set_switch_port_mirror", {
                "mac": switch_mac, "mirroringPort": 4, "mirroredPorts": [5], "mirroredLags": [1],
            })
            self.assertTrue(response["result"]["isError"])
            self.assertIn("mirroredlags", response["result"]["content"][0]["text"].lower())
            self.assertEqual(response["result"]["structuredContent"]["outcome"], "uncertain")

    def test_switch_global_verification_detects_ignored_timer_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            switch_mac = ctrl.switch_insight_detail[0]["mac"]
            ctrl.silent_noop_for.add(("PUT", "/config/services"))
            response = call_confirmed(server, "update_switch_global_features", {
                "mac": switch_mac, "helloTime": 3,
            })
            self.assertTrue(response["result"]["isError"])
            self.assertIn("hellotime", response["result"]["content"][0]["text"].lower())
            self.assertEqual(response["result"]["structuredContent"]["outcome"], "uncertain")


if __name__ == "__main__":
    unittest.main()
