"""Phase A tests: hygiene/account read tools, port/MAC groups, schedules, active diagnostics."""

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


class PhaseAReadToolsTests(unittest.TestCase):
    def test_blocked_clients_rate_limits_schedules_users_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True)
            # Mark one client blocked & inject v6-flat + v5-nested rate-limit profile
            ctrl.clients["AA-BB-CC-11-11-02"]["block"] = True
            ctrl.rate_limit_profiles.append({
                "id": "rl-v6-flat",
                "name": "Voice-Flat",
                "isDefault": False,
                "downLimitEnable": True,
                "downLimit": 2500,
                "downLimitUnit": 1,
                "upLimitEnable": True,
                "upLimit": 1500,
                "upLimitUnit": 1,
            })
            # Inject sensitive fields to confirm deep_redact strips them
            ctrl.controller_status["smtpPassword"] = "smtp-super-secret-xyz"
            ctrl.controller_setting["mailPassword"] = "mail-secret-123"
            ctrl.users[0]["email"] = "admin@example.com"

            blocked = unwrap_ok(call_tool(server, "list_blocked_clients"))
            self.assertEqual(blocked["count"], 1)
            self.assertEqual(blocked["items"][0]["mac"], "aa:bb:cc:11:11:02")
            self.assertTrue(blocked["items"][0]["block"])

            rates = unwrap_ok(call_tool(server, "list_rate_limit_profiles"))
            self.assertEqual(rates["count"], 3)
            flat = next(r for r in rates["items"] if r["id"] == "rl-v6-flat")
            self.assertTrue(flat["downLimitEnable"])
            self.assertEqual(flat["downLimit"], 2500)
            nested = next(r for r in rates["items"] if r["id"] == "rl-prof-1")
            self.assertEqual(nested["downLimit"], 10000)

            scheds = unwrap_ok(call_tool(server, "list_schedules"))
            self.assertEqual(scheds["count"], 1)
            self.assertEqual(scheds["items"][0]["dayModeLabel"], "weekday")
            self.assertEqual(scheds["items"][0]["days"], ["mon", "tue", "wed", "thu", "fri"])
            self.assertEqual(scheds["items"][0]["timeList"][0]["start"], "08:00")

            users = unwrap_ok(call_tool(server, "list_controller_users"))
            self.assertEqual(users["count"], 2)
            self.assertFalse(users["viewerLimited"])
            self.assertIsNotNone(users["currentUser"])

            status_resp = call_tool(server, "get_controller_status")
            status = unwrap_ok(status_resp)
            self.assertIn("status", status)
            serialized = json.dumps(status_resp)
            self.assertNotIn("smtp-super-secret-xyz", serialized)
            self.assertNotIn("mail-secret-123", serialized)
            self.assertEqual(ctrl.write_request_count, 0)

    def test_viewer_role_fallbacks_for_blocked_clients_users_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, role="Viewer", read_only=True)
            ctrl.clients["AA-BB-CC-11-11-01"]["block"] = True

            # Viewer gets -1007 on /clients and transparently falls back to insight/clients
            blocked = unwrap_ok(call_tool(server, "list_blocked_clients"))
            self.assertEqual(blocked["count"], 1)
            self.assertEqual(blocked["items"][0]["mac"], "aa:bb:cc:11:11:01")
            self.assertTrue(any("/insight/clients" in r["url"] for r in ctrl.requests))

            # Viewer sees self only in users
            users = unwrap_ok(call_tool(server, "list_controller_users"))
            self.assertEqual(users["count"], 1)
            self.assertTrue(users["viewerLimited"])
            self.assertTrue(any("Viewer" in w for w in users["warnings"]))

            # Viewer gets -1007 on site NTP inside get_controller_status, warning cleanly
            status = unwrap_ok(call_tool(server, "get_controller_status"))
            self.assertIsNone(status["siteNtp"])
            self.assertTrue(any("site NTP" in w for w in status["warnings"]))

    def test_port_and_mac_groups_appear_in_list_ip_groups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True)
            ctrl.groups.extend([
                {
                    "groupId": "pg-web",
                    "name": "Web-Ports",
                    "type": 1,
                    "portType": 0,
                    "ipList": [],
                    "portList": ["80", "443"],
                    "portMaskList": [{"ip": "10.0.0.1", "mask": "32"}],
                },
                {
                    "groupId": "mg-cams",
                    "name": "Camera-MACs",
                    "type": 2,
                    "ipList": [],
                    "macAddressList": [{"name": "cam1", "macAddress": "AA-BB-CC-DD-EE-10"}],
                },
            ])
            port_res = unwrap_ok(call_tool(server, "list_ip_groups", {"groupType": "port"}))
            web_port = next(g for g in port_res["items"] if g["id"] == "pg-web")
            self.assertEqual(web_port["portList"], ["80", "443"])
            self.assertEqual(web_port["entryCount"], 2)

            mac_res = unwrap_ok(call_tool(server, "list_ip_groups", {"groupType": "mac"}))
            self.assertEqual(mac_res["count"], 1)
            self.assertEqual(mac_res["items"][0]["macAddressList"][0]["macAddress"], "AA-BB-CC-DD-EE-10")


class PhaseAGroupAndScheduleWriteTests(unittest.TestCase):
    def test_port_group_crud_acl_ref_block_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, _ctrl, _ = make_write_env(tmp)
            baseline = unwrap_ok(call_tool(server, "get_config_snapshot"))
            initial_ports = unwrap_ok(call_tool(server, "list_ip_groups", {"groupType": "port"}))["count"]

            # Create port group
            dry = unwrap_ok(call_tool(server, "upsert_port_group", {
                "name": "App-Ports",
                "ports": ["8080", "8443", "9000-9010"],
            }))
            self.assertTrue(dry["dryRun"])
            created = unwrap_ok(call_tool(server, "upsert_port_group", {
                "name": "App-Ports",
                "ports": ["8080", "8443", "9000-9010"],
                "dryRun": False,
                "confirm": dry["confirmToken"],
            }))
            self.assertTrue(created["applied"])
            pg_id = created["after"]["groupId"]

            # Update in-place by name
            dry_upd = unwrap_ok(call_tool(server, "upsert_port_group", {
                "name": "App-Ports",
                "ports": ["443", "8443"],
            }))
            upd = unwrap_ok(call_tool(server, "upsert_port_group", {
                "name": "App-Ports",
                "ports": ["443", "8443"],
                "dryRun": False,
                "confirm": dry_upd["confirmToken"],
            }))
            self.assertEqual(upd["after"]["portList"], ["443", "8443"])

            # Delete with rollback
            dry_del = unwrap_ok(call_tool(server, "delete_port_group", {"group": pg_id}))
            deleted = unwrap_ok(call_tool(server, "delete_port_group", {
                "group": pg_id,
                "dryRun": False,
                "confirm": dry_del["confirmToken"],
            }))
            self.assertTrue(deleted["applied"])
            self.assertEqual(unwrap_ok(call_tool(server, "list_ip_groups", {"groupType": "port"}))["count"], initial_ports)

            # Rollback the delete -> recreates the port group
            snap_id = Path(deleted["snapshot"]).name
            rb_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": snap_id}))
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": snap_id,
                "dryRun": False,
                "confirm": rb_dry["confirmToken"],
            }))
            restored = unwrap_ok(call_tool(server, "list_ip_groups", {"groupType": "port"}))
            self.assertEqual(restored["count"], initial_ports + 1)
            restored_app = next(g for g in restored["items"] if g["name"] == "App-Ports")
            self.assertEqual(restored_app["portList"], ["443", "8443"])

            # Clean up back to baseline & check snapshot diff has zero port-group drift
            restored_id = restored_app["id"]
            d2 = unwrap_ok(call_tool(server, "delete_port_group", {"group": restored_id}))
            unwrap_ok(call_tool(server, "delete_port_group", {
                "group": restored_id, "dryRun": False, "confirm": d2["confirmToken"],
            }))
            diff = unwrap_ok(call_tool(server, "diff_config_snapshots", {"baseline": baseline}))
            self.assertFalse(diff["hasChanges"])

    def test_mac_group_crud_normalization_acl_block_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)

            dry = unwrap_ok(call_tool(server, "upsert_mac_group", {
                "name": "Kiosk-MACs",
                "entries": [
                    "aa:bb:cc:11:22:33",
                    {"name": "kiosk-2", "mac": "aa-bb-cc-11-22-44"},
                ],
            }))
            created = unwrap_ok(call_tool(server, "upsert_mac_group", {
                "name": "Kiosk-MACs",
                "entries": [
                    "aa:bb:cc:11:22:33",
                    {"name": "kiosk-2", "mac": "aa-bb-cc-11-22-44"},
                ],
                "dryRun": False,
                "confirm": dry["confirmToken"],
            }))
            mg_id = created["after"]["groupId"]
            self.assertEqual(
                [e["macAddress"] for e in created["after"]["macAddressList"]],
                ["AA-BB-CC-11-22-33", "AA-BB-CC-11-22-44"],
            )

            # Referenced by an ACL -> delete must fail
            ctrl.acls.append({
                "id": "acl-mac-ref",
                "index": 9,
                "name": "Ref-MAC",
                "status": True,
                "policy": 0,
                "sourceType": 3,
                "sourceIds": [mg_id],
                "destinationType": 0,
                "destinationIds": ["net-mgmt-1"],
                "direction": {"lanToWan": True, "lanToLan": False},
            })
            blocked_del = call_tool(server, "delete_mac_group", {"group": mg_id})
            self.assertTrue(blocked_del["result"]["isError"])

            # Clear ACL ref, delete, then rollback create -> deletes created MAC group
            ctrl.acls = [a for a in ctrl.acls if a["id"] != "acl-mac-ref"]
            snap_create = Path(created["snapshot"]).name
            rb_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": snap_create}))
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": snap_create,
                "dryRun": False,
                "confirm": rb_dry["confirmToken"],
            }))
            self.assertEqual(unwrap_ok(call_tool(server, "list_ip_groups", {"groupType": "mac"}))["count"], 0)

    def test_schedule_crud_validation_acl_ref_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            baseline = unwrap_ok(call_tool(server, "get_config_snapshot"))

            # Reject custom mode with empty days
            bad = call_tool(server, "upsert_schedule", {
                "name": "Bad-Custom",
                "dayMode": "custom",
                "windows": [{"start": "09:00", "end": "17:00"}],
            })
            self.assertTrue(bad["result"]["isError"])

            # Create custom schedule
            dry = unwrap_ok(call_tool(server, "upsert_schedule", {
                "name": "Weekend-Backup",
                "dayMode": "custom",
                "days": ["sat", "sun"],
                "windows": [{"start": "01:00", "end": "05:30"}],
            }))
            created = unwrap_ok(call_tool(server, "upsert_schedule", {
                "name": "Weekend-Backup",
                "dayMode": "custom",
                "days": ["sat", "sun"],
                "windows": [{"start": "01:00", "end": "05:30"}],
                "dryRun": False,
                "confirm": dry["confirmToken"],
            }))
            sid = created["after"]["id"]
            self.assertTrue(created["after"]["daySat"])
            self.assertTrue(created["after"]["daySun"])
            self.assertFalse(created["after"]["dayMon"])
            sched_list = unwrap_ok(call_tool(server, "list_schedules"))
            created_proj = next(s for s in sched_list["items"] if s["id"] == sid)
            self.assertEqual(created_proj["days"], ["sat", "sun"])

            # Update to weekday & rename using scheduleId
            dry_upd = unwrap_ok(call_tool(server, "upsert_schedule", {
                "scheduleId": sid,
                "name": "Weekday-Evening",
                "dayMode": "weekday",
                "windows": [{"start": "18:00", "end": "22:00"}],
            }))
            upd = unwrap_ok(call_tool(server, "upsert_schedule", {
                "scheduleId": sid,
                "name": "Weekday-Evening",
                "dayMode": "weekday",
                "windows": [{"start": "18:00", "end": "22:00"}],
                "dryRun": False,
                "confirm": dry_upd["confirmToken"],
            }))
            self.assertEqual(upd["after"]["name"], "Weekday-Evening")

            # Block deletion if referenced by ACL
            ctrl.acls[0]["scheduleId"] = sid
            blocked = call_tool(server, "delete_schedule", {"schedule": sid})
            self.assertTrue(blocked["result"]["isError"])
            ctrl.acls[0].pop("scheduleId", None)

            # Delete & rollback
            dry_del = unwrap_ok(call_tool(server, "delete_schedule", {"schedule": sid}))
            deleted = unwrap_ok(call_tool(server, "delete_schedule", {
                "schedule": sid,
                "dryRun": False,
                "confirm": dry_del["confirmToken"],
            }))
            self.assertEqual(unwrap_ok(call_tool(server, "list_schedules"))["count"], 1)

            # Rollback the delete -> restores schedule
            rb1_snap = Path(deleted["snapshot"]).name
            rb1_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": rb1_snap}))
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": rb1_snap, "dryRun": False, "confirm": rb1_dry["confirmToken"],
            }))
            self.assertEqual(unwrap_ok(call_tool(server, "list_schedules"))["count"], 2)

            # Delete created schedule cleanly & verify baseline match
            d2 = unwrap_ok(call_tool(server, "delete_schedule", {"schedule": "Weekday-Evening"}))
            unwrap_ok(call_tool(server, "delete_schedule", {
                "schedule": "Weekday-Evening", "dryRun": False, "confirm": d2["confirmToken"],
            }))
            diff = unwrap_ok(call_tool(server, "diff_config_snapshots", {"baseline": baseline}))
            self.assertFalse(diff["hasChanges"])


class PhaseAActiveDiagnosticsAndReadOnlyTests(unittest.TestCase):
    def test_ping_traceroute_speedtest_and_cable_test_guards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)

            # Ping from gateway
            dry_ping = unwrap_ok(call_tool(server, "run_ping", {
                "deviceMac": "AA-BB-CC-00-00-01",
                "target": "1.1.1.1",
                "count": 3,
                "packetSize": 64,
            }))
            self.assertEqual(dry_ping["after"]["test"], "ping")
            res_ping = unwrap_ok(call_tool(server, "run_ping", {
                "deviceMac": "AA-BB-CC-00-00-01",
                "target": "1.1.1.1",
                "count": 3,
                "packetSize": 64,
                "dryRun": False,
                "confirm": dry_ping["confirmToken"],
            }))
            self.assertTrue(res_ping["applied"])
            self.assertEqual(ctrl.network_checks[-1]["test"], 0)
            self.assertEqual(ctrl.network_checks[-1]["deviceType"], 2)

            # Traceroute from AP (deviceType=0)
            dry_tr = unwrap_ok(call_tool(server, "run_traceroute", {
                "deviceMac": "AA-BB-CC-00-00-03",
                "target": "8.8.8.8",
            }))
            res_tr = unwrap_ok(call_tool(server, "run_traceroute", {
                "deviceMac": "AA-BB-CC-00-00-03",
                "target": "8.8.8.8",
                "dryRun": False,
                "confirm": dry_tr["confirmToken"],
            }))
            self.assertEqual(res_tr["after"]["deviceType"], "ap")
            self.assertEqual(ctrl.network_checks[-1]["deviceType"], 0)
            self.assertEqual(ctrl.network_checks[-1]["test"], 1)

            # Invalid target rejected
            bad_ping = call_tool(server, "run_ping", {
                "deviceMac": "AA-BB-CC-00-00-01",
                "target": "bad host name!",
            })
            self.assertTrue(bad_ping["result"]["isError"])

            # WAN speedtest
            dry_st = unwrap_ok(call_tool(server, "start_wan_speedtest", {"pure": True}))
            res_st = unwrap_ok(call_tool(server, "start_wan_speedtest", {
                "pure": True,
                "dryRun": False,
                "confirm": dry_st["confirmToken"],
            }))
            self.assertTrue(res_st["applied"])

            # Missing gateway blocks speedtest
            ctrl.has_gateway = False
            ctrl.devices = [d for d in ctrl.devices if d.get("type") != "gateway"]
            no_gw = call_tool(server, "start_wan_speedtest", {})
            self.assertTrue(no_gw["result"]["isError"])

            # Cable test on uplink port 17 refuses unless allowUplinkMutation=True
            blocked_ct = call_tool(server, "start_cable_test", {
                "deviceMac": "AA-BB-CC-00-00-02",
                "ports": [17],
            })
            self.assertTrue(blocked_ct["result"]["isError"])

            dry_ct = unwrap_ok(call_tool(server, "start_cable_test", {
                "deviceMac": "AA-BB-CC-00-00-02",
                "ports": [3],
            }))
            res_ct = unwrap_ok(call_tool(server, "start_cable_test", {
                "deviceMac": "AA-BB-CC-00-00-02",
                "ports": [3],
                "dryRun": False,
                "confirm": dry_ct["confirmToken"],
            }))
            self.assertTrue(res_ct["applied"])
            self.assertEqual(ctrl.cable_test_runs[-1]["ports"], [3])

    def test_read_only_mode_blocks_all_10_new_write_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True)
            write_calls = [
                ("upsert_port_group", {"name": "P", "ports": ["80"]}),
                ("delete_port_group", {"group": "pg1"}),
                ("upsert_mac_group", {"name": "M", "entries": ["AA-BB-CC-11-22-33"]}),
                ("delete_mac_group", {"group": "mg1"}),
                ("upsert_schedule", {"name": "S", "windows": [{"start": "09:00", "end": "17:00"}]}),
                ("delete_schedule", {"schedule": "sched-seed-1"}),
                ("run_ping", {"deviceMac": "AA-BB-CC-00-00-01", "target": "1.1.1.1"}),
                ("run_traceroute", {"deviceMac": "AA-BB-CC-00-00-01", "target": "1.1.1.1"}),
                ("start_wan_speedtest", {}),
                ("start_cable_test", {"deviceMac": "AA-BB-CC-00-00-02", "ports": [3]}),
            ]
            for name, args in write_calls:
                resp = call_tool(server, name, args)
                self.assertEqual(resp["error"]["code"], -32003, name)
            self.assertEqual(ctrl.requests, [])


if __name__ == "__main__":
    unittest.main()
