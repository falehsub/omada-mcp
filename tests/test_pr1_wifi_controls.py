"""PR 1 regression tests: get_ssid, expanded update_ssid, set_wifi_radio_features, wlans drift."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fake_controller import FakeController, make_config  # noqa: E402
from write_harness import call_tool, make_write_env, unwrap_ok  # noqa: E402

from omada_mcp.client import OmadaClient  # noqa: E402
from omada_mcp.server import Server  # noqa: E402


class Pr1WifiControlsTests(unittest.TestCase):
    def test_get_ssid_and_list_wlans_surface_steering_and_redact_psk(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, _ctrl, _ = make_write_env(tmp, read_only=True)

            wlans = unwrap_ok(call_tool(server, "list_wlans", {}))["items"]
            corp = next(w for w in wlans if w["name"] == "Lab-Main")
            self.assertEqual(corp["bandSteering"], "prefer_5g")
            self.assertEqual(corp["bandSteeringMode"], 1)
            self.assertFalse(corp["loadBalance"])
            self.assertEqual(corp["pmfMode"], 2)
            self.assertTrue(corp["enable11r"])
            self.assertTrue(corp["hasPresharedKey"])
            self.assertNotIn("synthetic-test-passphrase-never-leak", json.dumps(wlans))

            detail = unwrap_ok(call_tool(server, "get_ssid", {"ssid": "Lab-Main", "wlanGroup": "Default"}))
            self.assertEqual(detail["id"], "ssid-corp")
            self.assertEqual(detail["wlanId"], "wlan-grp-1")
            self.assertEqual(detail["bandSteering"], "prefer_5g")
            self.assertEqual(detail["bandSteeringMode"], 1)
            self.assertEqual(detail["pmfModeLabel"], "capable")
            self.assertFalse(detail["loadBalance"])
            self.assertFalse(detail["wifiCallingEnable"])
            self.assertFalse(detail["condBroadcastCtrl"])
            self.assertTrue(detail["hasPresharedKey"])
            self.assertNotIn("pskSetting", detail)
            self.assertNotIn("securityKey", detail)
            self.assertNotIn("synthetic-test-passphrase-never-leak", json.dumps(detail))

    def test_get_ssid_works_on_v5_flat_wlans_and_disambiguates_duplicates(self):
        fake = FakeController()
        cfg = make_config(read_only=True)
        client = OmadaClient(cfg, transport=fake, sleep=lambda _s: None, clock=lambda: 0.0, log_fn=lambda _m: None)
        server = Server(cfg, client=client)
        detail = unwrap_ok(call_tool(server, "get_ssid", {"ssid": "lab"}))
        self.assertEqual(detail["id"], "w1")
        self.assertTrue(detail["hasPresharedKey"])
        self.assertNotIn("super-secret-passphrase", json.dumps(detail))

        with tempfile.TemporaryDirectory() as tmp:
            server2, _c2, ctrl, _ = make_write_env(tmp, read_only=True)
            ctrl.wlans.append({"id": "wlan-grp-2", "name": "Branch"})
            dup = copy.deepcopy(ctrl.ssids_by_group["wlan-grp-1"][0])
            dup["id"] = "ssid-corp-branch"
            ctrl.ssids_by_group["wlan-grp-2"] = [dup]

            ambig = call_tool(server2, "get_ssid", {"ssid": "Lab-Main"})
            self.assertTrue(ambig["result"]["isError"])
            self.assertIn("matched multiple entries", ambig["result"]["content"][0]["text"])

            scoped = unwrap_ok(call_tool(server2, "get_ssid", {"ssid": "Lab-Main", "wlanGroup": "Branch"}))
            self.assertEqual(scoped["id"], "ssid-corp-branch")
            self.assertEqual(scoped["wlanId"], "wlan-grp-2")

    def test_update_ssid_steering_and_advanced_flags_verified_and_drift_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            snap_before = unwrap_ok(call_tool(server, "get_config_snapshot", {"objects": ["wlans"]}))

            preview = unwrap_ok(call_tool(server, "update_ssid", {
                "ssid": "Lab-Main",
                "wlanGroup": "Default",
                "bandSteering": "balanced",
                "loadBalance": True,
                "wifiCalling": True,
                "condBroadcast": True,
                "macFilterEnable": True,
                "rateLimitProfile": "Guest-10M",
                "schedule": "Work-Hours",
                "mloEnable": True,
            }))
            self.assertTrue(preview["dryRun"])
            self.assertEqual(preview["after"]["bandSteeringForMultiBand"], {"mode": 2})

            applied = unwrap_ok(call_tool(server, "update_ssid", {
                "ssid": "Lab-Main",
                "wlanGroup": "Default",
                "bandSteering": "balanced",
                "loadBalance": True,
                "wifiCalling": True,
                "condBroadcast": True,
                "macFilterEnable": True,
                "rateLimitProfile": "Guest-10M",
                "schedule": "Work-Hours",
                "mloEnable": True,
                "dryRun": False,
                "confirm": preview["confirmToken"],
            }))
            self.assertTrue(applied["verified"])
            self.assertEqual(applied["outcome"], "verified")

            detail = unwrap_ok(call_tool(server, "get_ssid", {"ssid": "Lab-Main", "wlanGroup": "Default"}))
            self.assertEqual(detail["bandSteering"], "balanced")
            self.assertEqual(detail["bandSteeringMode"], 2)
            self.assertTrue(detail["loadBalance"])
            self.assertTrue(detail["wifiCallingEnable"])
            self.assertTrue(detail["condBroadcastCtrl"])
            self.assertTrue(detail["macFilterEnable"])
            self.assertTrue(detail["rateLimitEnable"])
            self.assertEqual(detail["rateLimit"]["rateLimitProfileId"], "rl-prof-1")
            self.assertTrue(detail["wlanScheduleEnable"])
            self.assertEqual(detail["wlanScheduleId"], "sched-seed-1")
            self.assertTrue(detail["mloEnable"])

            # Snapshot drift must detect SSID-level config changes
            drift = unwrap_ok(call_tool(server, "diff_config_snapshots", {
                "baseline": snap_before,
                "objects": ["wlans"],
            }))
            self.assertTrue(drift["hasChanges"])
            self.assertGreater(len(drift["sections"]["wlans"]["changed"]), 0)
            changed_fields = drift["sections"]["wlans"]["changed"][0]["changes"]
            self.assertIn("bandSteering", changed_fields)
            self.assertIn("loadBalance", changed_fields)
            self.assertIn("wifiCallingEnable", changed_fields)
            self.assertIn("condBroadcastCtrl", changed_fields)

            # Silent ignore on bandSteeringForMultiBand must fail verification
            pv2 = unwrap_ok(call_tool(server, "update_ssid", {
                "ssid": "Lab-Main",
                "wlanGroup": "Default",
                "bandSteering": "disable",
            }))
            ctrl.silent_noop_for.add(("PATCH", "ssids/ssid-corp"))
            failed = call_tool(server, "update_ssid", {
                "ssid": "Lab-Main",
                "wlanGroup": "Default",
                "bandSteering": "disable",
                "dryRun": False,
                "confirm": pv2["confirmToken"],
            })
            self.assertTrue(failed["result"]["isError"])
            self.assertIn("verification failed", failed["result"]["content"][0]["text"].lower())

    def test_update_ssid_reauth_replays_when_session_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, ctrl, _ = make_write_env(tmp)
            client.authenticate()
            logins_before = ctrl.logins
            pv = unwrap_ok(call_tool(server, "update_ssid", {
                "ssid": "Lab-Main",
                "wlanGroup": "Default",
                "bandSteering": "balanced",
            }))
            ctrl.expired_once_for.add(("PATCH", "ssids/ssid-corp"))
            applied = unwrap_ok(call_tool(server, "update_ssid", {
                "ssid": "Lab-Main",
                "wlanGroup": "Default",
                "bandSteering": "balanced",
                "dryRun": False,
                "confirm": pv["confirmToken"],
            }))
            self.assertTrue(applied["verified"])
            self.assertGreater(ctrl.logins, logins_before)
            self.assertEqual(ctrl.ssids_by_group["wlan-grp-1"][0]["bandSteeringForMultiBand"]["mode"], 2)

    def test_set_wifi_radio_features_verify_fault_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            pv = unwrap_ok(call_tool(server, "set_wifi_radio_features", {
                "nonStickRoamingEnable": True,
                "aiRoamingEnable": True,
                "forceDisassociationEnable": True,
                "differenceThreshold": 15,
                "multiBandMode": "balanced",
                "atf2g": True,
            }))
            self.assertTrue(pv["dryRun"])
            self.assertTrue(pv["after"]["roaming"]["nonStickRoamingEnable"])
            self.assertEqual(pv["after"]["bandSteeringForMultiBand"]["mode"], 2)
            # Sibling fields preserved
            self.assertTrue(pv["after"]["roaming"]["fastRoamingEnable"])
            self.assertEqual(pv["after"]["bandSteering"]["connectionThreshold"], 10)

            applied = unwrap_ok(call_tool(server, "set_wifi_radio_features", {
                "nonStickRoamingEnable": True,
                "aiRoamingEnable": True,
                "forceDisassociationEnable": True,
                "differenceThreshold": 15,
                "multiBandMode": "balanced",
                "atf2g": True,
                "dryRun": False,
                "confirm": pv["confirmToken"],
            }))
            self.assertTrue(applied["verified"])
            snap_id = Path(applied["snapshot"]).name

            read_back = unwrap_ok(call_tool(server, "get_wifi_radio_features", {}))
            self.assertTrue(read_back["roaming"]["nonStickRoamingEnable"])
            self.assertTrue(read_back["roaming"]["aiRoamingEnable"])
            self.assertTrue(read_back["roaming"]["forceDisassociationEnable"])
            self.assertEqual(read_back["bandSteering"]["differenceThreshold"], 15)
            self.assertEqual(read_back["bandSteering"]["multiBandMode"], 2)
            self.assertTrue(read_back["airtimeFairness"]["enable2g"])

            # Rollback from snapshot restores previous settings
            rb_pv = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": snap_id}))
            rb_done = unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": snap_id,
                "dryRun": False,
                "confirm": rb_pv["confirmToken"],
            }))
            self.assertTrue(rb_done["verified"])

            reverted = unwrap_ok(call_tool(server, "get_wifi_radio_features", {}))
            self.assertFalse(reverted["roaming"]["nonStickRoamingEnable"])
            self.assertEqual(reverted["bandSteering"]["differenceThreshold"], 12)
            self.assertEqual(reverted["bandSteering"]["multiBandMode"], 1)

            # Silent ignore fault injection fails verification
            pv_fail = unwrap_ok(call_tool(server, "set_wifi_radio_features", {"nonStickRoamingEnable": True}))
            ctrl.silent_noop_for.add(("PATCH", "setting/wireless/feature"))
            err = call_tool(server, "set_wifi_radio_features", {
                "nonStickRoamingEnable": True,
                "dryRun": False,
                "confirm": pv_fail["confirmToken"],
            })
            self.assertTrue(err["result"]["isError"])
            self.assertIn("verification failed", err["result"]["content"][0]["text"].lower())


if __name__ == "__main__":
    unittest.main()
