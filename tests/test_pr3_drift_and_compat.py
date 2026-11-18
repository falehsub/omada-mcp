"""PR 3 regression tests: ssids snapshot/drift, UI-materialized defaults, and argument aliases."""

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

from write_harness import call_tool, make_write_env, unwrap_ok  # noqa: E402


class Pr3DriftAndCompatTests(unittest.TestCase):
    def test_ssids_snapshot_captures_full_non_secret_config_and_ignores_timestamp_noise(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, _ctrl, _ = make_write_env(tmp, read_only=True)
            snap1 = unwrap_ok(call_tool(server, "get_config_snapshot", {"objects": ["ssids", "wirelessFeature"]}))
            self.assertRegex(snap1["capturedAt"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
            self.assertEqual(snap1["sectionStatus"]["ssids"]["status"], "ok")
            self.assertEqual(snap1["sectionStatus"]["wirelessFeature"]["status"], "ok")

            corp = next(s for s in snap1["ssids"] if s["name"] == "Lab-Main")
            self.assertEqual(corp["bandSteering"], "prefer_5g")
            self.assertEqual(corp["bandSteeringForMultiBand"], {"mode": 1})
            self.assertIn("vlanSetting", corp)
            self.assertTrue(corp["hasPresharedKey"])
            self.assertNotIn("synthetic-test-passphrase-never-leak", json.dumps(snap1))

            snap2 = copy.deepcopy(snap1)
            snap2["capturedAt"] = "2099-01-01T00:00:00Z"
            no_diff = unwrap_ok(call_tool(server, "diff_config_snapshots", {"baseline": snap1, "current": snap2}))
            self.assertFalse(no_diff["hasChanges"])
            self.assertEqual(no_diff["baselineCapturedAt"], snap1["capturedAt"])
            self.assertEqual(no_diff["currentCapturedAt"], "2099-01-01T00:00:00Z")

    def test_live_diff_detects_ui_ssid_edit_and_materialized_default_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True)
            # Remove optional flags on baseline SSID so baseline matches pre-UI-save firmware output
            raw_ssid = ctrl.ssids_by_group["wlan-grp-1"][0]
            for key in ("loadBalance", "wifiCallingEnable", "condBroadcastCtrl"):
                raw_ssid.pop(key, None)

            baseline = unwrap_ok(call_tool(server, "get_config_snapshot", {"objects": ["ssids", "wirelessFeature"]}))

            # Simulate out-of-band UI edit: sets balanced steering, rate limit, AND materializes explicit false keys
            raw_ssid["bandSteeringForMultiBand"] = {"mode": 2}
            raw_ssid["loadBalance"] = False
            raw_ssid["wifiCallingEnable"] = False
            raw_ssid["condBroadcastCtrl"] = False
            raw_ssid["rateLimitEnable"] = True
            raw_ssid["rateLimit"] = {"enable": True, "rateLimitProfileId": "rl-prof-1"}
            ctrl.wireless_feature["roaming"]["nonStickRoamingEnable"] = True

            drift = unwrap_ok(call_tool(server, "diff_config_snapshots", {"baseline": baseline}))
            self.assertEqual(drift["comparedSource"], "live")
            self.assertTrue(drift["hasChanges"])

            ssid_changed = drift["sections"]["ssids"]["changed"][0]
            self.assertEqual(ssid_changed["changes"]["bandSteering"]["before"], "prefer_5g")
            self.assertEqual(ssid_changed["changes"]["bandSteering"]["after"], "balanced")
            self.assertEqual(ssid_changed["changes"]["rateLimit"]["after"]["rateLimitProfileId"], "rl-prof-1")
            self.assertEqual(ssid_changed["changes"]["loadBalance"], {"before": None, "after": False})
            self.assertEqual(
                ssid_changed["materializedKeys"],
                ["condBroadcastCtrl", "loadBalance", "wifiCallingEnable"],
            )
            self.assertEqual(len(drift["materializedDefaults"]), 1)
            self.assertEqual(drift["materializedDefaults"][0]["section"], "ssids")
            self.assertEqual(
                drift["materializedDefaults"][0]["fields"],
                ["condBroadcastCtrl", "loadBalance", "wifiCallingEnable"],
            )

            wf_changes = drift["sections"]["wirelessFeature"]["changed"][0]["changes"]
            self.assertEqual(wf_changes["roaming.nonStickRoamingEnable"], {"before": False, "after": True})

    def test_legacy_group_argument_aliases_on_group_delete_and_replace_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Create a fresh unreferenced IP group to delete cleanly via legacy id= alias
            create_pv = unwrap_ok(
                call_tool(server, "create_ip_group", {"name": "Legacy-Alias-Grp", "cidrs": ["10.77.0.0/24"]})
            )
            created = unwrap_ok(
                call_tool(
                    server,
                    "create_ip_group",
                    {
                        "name": "Legacy-Alias-Grp",
                        "cidrs": ["10.77.0.0/24"],
                        "dryRun": False,
                        "confirm": create_pv["confirmToken"],
                    },
                )
            )
            gid = created["after"]["groupId"]

            # Conflicting alias vs canonical group rejects before controller I/O
            conflict = call_tool(server, "delete_ip_group", {"id": gid, "group": "other-id"})
            self.assertIn("error", conflict)
            self.assertIn("conflicting arguments", conflict["error"]["message"])

            # Preview via id= and apply via id= succeeds and binds confirmation identically
            del_pv = unwrap_ok(call_tool(server, "delete_ip_group", {"id": gid}))
            self.assertEqual(del_pv["target"], gid)
            del_ok = unwrap_ok(
                call_tool(
                    server,
                    "delete_ip_group",
                    {"group": gid, "dryRun": False, "confirm": del_pv["confirmToken"]},
                )
            )
            self.assertTrue(del_ok["verified"])
            self.assertFalse(any(g.get("id") == gid or g.get("groupId") == gid for g in ctrl.groups))

            # Port & MAC group deletes also accept id= / groupId=
            pg_id = next(g.get("id") or g.get("groupId") for g in ctrl.groups if g.get("type") == 1)
            ctrl.groups.append({
                "groupId": "grp-mac-alias-test",
                "name": "Alias-Macs",
                "type": 2,
                "macList": [{"mac": "AA:BB:CC:22:33:44", "description": "alias"}],
            })
            mg_id = "grp-mac-alias-test"
            pg_pv = unwrap_ok(call_tool(server, "delete_port_group", {"groupId": pg_id}))
            mg_pv = unwrap_ok(call_tool(server, "delete_mac_group", {"id": mg_id}))
            self.assertEqual(pg_pv["target"], pg_id)
            self.assertEqual(mg_pv["target"], mg_id)


if __name__ == "__main__":
    unittest.main()
