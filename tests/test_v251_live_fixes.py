"""v2.5.1 regression tests for live Omada 6.3.0.45 findings."""

from __future__ import annotations

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

from omada_mcp.tools import TOOL_MAP  # noqa: E402


class V251LiveFixesTests(unittest.TestCase):
    def test_survey_wifi_and_start_rf_scan_tolerate_advancing_controller_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, ctrl, _ = make_write_env(tmp, read_only=False)

            tick = [1795024077535]
            ctrl.eap_rf_scan["AA-BB-CC-00-00-03"] = {"status": 1, "status5g": 1, "time": tick[0]}

            # Wrap ctrl.request so every GET .../tools/rfScan advances controller 'time'
            orig_request = ctrl.request

            def ticking_request(method: str, url: str, *args, **kwargs):
                res = orig_request(method, url, *args, **kwargs)
                if method == "GET" and "/tools/rfScan" in url:
                    tick[0] += 3437
                    ctrl.eap_rf_scan["AA-BB-CC-00-00-03"]["time"] = tick[0]
                return res

            ctrl.request = ticking_request

            pv = unwrap_ok(
                call_tool(server, "survey_wifi", {"deviceMac": "AA-BB-CC-00-00-03", "bands": ["5g"], "dryRun": True})
            )
            ctrl.rf_scan_post_poll_sequence = [
                {"status": 2, "status5g": 2, "channel5g": []},
                {
                    "status": 0,
                    "status5g": 0,
                    "time5g": 1795026269759,
                    "channel5g": [{"chan": 36, "chanWidth": 3, "inter": -95, "util": 0}],
                },
            ]
            applied = unwrap_ok(
                call_tool(
                    server,
                    "survey_wifi",
                    {
                        "deviceMac": "AA-BB-CC-00-00-03",
                        "bands": ["5g"],
                        "dryRun": False,
                        "confirm": pv["confirmToken"],
                    },
                )
            )
            self.assertTrue(applied["applied"])
            self.assertTrue(applied["verified"])
            self.assertEqual(applied["outcome"], "verified")
            self.assertEqual(applied["after"]["statusLabel"], "idle")
            self.assertFalse(applied["after"]["timedOut"])
            self.assertFalse(applied["after"]["scanning"])
            self.assertGreaterEqual(applied["after"]["polls"], 1)
            self.assertEqual(applied["after"]["channelCount"], 1)
            row_5g = applied["after"]["channelsByBand"]["5g"][0]
            self.assertEqual(row_5g["chanWidth"], 3)
            self.assertEqual(row_5g["chanWidthLabel"], "40MHz")
            self.assertEqual(len(applied["after"]["rfScan"]["channelsByBand"]["5g"]), 1)

            # Timeout while scanning proves trigger succeeded (verified=True) while scanCompleted=False + resumeHint
            pv_to = unwrap_ok(
                call_tool(
                    server,
                    "survey_wifi",
                    {
                        "deviceMac": "AA-BB-CC-00-00-03",
                        "bands": ["5g"],
                        "wait": True,
                        "timeoutSeconds": 3,
                        "pollIntervalSeconds": 2,
                        "dryRun": True,
                    },
                )
            )
            ctrl.rf_scan_post_poll_sequence = [{"status": 2, "status5g": 2, "channel5g": []}]
            timed_out_res = unwrap_ok(
                call_tool(
                    server,
                    "survey_wifi",
                    {
                        "deviceMac": "AA-BB-CC-00-00-03",
                        "bands": ["5g"],
                        "wait": True,
                        "timeoutSeconds": 3,
                        "pollIntervalSeconds": 2,
                        "dryRun": False,
                        "confirm": pv_to["confirmToken"],
                    },
                )
            )
            self.assertTrue(timed_out_res["applied"])
            self.assertTrue(timed_out_res["verified"])
            self.assertEqual(timed_out_res["outcome"], "verified")
            self.assertTrue(timed_out_res["after"]["triggerVerified"])
            self.assertFalse(timed_out_res["after"]["scanCompleted"])
            self.assertTrue(timed_out_res["after"]["timedOut"])
            self.assertIn("timeoutSeconds=600", timed_out_res["after"]["resumeHint"])
            self.assertNotIn("aa:bb:cc:00:00:03", timed_out_res["after"]["resumeHint"].lower())

            # timeoutSeconds=300 (beyond legacy 180s ceiling) completes a ~264s simulated 5 GHz scan cleanly
            ctrl.eap_rf_scan["AA-BB-CC-00-00-03"].update({"status": 1, "status5g": 1})
            pv_long = unwrap_ok(
                call_tool(
                    server,
                    "survey_wifi",
                    {
                        "deviceMac": "AA-BB-CC-00-00-03",
                        "bands": ["5g"],
                        "wait": True,
                        "timeoutSeconds": 300,
                        "pollIntervalSeconds": 30,
                        "dryRun": True,
                    },
                )
            )
            ctrl.rf_scan_post_poll_sequence = [
                *([{"status": 2, "status5g": 2, "channel5g": []}] * 9),
                {
                    "status": 0,
                    "status5g": 0,
                    "time5g": 1795029999999,
                    "channel5g": [{"chan": 36, "chanWidth": 2, "inter": -95, "util": 0}],
                },
            ]
            long_res = unwrap_ok(
                call_tool(
                    server,
                    "survey_wifi",
                    {
                        "deviceMac": "AA-BB-CC-00-00-03",
                        "bands": ["5g"],
                        "wait": True,
                        "timeoutSeconds": 300,
                        "pollIntervalSeconds": 30,
                        "dryRun": False,
                        "confirm": pv_long["confirmToken"],
                    },
                )
            )
            self.assertTrue(long_res["verified"])
            self.assertTrue(long_res["after"]["scanCompleted"])
            self.assertFalse(long_res["after"]["timedOut"])
            self.assertGreater(long_res["after"]["elapsedSeconds"], 180.0)
            self.assertEqual(long_res["after"]["channelsByBand"]["5g"][0]["chanWidthLabel"], "20MHz")

            # wait=False with unchanged idle timestamps reports accepted / verified=False
            ctrl.eap_rf_scan["AA-BB-CC-00-00-03"].update({"status": 0, "status5g": 0})
            pv_nw = unwrap_ok(
                call_tool(
                    server,
                    "survey_wifi",
                    {"deviceMac": "AA-BB-CC-00-00-03", "bands": ["5g"], "wait": False, "dryRun": True},
                )
            )
            ctrl.rf_scan_post_poll_sequence = []
            nw_res = unwrap_ok(
                call_tool(
                    server,
                    "survey_wifi",
                    {
                        "deviceMac": "AA-BB-CC-00-00-03",
                        "bands": ["5g"],
                        "wait": False,
                        "dryRun": False,
                        "confirm": pv_nw["confirmToken"],
                    },
                )
            )
            self.assertTrue(nw_res["applied"])
            self.assertFalse(nw_res["verified"])
            self.assertEqual(nw_res["outcome"], "accepted")
            self.assertFalse(nw_res["after"]["triggerVerified"])
            # Reset rf_scan state to completed before the raw-scan check below
            ctrl.eap_rf_scan["AA-BB-CC-00-00-03"].update({"status": 1, "status5g": 1})

            # Same stability for start_rf_scan when controller 'time' advances between preview and apply
            pv_raw = unwrap_ok(
                call_tool(server, "start_rf_scan", {"deviceMac": "AA-BB-CC-00-00-03", "bands": ["5g"], "dryRun": True})
            )
            applied_raw = unwrap_ok(
                call_tool(
                    server,
                    "start_rf_scan",
                    {
                        "deviceMac": "AA-BB-CC-00-00-03",
                        "bands": ["5g"],
                        "dryRun": False,
                        "confirm": pv_raw["confirmToken"],
                    },
                )
            )
            self.assertTrue(applied_raw["applied"])

            # Safety guard still blocks if an active scan (status=2) begins between preview and apply
            pv_blocked = unwrap_ok(
                call_tool(server, "survey_wifi", {"deviceMac": "AA-BB-CC-00-00-03", "bands": ["5g"], "dryRun": True})
            )
            ctrl.eap_rf_scan["AA-BB-CC-00-00-03"].update({"status": 2, "status5g": 2})
            blocked = call_tool(
                server,
                "survey_wifi",
                {
                    "deviceMac": "AA-BB-CC-00-00-03",
                    "bands": ["5g"],
                    "dryRun": False,
                    "confirm": pv_blocked["confirmToken"],
                },
            )
            self.assertTrue(blocked["result"]["isError"])
            self.assertIn("observed state changed", blocked["result"]["content"][0]["text"])

    def test_update_ssid_and_snapshot_preserve_enable_dict_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=False)
            raw_ssid = ctrl.ssids_by_group["wlan-grp-1"][0]
            raw_ssid.pop("loadBalance", None)
            raw_ssid.pop("condBroadcastCtrl", None)

            baseline = unwrap_ok(call_tool(server, "get_config_snapshot", {"objects": ["ssids"]}))

            # Omada 6.3+ materializes {"enable": False}
            raw_ssid["loadBalance"] = {"enable": False}
            raw_ssid["condBroadcastCtrl"] = {"enable": False}

            drift = unwrap_ok(call_tool(server, "diff_config_snapshots", {"baseline": baseline}))
            self.assertEqual(
                drift["sections"]["ssids"]["changed"][0]["materializedKeys"],
                ["condBroadcastCtrl", "loadBalance"],
            )

            detail = unwrap_ok(call_tool(server, "get_ssid", {"ssid": "Lab-Main", "wlanGroup": "Default"}))
            self.assertEqual(detail["loadBalance"], {"enable": False})
            self.assertEqual(detail["condBroadcastCtrl"], {"enable": False})

            pv = unwrap_ok(
                call_tool(
                    server,
                    "update_ssid",
                    {
                        "ssid": "Lab-Main",
                        "wlanGroup": "Default",
                        "loadBalance": True,
                        "condBroadcast": True,
                        "dryRun": True,
                    },
                )
            )
            self.assertEqual(pv["before"]["loadBalance"], {"enable": False})
            self.assertEqual(pv["after"]["loadBalance"], {"enable": True})
            self.assertEqual(pv["diff"]["loadBalance"], {"before": {"enable": False}, "after": {"enable": True}})

            applied = unwrap_ok(
                call_tool(
                    server,
                    "update_ssid",
                    {
                        "ssid": "Lab-Main",
                        "wlanGroup": "Default",
                        "loadBalance": True,
                        "condBroadcast": True,
                        "dryRun": False,
                        "confirm": pv["confirmToken"],
                    },
                )
            )
            self.assertTrue(applied["verified"])
            stored = ctrl.ssids_by_group["wlan-grp-1"][0]
            self.assertEqual(stored["loadBalance"], {"enable": True})
            self.assertEqual(stored["condBroadcastCtrl"], {"enable": True})

    def test_group_schemas_advertise_legacy_id_aliases(self):
        for tool_name in ("delete_ip_group", "replace_ip_group", "delete_port_group", "delete_mac_group"):
            props = TOOL_MAP[tool_name].input_schema["properties"]
            self.assertIn("id", props, f"{tool_name} should advertise 'id' alias")
            self.assertIn("groupId", props, f"{tool_name} should advertise 'groupId' alias")


if __name__ == "__main__":
    unittest.main()
