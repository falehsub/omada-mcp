"""PR 2 regression tests: get_rf_scan key parsing, bounded polling, and impact-aware survey_wifi."""

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


class Pr2RfSurveyTests(unittest.TestCase):
    def test_get_rf_scan_parses_real_controller_band_keys_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True)
            ctrl.eap_rf_scan["AA-BB-CC-00-00-03"] = {
                "status2g": 1,
                "status5g": 2,
                "status6g": 0,
                "time5g": 1700000123,
                "channel2g": [
                    {"channel": 1, "bssid": "10:11:12:13:14:15", "ssid": "Neighbor-2G", "rssi": -68, "utilization": 42},
                ],
                "channel5g2": [
                    {"channel": 149, "bssid": "20:21:22:23:24:25", "ssid": "Neighbor-5G2", "rssi": -74, "utilization": 18},
                ],
                "channel6g": [],
            }

            res = unwrap_ok(call_tool(server, "get_rf_scan", {"mac": "AA-BB-CC-00-00-03"}))
            self.assertEqual(res["statusLabel"], "scanning")
            self.assertEqual(res["bandStatusLabels"], {"2g": "completed", "5g": "scanning", "6g": "idle"})
            self.assertEqual(res["bandTimes"], {"5g": 1700000123})
            self.assertEqual(len(res["channels"]), 2)
            self.assertEqual(res["channels"][0]["band"], "2g")
            self.assertEqual(res["channels"][0]["ssid"], "Neighbor-2G")
            self.assertEqual(res["channels"][1]["band"], "5g2")
            self.assertEqual(res["channels"][1]["channel"], 149)
            self.assertIn("2g", res["channelsByBand"])
            self.assertIn("5g2", res["channelsByBand"])
            self.assertFalse(res["timedOut"])

    def test_get_rf_scan_wait_polls_to_completion_and_handles_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, ctrl, _ = make_write_env(tmp, read_only=True)
            now = [1000.0]

            def fake_sleep(dt: float) -> None:
                now[0] += max(0.0, float(dt))

            client._clock = lambda: now[0]
            client._sleep = fake_sleep

            # First read returns scanning (2), second read returns completed (1) with 2.4 GHz row
            ctrl.rf_scan_poll_sequence = [
                {"status": 2, "status2g": 2, "channel2g": []},
                {
                    "status": 1,
                    "status2g": 1,
                    "time2g": 1700000999,
                    "channel2g": [{"channel": 6, "ssid": "AP-NextDoor", "rssi": -61}],
                },
            ]
            done = unwrap_ok(
                call_tool(
                    server,
                    "get_rf_scan",
                    {"mac": "AA-BB-CC-00-00-03", "wait": True, "timeoutSeconds": 20, "pollIntervalSeconds": 2},
                )
            )
            self.assertFalse(done["timedOut"])
            self.assertEqual(done["status"], 1)
            self.assertEqual(done["statusLabel"], "completed")
            self.assertEqual(len(done["channels"]), 1)
            self.assertEqual(done["channels"][0]["ssid"], "AP-NextDoor")
            self.assertGreater(now[0], 1000.0)

            # Now simulate stuck scanning (status=2) until timeout
            ctrl.rf_scan_poll_sequence = []
            ctrl.eap_rf_scan["AA-BB-CC-00-00-03"] = {"status": 2, "status5g": 2, "channel5g": []}
            timed_out = unwrap_ok(
                call_tool(
                    server,
                    "get_rf_scan",
                    {"mac": "AA-BB-CC-00-00-03", "wait": True, "timeoutSeconds": 5, "pollIntervalSeconds": 2},
                )
            )
            self.assertTrue(timed_out["timedOut"])
            self.assertEqual(timed_out["statusLabel"], "scanning")

    def test_survey_wifi_preview_reports_client_impact_and_applies_with_polling(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, ctrl, _ = make_write_env(tmp, read_only=False)
            now = [2000.0]

            def fake_sleep(dt: float) -> None:
                now[0] += max(0.0, float(dt))

            client._clock = lambda: now[0]
            client._sleep = fake_sleep

            # Place two clients on 5G (radioId 1) and one client on 2G (radioId 0) on AP ...03
            ctrl.clients["AA-BB-CC-11-11-01"].update({"wireless": True, "apMac": "AA-BB-CC-00-00-03", "radioId": 1, "active": True})
            ctrl.clients["AA-BB-CC-11-11-02"].update({"wireless": True, "apMac": "AA-BB-CC-00-00-03", "radioId": 1, "active": True})
            ctrl.clients["AA-BB-CC-11-11-03"].update({"wireless": True, "apMac": "AA-BB-CC-00-00-03", "radioId": 0, "active": True})
            ctrl.eap_rf_scan["AA-BB-CC-00-00-03"] = {"status": 0, "status5g": 0}

            preview = unwrap_ok(
                call_tool(
                    server,
                    "survey_wifi",
                    {"deviceMac": "AA-BB-CC-00-00-03", "bands": ["5g"], "wait": True, "timeoutSeconds": 20, "pollIntervalSeconds": 2, "dryRun": True},
                )
            )
            self.assertTrue(preview["dryRun"])
            self.assertEqual(preview["after"]["radioIdList"], [1])
            impact = preview["after"]["impact"]
            self.assertTrue(impact["impactKnown"])
            self.assertEqual(impact["totalAffectedClients"], 2)
            self.assertEqual(impact["affectedClientsByBand"], {"5g": 2})
            self.assertTrue(any("disconnect 2 client(s)" in w for w in preview["warnings"]))

            # Also check start_rf_scan surfaces the same impact in its preview
            raw_scan_preview = unwrap_ok(
                call_tool(server, "start_rf_scan", {"deviceMac": "AA-BB-CC-00-00-03", "bands": ["2g"], "dryRun": True})
            )
            self.assertTrue(raw_scan_preview["after"]["impact"]["impactKnown"])
            self.assertEqual(raw_scan_preview["after"]["impact"]["totalAffectedClients"], 1)
            self.assertEqual(raw_scan_preview["after"]["impact"]["affectedClientsByBand"], {"2g": 1})

            # Execute survey_wifi dryRun=False and verify polling yields decoded band results
            ctrl.rf_scan_post_poll_sequence = [
                {"status": 2, "status5g": 2, "channel5g": []},
                {
                    "status": 1,
                    "status5g": 1,
                    "time5g": 1700001111,
                    "channel5g": [{"channel": 36, "ssid": "Adjacent-5G", "rssi": -70}],
                },
            ]
            applied = unwrap_ok(
                call_tool(
                    server,
                    "survey_wifi",
                    {
                        "deviceMac": "AA-BB-CC-00-00-03",
                        "bands": ["5g"],
                        "wait": True,
                        "timeoutSeconds": 20,
                        "pollIntervalSeconds": 2,
                        "dryRun": False,
                        "confirm": preview["confirmToken"],
                    },
                )
            )
            self.assertTrue(applied["applied"])
            rf_out = applied["after"]["rfScan"]
            self.assertFalse(rf_out["timedOut"])
            self.assertEqual(ctrl.eap_rf_scan["AA-BB-CC-00-00-03"]["lastRadioIdList"], [1])
            self.assertEqual(rf_out["statusLabel"], "completed")
            self.assertEqual(len(rf_out["channelsByBand"]["5g"]), 1)

    def test_survey_wifi_marks_impact_unknown_when_client_telemetry_lacks_radio_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=False)
            for row in ctrl.clients.values():
                row.pop("radioId", None)
                row.pop("apMac", None)
                row.pop("apName", None)

            preview = unwrap_ok(
                call_tool(server, "survey_wifi", {"deviceMac": "AA-BB-CC-00-00-03", "bands": ["2g"], "dryRun": True})
            )
            impact = preview["after"]["impact"]
            self.assertFalse(impact["impactKnown"])
            self.assertIsNone(impact["totalAffectedClients"])
            self.assertTrue(any("disconnect impact is unknown" in w for w in preview["warnings"]))


if __name__ == "__main__":
    unittest.main()
