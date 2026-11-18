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
                {"status": 1, "status5g": 1, "channel5g": [{"channel": 36, "ssid": "Lab-Neighbor", "rssi": -65}]},
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
            self.assertEqual(len(applied["after"]["rfScan"]["channelsByBand"]["5g"]), 1)

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
