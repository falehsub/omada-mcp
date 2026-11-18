from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from write_harness import call_tool, make_write_env, unwrap_ok


class WriteIntegrityTests(unittest.TestCase):
    def test_confirmation_is_session_local_single_use_and_binds_payload(self):
        with tempfile.TemporaryDirectory() as root:
            server, _, controller, _ = make_write_env(root)
            other_server, _, _, _ = make_write_env(root)
            tool = "set_client_fixed_ip"
            args = {"mac": "AA-BB-CC-11-11-01", "ip": "192.168.20.55"}

            def apply(instance, token, **changes):
                return call_tool(instance, tool, {**args, **changes, "dryRun": False, "confirm": token})

            guessed = apply(server, "set_client_fixed_ip:aa:bb:cc:11:11:01")
            self.assertTrue(guessed["result"]["isError"])
            preview = unwrap_ok(call_tool(server, tool, args))["confirmToken"]
            self.assertTrue(apply(other_server, preview)["result"]["isError"])
            self.assertTrue(apply(server, preview, ip="192.168.20.56")["result"]["isError"])
            self.assertEqual(controller.write_request_count, 0)
            self.assertEqual(unwrap_ok(apply(server, preview))["outcome"], "verified")
            self.assertTrue(apply(server, preview)["result"]["isError"])
            self.assertEqual(controller.write_request_count, 1)

    def test_expiry_and_live_drift_require_a_new_preview(self):
        with tempfile.TemporaryDirectory() as root:
            server, client, controller, _ = make_write_env(root)
            now = [10.0]
            client._clock = lambda: now[0]
            tool = "set_client_fixed_ip"
            args = {"mac": "AA-BB-CC-11-11-01", "ip": "192.168.20.55"}

            def apply(token):
                return call_tool(server, tool, {**args, "dryRun": False, "confirm": token})["result"]

            token = unwrap_ok(call_tool(server, tool, args))["confirmToken"]
            now[0] += 301
            self.assertTrue(apply(token)["isError"])
            token = unwrap_ok(call_tool(server, tool, args))["confirmToken"]
            controller.clients[args["mac"]]["ipSetting"]["ip"] = "192.168.20.57"
            fault = apply(token)
            self.assertTrue(fault["isError"])
            self.assertIn("state changed", fault["content"][0]["text"])
            self.assertEqual(controller.write_request_count, 0)

    def test_ap_override_requires_the_requested_fields_to_change(self):
        with tempfile.TemporaryDirectory() as root:
            server, _, controller, _ = make_write_env(root)
            tool = "set_ap_ssid_overrides"
            args = {"mac": "AA-BB-CC-00-00-03", "overrides": [
                {"globalSsid": "CorpWiFi", "enable": True, "newSsid": "Lab-Override"},
            ]}
            endpoint = "eaps/AA-BB-CC-00-00-03/config/wlans"
            token = unwrap_ok(call_tool(server, tool, args))["confirmToken"]
            controller.silent_noop_for.add(("PUT", endpoint))
            result = call_tool(server, tool, {**args, "dryRun": False, "confirm": token})["result"]
            self.assertTrue(result["isError"])
            self.assertEqual(result["structuredContent"]["outcome"], "uncertain")

    def test_session_recovery_compares_ap_overrides_before_replay(self):
        with tempfile.TemporaryDirectory() as root:
            server, _, controller, _ = make_write_env(root)
            tool = "set_ap_ssid_overrides"
            args = {"mac": "AA-BB-CC-00-00-03", "overrides": [
                {"globalSsid": "CorpWiFi", "enable": True, "newSsid": "Lab-Override"},
            ]}
            token = unwrap_ok(call_tool(server, tool, args))["confirmToken"]
            rejected = []

            def expire_first_put(method, _path, _body):
                if method == "PUT" and not rejected:
                    rejected.append(method)
                    return 200, {"errorCode": -30109}
                return None

            controller.next_fault_hook = expire_first_put
            result = unwrap_ok(call_tool(server, tool, {**args, "dryRun": False, "confirm": token}))
            self.assertTrue(rejected)
            self.assertTrue(result["verified"])
            overrides = result["after"]["ssidOverrides"]
            self.assertTrue(any(row["ssid"] == "Lab-Override" for row in overrides))

    def test_audit_failure_preserves_verified_outcome(self):
        with tempfile.TemporaryDirectory() as root:
            server, client, controller, _ = make_write_env(root)
            tool = "set_client_fixed_ip"
            args = {"mac": "AA-BB-CC-11-11-01", "ip": "192.168.20.55"}
            token = unwrap_ok(call_tool(server, tool, args))["confirmToken"]
            with patch.object(client, "_append_audit", side_effect=OSError("injected audit failure")):
                applied = unwrap_ok(call_tool(server, tool, {**args, "dryRun": False, "confirm": token}))
            self.assertEqual(applied["outcome"], "verified")
            self.assertTrue(applied["verified"])
            self.assertTrue(applied["snapshot"])
            self.assertTrue(any("audit" in note.lower() for note in applied["warnings"]))
            self.assertEqual(controller.write_request_count, 1)

    def test_acknowledged_action_without_read_back_is_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            server, _, _, _ = make_write_env(root)
            tool = "reconnect_client"
            args = {"mac": "AA-BB-CC-11-11-02"}
            token = unwrap_ok(call_tool(server, tool, args))["confirmToken"]
            applied = unwrap_ok(call_tool(server, tool, {**args, "dryRun": False, "confirm": token}))
            self.assertTrue(applied["applied"])
            self.assertFalse(applied["verified"])
            self.assertEqual(applied["outcome"], "accepted")
