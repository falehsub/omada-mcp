"""Offline regressions for hotspot credentials and public doctor reports."""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from write_harness import call_tool, make_write_env, unwrap_ok

from omada_mcp import cli
from omada_mcp.config import ConfigError
from omada_mcp.doctor import run_doctor

VOUCHER_CODE = "VoucherSecret07"
NESTED_SECRET = "HiddenVoucherSecret09"
REPORT_SECRET = "doctor-private-identifier"


class HotspotPrivacyTests(unittest.TestCase):
    def test_list_and_revoke_project_only_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            controller.vouchers[0].update({
                "code": VOUCHER_CODE,
                "voucherCode": VOUCHER_CODE,
                "details": {"activationCode": NESTED_SECRET},
                "status": {"credential": NESTED_SECRET},
            })
            controller.voucher_groups[0]["vouchers"] = [{"code": VOUCHER_CODE}]
            for arguments in ({}, {"groupId": "vg-seed-1"}):
                response = call_tool(server, "list_hotspot_vouchers", arguments)
                payload = unwrap_ok(response)
                self.assertEqual(payload["vouchers"], [{"id": "v-seed-1", "groupId": "vg-seed-1"}])
                self.assertEqual(payload["groups"][0]["name"], "Guest-Pass")
                self.assertNotIn(VOUCHER_CODE, json.dumps(response))
                self.assertNotIn(NESTED_SECRET, json.dumps(response))

            args = {"target": VOUCHER_CODE, "targetType": "voucher"}
            response = call_tool(server, "revoke_hotspot_voucher", args)
            dry = unwrap_ok(response)
            self.assertEqual(dry["before"], {"id": "v-seed-1", "groupId": "vg-seed-1"})
            self.assertNotIn(VOUCHER_CODE, json.dumps(response))
            self.assertNotIn(NESTED_SECRET, json.dumps(response))

            response = call_tool(server, "revoke_hotspot_voucher", {
                **args, "dryRun": False, "confirm": dry["confirmToken"],
            })
            committed = unwrap_ok(response)
            self.assertTrue(committed["verified"])
            self.assertEqual(controller.vouchers, [])
            self.assertNotIn(VOUCHER_CODE, json.dumps(response))
            for artifact in Path(tmp).iterdir():
                if artifact.is_file():
                    contents = artifact.read_text(encoding="utf-8")
                    self.assertNotIn(VOUCHER_CODE, contents)
                    self.assertNotIn(NESTED_SECRET, contents)

    def test_unknown_voucher_lookup_does_not_echo_the_submitted_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, _, _ = make_write_env(tmp)
            response = call_tool(server, "revoke_hotspot_voucher", {
                "target": VOUCHER_CODE, "targetType": "voucher",
            })
            self.assertTrue(response["result"]["isError"])
            self.assertNotIn(VOUCHER_CODE, json.dumps(response))

    def test_colliding_id_is_not_exposed_or_used_as_a_revoke_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            controller.vouchers[0].update(id=VOUCHER_CODE, code=VOUCHER_CODE)
            result = unwrap_ok(call_tool(server, "list_hotspot_vouchers", {}))
            self.assertNotIn("id", result["vouchers"][0])
            self.assertNotIn(VOUCHER_CODE, json.dumps(result))
            response = call_tool(server, "revoke_hotspot_voucher", {
                "target": VOUCHER_CODE, "targetType": "voucher",
            })
            self.assertTrue(response["result"]["isError"])
            self.assertNotIn(VOUCHER_CODE, json.dumps(response))

    def test_controller_error_text_remains_private_without_hiding_uncertain_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            controller.vouchers[0]["code"] = VOUCHER_CODE
            args = {"target": VOUCHER_CODE, "targetType": "voucher"}
            dry = unwrap_ok(call_tool(server, "revoke_hotspot_voucher", args))

            def fault(method, path, _body):
                if method == "DELETE" and path.partition("?")[0].endswith("/vouchers/v-seed-1"):
                    return 200, {"errorCode": -1001, "msg": VOUCHER_CODE}
                return None

            controller.next_fault_hook = fault
            response = call_tool(server, "revoke_hotspot_voucher", {
                **args, "dryRun": False, "confirm": dry["confirmToken"],
            })
            self.assertTrue(response["result"]["isError"])
            self.assertEqual(response["result"]["structuredContent"]["outcome"], "uncertain")
            self.assertNotIn(VOUCHER_CODE, json.dumps(response))
            self.assertNotIn(VOUCHER_CODE, (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8"))

    def test_an_incomplete_read_back_cannot_verify_voucher_deletion(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            args = {"target": "v-seed-1", "targetType": "voucher"}
            dry = unwrap_ok(call_tool(server, "revoke_hotspot_voucher", args))

            def fault(method, path, _body):
                if method == "GET" and path.partition("?")[0].endswith("/vouchers") and not controller.vouchers:
                    return 200, {"errorCode": 0, "result": {"data": [], "totalRows": 1}}
                return None

            controller.next_fault_hook = fault
            response = call_tool(server, "revoke_hotspot_voucher", {
                **args, "dryRun": False, "confirm": dry["confirmToken"],
            })
            self.assertTrue(response["result"]["isError"])
            self.assertEqual(response["result"]["structuredContent"]["outcome"], "uncertain")


class BackupAuditTests(unittest.TestCase):
    def test_verified_backup_is_reported_when_audit_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, controller, _ = make_write_env(tmp)
            dry = unwrap_ok(call_tool(server, "export_controller_backup", {}))
            self.assertIn("<utc-timestamp>", dry["after"]["outputPath"])
            with mock.patch.object(client, "_append_audit", side_effect=OSError(REPORT_SECRET)):
                response = call_tool(server, "export_controller_backup", {
                    "dryRun": False, "confirm": dry["confirmToken"],
                })
            committed = unwrap_ok(response)
            self.assertTrue(committed["verified"])
            self.assertTrue(committed["warnings"])
            raw = Path(committed["after"]["outputPath"]).read_bytes()
            self.assertEqual(raw, controller.backup_bytes)
            self.assertEqual(committed["after"]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertNotIn(REPORT_SECRET, json.dumps(response))


class DoctorShareSafeTests(unittest.TestCase):
    def test_share_safe_report_omits_success_identifiers_and_unexpected_firmware_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, client, _, _ = make_write_env(tmp, controller_url=f"https://{REPORT_SECRET}.invalid")
            stream = io.StringIO()
            with mock.patch.object(client, "controller_info", return_value={
                "omadacId": f"{REPORT_SECRET}-controller",
                "controllerVer": f"6.2.1-{REPORT_SECRET}",
            }):
                rc = run_doctor(config_factory=lambda: client.config, client_factory=lambda _: client,
                                stream=stream, share_safe=True)
            raw = stream.getvalue()
            report = json.loads(raw)
            self.assertEqual(rc, 0)
            self.assertTrue(report["shareSafe"])
            self.assertIsNone(report["controller"]["omadacId"])
            self.assertIsNone(report["controller"]["controllerVer"])
            self.assertEqual(report["controller"]["family"], "software-6.x")
            self.assertIsNone(report["site"])
            self.assertNotIn(REPORT_SECRET, raw)
            self.assertNotIn(client.config.username, raw)
            self.assertNotIn(str(tmp), raw)

    def test_share_safe_report_omits_failure_details_and_hints(self):
        def bad_config():
            raise ConfigError(f"could not read /private/{REPORT_SECRET}", hint=REPORT_SECRET)

        stream = io.StringIO()
        self.assertEqual(run_doctor(config_factory=bad_config, stream=stream, share_safe=True), 1)
        report = json.loads(stream.getvalue())
        self.assertEqual(report["phases"][0]["name"], "env")
        self.assertEqual(report["phases"][0]["status"], "FAIL")
        self.assertNotIn(REPORT_SECRET, stream.getvalue())

        stream = io.StringIO()
        self.assertEqual(run_doctor(config_factory=bad_config, stream=stream, json_output=True), 1)
        self.assertIn(REPORT_SECRET, stream.getvalue())

    def test_cli_routes_share_safe_to_doctor(self):
        with mock.patch.object(cli, "run_doctor", return_value=0) as doctor:
            self.assertEqual(cli.main(["--doctor", "--json", "--share-safe"]), 0)
        doctor.assert_called_once_with(json_output=True, share_safe=True)
