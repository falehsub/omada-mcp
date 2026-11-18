"""Offline verification of rollback ordering and interrupted IP-group swaps."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from write_harness import call_confirmed, call_tool, make_write_env, unwrap_ok

from omada_mcp.server import Server


class RecoveryTests(unittest.TestCase):
    def test_verified_rollback_unblocks_the_next_older_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            server, _, _, _ = make_write_env(directory)
            first = unwrap_ok(call_confirmed(server, "set_upnp", {"enable": True}))
            second = unwrap_ok(call_confirmed(server, "set_upnp", {"enable": False}))

            older = {"snapshotId": first["snapshot"]}
            blocked = call_tool(server, "rollback_from_snapshot", older)["result"]
            self.assertTrue(blocked["isError"])
            self.assertIn("stale snapshot", blocked["content"][0]["text"])

            unwrap_ok(call_confirmed(server, "rollback_from_snapshot", {"snapshotId": second["snapshot"]}))
            restored = unwrap_ok(call_confirmed(server, "rollback_from_snapshot", older))
            self.assertTrue(restored["verified"])
            self.assertFalse(restored["after"]["enable"])

    def test_restart_reconciles_created_temp_group_without_reissuing_post(self):
        with tempfile.TemporaryDirectory() as directory:
            server, client, controller, _ = make_write_env(directory)
            write = client.write

            def stop_after_create(endpoint, **kwargs):
                result = write(endpoint, **kwargs)
                if kwargs["method"] == "POST":
                    raise KeyboardInterrupt
                return result

            arguments = {"group": "lab-devices", "cidrs": ["198.51.100.16/28"]}
            with patch.object(client, "write", side_effect=stop_after_create), self.assertRaises(KeyboardInterrupt):
                call_confirmed(server, "replace_ip_group", arguments)

            journals = list(Path(directory).glob("ip-group-recovery/*.json"))
            self.assertEqual(len(journals), 1)
            recovery_id = json.loads(journals[0].read_text(encoding="utf-8"))["operationId"]
            restarted = Server(client.config, client=client)
            result = unwrap_ok(call_confirmed(restarted, "replace_ip_group", {
                "group": "lab-devices", "recoveryId": recovery_id,
            }))
            temp_posts = [req for req in controller.requests if req["method"] == "POST"
                          and str((req.get("body") or {}).get("name")).startswith("lab-devices__tmp")]
            self.assertEqual(len(temp_posts), 1)
            source_rule = next(row for row in controller.acls if row["id"] == "acl-002")
            self.assertEqual(source_rule["sourceIds"], [result["after"]["id"]])
            stale = call_tool(restarted, "replace_ip_group", {"group": "lab-devices", "recoveryId": recovery_id})
            self.assertTrue(stale["result"]["isError"])
            self.assertIn("already complete", stale["result"]["content"][0]["text"])

    def test_resume_retries_a_proven_pending_acl_step_and_refuses_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            server, client, controller, _ = make_write_env(directory)

            def fail_acl(method, path, body):
                if method == "PUT" and "/acls/acl-002" in path:
                    return 200, {"errorCode": -1600}
                return None

            controller.next_fault_hook = fail_acl
            reply = call_confirmed(server, "replace_ip_group", {
                "group": "lab-devices", "cidrs": ["198.51.100.16/28"],
            })["result"]
            self.assertTrue(reply["isError"])
            operation_id = reply["structuredContent"]["recoveryId"]
            args = {"group": "lab-devices", "recoveryId": operation_id}
            server = Server(client.config, client=client)
            controller.next_fault_hook = None
            source = next(row for row in controller.acls if row["id"] == "acl-002")
            previous_status = source["status"]
            source["status"] = not previous_status
            before = controller.write_request_count
            blocked = call_tool(server, "replace_ip_group", args)["result"]
            self.assertTrue(blocked["isError"])
            self.assertIn("changed outside the checkpoint", blocked["content"][0]["text"])
            self.assertEqual(controller.write_request_count, before)

            source["status"] = previous_status
            completed = unwrap_ok(call_confirmed(server, "replace_ip_group", args))
            self.assertTrue(completed["verified"])
            self.assertEqual(len(completed["steps"]), 6)
