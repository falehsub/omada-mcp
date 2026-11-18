"""Scope, live safety, and verification tests for controller snapshot rollback."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from write_harness import call_confirmed, call_tool, make_write_env, unwrap_ok


def _apply(server, tool, arguments):
    return unwrap_ok(call_confirmed(server, tool, arguments))


class RollbackSafetyTests(unittest.TestCase):
    def assert_tool_error(self, response, detail):
        result = response["result"]
        self.assertTrue(result["isError"], result)
        self.assertIn(detail, result["content"][0]["text"])

    def test_snapshot_is_bound_to_controller_and_site_even_with_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, first_client, first_controller, _ = make_write_env(tmp, controller_url="https://192.0.2.1:8043")
            first_controller.sites.append({"id": "synthetic-other-site", "name": "Other test site"})
            changed = _apply(first, "set_upnp", {"enable": True})
            snapshot_id = changed["snapshot"]
            snapshot_path = Path(tmp) / snapshot_id
            envelope = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertEqual(envelope["version"], 2)
            self.assertEqual(envelope["siteId"], first_client.current_site().site_id)
            self.assertEqual(envelope["controllerId"], first_client.controller_id)
            self.assertTrue(envelope["resource"]["kind"])
            self.assertTrue(envelope["resource"]["id"])

            arguments = {"snapshotId": snapshot_id, "force": True}
            original_writes = first_controller.write_request_count
            self.assert_tool_error(call_tool(first, "rollback_from_snapshot", {
                **arguments, "site": "Other test site",
            }), "does not belong to the active controller and site")
            self.assertEqual(first_controller.write_request_count, original_writes)

            other, _, other_controller, _ = make_write_env(tmp, controller_url="https://192.0.2.2:8043")
            self.assert_tool_error(call_tool(other, "rollback_from_snapshot", arguments),
                                   "does not belong to the active controller and site")
            self.assertEqual(other_controller.write_request_count, 0)

            envelope["controllerId"] = "synthetic-different-controller-id"
            snapshot_path.write_text(json.dumps(envelope), encoding="utf-8")
            self.assert_tool_error(call_tool(first, "rollback_from_snapshot", arguments),
                                   "does not belong to the active controller and site")
            self.assertEqual(first_controller.write_request_count, original_writes)

    def test_legacy_snapshot_can_preview_but_cannot_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            snapshot_path = Path(tmp) / "legacy-upnp.json"
            snapshot_path.write_text(json.dumps({"tool": "set_upnp", "target": "legacy-site", "data": {"enable": False}}),
                                     encoding="utf-8")
            arguments = {"snapshotId": snapshot_path.name, "force": True}
            preview = unwrap_ok(call_tool(server, "rollback_from_snapshot", arguments))
            self.assertTrue(any("preview-only" in warning for warning in preview["warnings"]))
            self.assert_tool_error(call_tool(server, "rollback_from_snapshot", {
                **arguments, "dryRun": False, "confirm": preview["confirmToken"],
            }), "preview-only")
            self.assertEqual(controller.write_request_count, 0)

    def test_switch_restore_rechecks_new_uplink_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            changed = _apply(server, "update_switch_port", {
                "deviceMac": "sw-access", "port": 4, "enabled": False,
            })
            original_writes = controller.write_request_count
            arguments = {"snapshotId": changed["snapshot"], "force": True}
            preview = unwrap_ok(call_tool(server, "rollback_from_snapshot", arguments))
            evidence = {"ports": [{"port": 4, "isUplink": True, "safetyEvidenceComplete": True}]}
            with patch("omada_mcp.domains.rollback.collect_switch_ports_data", return_value=evidence):
                self.assert_tool_error(call_tool(server, "rollback_from_snapshot", {
                    **arguments, "dryRun": False, "confirm": preview["confirmToken"],
                }), "uplink")
            self.assertEqual(controller.write_request_count, original_writes)

    def test_undo_lan_create_cannot_delete_newly_protected_management_subnet(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, controller, _ = make_write_env(tmp)
            lan = _apply(server, "create_lan_network", {
                "name": "Protected lab LAN", "vlan": 88, "purpose": "interface", "gatewaySubnet": "198.51.100.1/24",
            })
            arguments = {"snapshotId": lan["snapshot"], "force": True}
            preview = unwrap_ok(call_tool(server, "rollback_from_snapshot", arguments))
            self.assertEqual(preview["diff"]["state"]["before"]["name"], "Protected lab LAN")
            client.config = replace(client.config, management_cidrs=("198.51.100.200/32",))
            original_writes = controller.write_request_count
            self.assert_tool_error(call_tool(server, "rollback_from_snapshot", {
                **arguments, "dryRun": False, "confirm": preview["confirmToken"],
            }), "overlaps management range")
            self.assertEqual(controller.write_request_count, original_writes)

    def test_pure_vlan_creation_can_be_rolled_back_without_interface(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            created = _apply(server, "create_lan_network", {"name": "Standalone lab VLAN", "vlan": 88, "purpose": "vlan"})
            self.assertFalse(any(row["vlan"] == 88 for row in controller.lan_interfaces))
            restored = _apply(server, "rollback_from_snapshot", {"snapshotId": created["snapshot"]})
            self.assertTrue(restored["verified"])
            self.assertFalse(any(row["vlan"] == 88 for row in controller.lan_collection))

    def test_lan_restore_rejects_unchanged_config_and_preserves_unrelated_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            interface = next(row for row in controller.lan_interfaces if row["vlan"] == 20)
            original_name, net_id = interface["name"], interface["id"]
            changed = _apply(server, "update_lan_network", {"netId": net_id, "name": "Temporary lab LAN"})
            interface = next(row for row in controller.lan_interfaces if row["id"] == net_id)
            interface["igmpSnoopEnable"] = True
            arguments = {"snapshotId": changed["snapshot"]}
            preview = unwrap_ok(call_tool(server, "rollback_from_snapshot", arguments))
            controller.silent_noop_for.add(("PATCH", f"setting/lan/networks/{net_id}"))
            result = call_tool(server, "rollback_from_snapshot", {
                **arguments, "dryRun": False, "confirm": preview["confirmToken"],
            })
            self.assert_tool_error(result, "write verification failed")

            controller.silent_noop_for.clear()
            restored = _apply(server, "rollback_from_snapshot", arguments)
            self.assertEqual(restored["after"]["interface"]["name"], original_name)
            self.assertIs(restored["after"]["interface"]["igmpSnoopEnable"], True)


if __name__ == "__main__":
    unittest.main()
