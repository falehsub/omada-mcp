"""Offline regressions for complete, credential-safe VPN and DDNS writes."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from write_harness import call_tool, make_write_env, unwrap_ok

KEY = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq="
PASSWORD = "ddns-private-password-test"


class VpnDdnsWriteVerificationTests(unittest.TestCase):
    def test_partial_peer_inventory_blocks_deleting_tunnel(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            controller.wireguard_configs.append({"id": "wg-1", "name": "edge"})

            def fault(method, path, _body):
                if method == "GET" and path.partition("?")[0].endswith("/wireguard/peer"):
                    return 200, {"errorCode": 0, "result": {"totalRows": 1, "data": []}}
                return None

            controller.next_fault_hook = fault
            response = call_tool(server, "delete_wireguard_tunnel", {"tunnel": "wg-1"})
            self.assertTrue(response["result"]["isError"])
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_tunnel_update_cannot_silently_regenerate_an_unreadable_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            controller.wireguard_configs.append({"id": "wg-1", "name": "edge", "privateKey": "********"})
            response = call_tool(server, "upsert_wireguard_tunnel", {
                "tunnelId": "wg-1", "name": "edge", "localIp": "192.0.2.1",
            })
            self.assertTrue(response["result"]["isError"])
            self.assertFalse(any("/wireguard/key" in request["path"] for request in controller.requests))

    def test_peer_readback_validates_requested_public_fields_without_echoing_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            controller.wireguard_configs.append({"id": "wg-1", "name": "edge"})
            controller.wireguard_peers.append({
                "id": "peer-1", "name": "laptop", "status": True, "interfaceId": "wg-1", "publicKey": KEY,
                "allowAddress": ["192.0.2.1/32"], "keepAlive": 25, "comment": "old comment",
            })
            args = {"peerId": "peer-1", "name": "laptop", "interface": "wg-1", "publicKey": KEY,
                    "allowAddress": ["192.0.2.2/32"], "keepAlive": 40}
            dry = unwrap_ok(call_tool(server, "upsert_wireguard_peer", args))
            controller.silent_noop_for.add(("PUT", "/setting/wireguard/peer/peer-1"))
            response = call_tool(server, "upsert_wireguard_peer", {
                **args, "dryRun": False, "confirm": dry["confirmToken"],
            })
            self.assertTrue(response["result"]["isError"])
            self.assertEqual(response["result"]["structuredContent"]["outcome"], "uncertain")
            self.assertNotIn("192.0.2.", json.dumps(response))

    def test_password_write_is_accepted_with_manual_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, _, _ = make_write_env(tmp)
            args = {"domainName": "lab.example.org", "username": "owner", "password": PASSWORD}
            dry = unwrap_ok(call_tool(server, "upsert_ddns", args))
            self.assertTrue(dry["manualRecoveryRequired"])
            committed = unwrap_ok(call_tool(server, "upsert_ddns", {
                **args, "dryRun": False, "confirm": dry["confirmToken"],
            }))
            self.assertEqual(committed["outcome"], "accepted")
            self.assertFalse(committed["verified"])
            self.assertTrue(committed["manualRecoveryRequired"])
            self.assertNotIn(PASSWORD, json.dumps((dry, committed)))
            snapshot = json.loads((Path(tmp) / committed["snapshot"]).read_text(encoding="utf-8"))
            self.assertTrue(snapshot["data"]["manualRecoveryRequired"])
            self.assertNotIn(PASSWORD, json.dumps(snapshot))

    def test_ddns_interface_and_username_must_match_nonsecret_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            controller.ddns["data"] = [{
                "id": "ddns-1", "domainName": "lab.example.org", "service": 0, "status": True,
                "interfacePortId": "wan-port-1", "username": "old-owner", "updateInterval": 12,
                "password": PASSWORD,
            }]
            args = {"ddnsId": "ddns-1", "domainName": "lab.example.org", "username": "new-owner",
                    "interface": "wan-port-1"}
            dry = unwrap_ok(call_tool(server, "upsert_ddns", args))
            controller.silent_noop_for.add(("PUT", "/setting/service/ddns/ddns-1"))
            response = call_tool(server, "upsert_ddns", {
                **args, "dryRun": False, "confirm": dry["confirmToken"],
            })
            self.assertTrue(response["result"]["isError"])
            self.assertNotIn("old-owner", json.dumps(response))
            self.assertNotIn(PASSWORD, json.dumps(response))

            controller.silent_noop_for.clear()
            dry = unwrap_ok(call_tool(server, "upsert_ddns", args))

            def fault(method, path, body):
                if method == "PUT" and path.partition("?")[0].endswith("/ddns/ddns-1"):
                    controller.ddns["data"][0].update(body, interfacePortId="unexpected-port")
                    return 200, {"errorCode": 0, "result": {}}
                return None

            controller.next_fault_hook = fault
            response = call_tool(server, "upsert_ddns", {
                **args, "dryRun": False, "confirm": dry["confirmToken"],
            })
            self.assertTrue(response["result"]["isError"])
            self.assertNotIn("unexpected-port", json.dumps(response))

            controller.next_fault_hook = None
            dry = unwrap_ok(call_tool(server, "upsert_ddns", args))
            committed = unwrap_ok(call_tool(server, "upsert_ddns", {
                **args, "dryRun": False, "confirm": dry["confirmToken"],
            }))
            self.assertTrue(committed["verified"])
            self.assertEqual(committed["outcome"], "verified")
            self.assertEqual(controller.ddns["data"][0]["password"], PASSWORD)

    def test_wireguard_credential_updates_require_manual_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, _, _ = make_write_env(tmp)
            tunnel_args = {"name": "edge", "localIp": "192.0.2.1", "privateKey": KEY}
            dry = unwrap_ok(call_tool(server, "upsert_wireguard_tunnel", tunnel_args))
            tunnel = unwrap_ok(call_tool(server, "upsert_wireguard_tunnel", {
                **tunnel_args, "dryRun": False, "confirm": dry["confirmToken"],
            }))
            self.assertEqual(tunnel["outcome"], "accepted")
            self.assertTrue(tunnel["manualRecoveryRequired"])
            self.assertNotIn(KEY, json.dumps(tunnel))

            peer_args = {"name": "laptop", "interface": tunnel["target"],
                         "publicKey": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg=",
                         "allowAddress": ["192.0.2.2/32"], "presharedKey": KEY}
            dry = unwrap_ok(call_tool(server, "upsert_wireguard_peer", peer_args))
            peer = unwrap_ok(call_tool(server, "upsert_wireguard_peer", {
                **peer_args, "dryRun": False, "confirm": dry["confirmToken"],
            }))
            self.assertEqual(peer["outcome"], "accepted")
            self.assertTrue(peer["manualRecoveryRequired"])
            self.assertNotIn(KEY, json.dumps(peer))
