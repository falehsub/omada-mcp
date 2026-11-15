"""Phase C test coverage: VPN/WireGuard/DDNS, routing/QoS, backups, hotspot & fleet."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from mock_controller import MockController  # noqa: E402
from write_harness import call_tool, make_write_config, make_write_env, unwrap_ok  # noqa: E402

from omada_mcp.client import OmadaClient, OmadaError  # noqa: E402
from omada_mcp.config import _READ_ONLY_TOOL_NAMES, WRITE_TOOL_NAMES, load_config  # noqa: E402
from omada_mcp.domains._common import mask_ipv4_middle  # noqa: E402
from omada_mcp.server import Server  # noqa: E402

VALID_KEY_A = "K7s8fJ2kLmNoPqRsTuVwXyZ0123456789abcdef012A="
VALID_KEY_B = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1V="
VALID_PSK = "P9s8fJ2kLmNoPqRsTuVwXyZ0123456789abcdef012A="
SECRET_DDNS = "ddns-super-secret-password-8821"
SECRET_WG = "wg-super-secret-private-key-val"


class PhaseCReadAndFleetTests(unittest.TestCase):
    def test_wan_ip_details_ipv6_traffic_qos_backups_hotspot_and_secret_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True)
            ctrl.ddns["data"] = [
                {
                    "id": "ddns-1",
                    "service": 0,
                    "interfacePortId": "wan-port-1",
                    "username": "alice",
                    "password": SECRET_DDNS,
                    "ddnsPwd": "another-ddns-pwd",
                    "domainName": "gw.example.org",
                    "updateInterval": 12,
                    "status": True,
                }
            ]
            ctrl.ddns["totalRows"] = 1
            ctrl.url_filtering_gw = [{"id": "uf-1", "name": "Block-Social", "status": True}]
            ctrl.qos_bwc = [{"id": "bwc-1", "name": "Video-Limit"}]
            ctrl.qos_class_rules = [{"id": "cls-1", "name": "VoIP-EF"}]
            ctrl.qos_switch_profiles = [{"id": "swq-1", "name": "Strict-Priority"}]

            wan_masked = unwrap_ok(call_tool(server, "get_wan_ip_details", {"maskWanIp": True}))
            self.assertEqual(wan_masked["ddnsCount"], 1)
            self.assertTrue(wan_masked["ddnsEntries"][0]["hasPassword"])
            serialized_wan = json.dumps(wan_masked)
            self.assertNotIn(SECRET_DDNS, serialized_wan)
            self.assertNotIn("another-ddns-pwd", serialized_wan)
            self.assertEqual(mask_ipv4_middle("198.51.100.45"), "198.51.***.***")
            self.assertGreaterEqual(wan_masked["wanPortCount"], 1)

            ipv6 = unwrap_ok(call_tool(server, "get_ipv6_status", {}))
            self.assertIn("wanIpv6Enabled", ipv6)
            self.assertGreaterEqual(ipv6["lanCount"], 1)

            lans = unwrap_ok(call_tool(server, "list_lan_networks", {}))
            self.assertIn("ipv6", lans["items"][0])

            traffic = unwrap_ok(call_tool(server, "list_traffic_rules", {}))
            self.assertEqual(traffic["gatewayUrlFilteringCount"], 1)
            self.assertEqual(traffic["gatewayUrlFilteringRules"][0]["name"], "Block-Social")

            qos = unwrap_ok(call_tool(server, "list_qos_rules", {}))
            self.assertEqual(len(qos["gatewayBwcRules"]), 1)
            self.assertEqual(len(qos["gatewayClassRules"]), 1)
            self.assertEqual(len(qos["switchQueueProfiles"]), 1)

            backups = unwrap_ok(call_tool(server, "list_backups", {}))
            self.assertEqual(backups["backupFileCount"], 1)
            self.assertNotIn("synthetic-backup-secret", json.dumps(backups))
            self.assertEqual(backups["autoBackupSchedule"]["password"], "***REDACTED***")

            vouchers = unwrap_ok(call_tool(server, "list_hotspot_vouchers", {}))
            self.assertEqual(vouchers["groupCount"], 1)
            self.assertEqual(vouchers["voucherCount"], 1)

            srv_viewer, _cv, _ctrlv, _sv = make_write_env(tmp, role="Viewer", read_only=True)
            bkp_viewer = unwrap_ok(call_tool(srv_viewer, "list_backups", {}))
            self.assertEqual(bkp_viewer["backupFileCount"], 0)
            self.assertGreaterEqual(len(bkp_viewer["warnings"]), 1)

    def test_cross_site_fleet_audit_requires_flag_and_aggregates_sites(self):
        with tempfile.TemporaryDirectory() as tmp:
            server_blocked, _c, _ctrl, _s = make_write_env(tmp, read_only=True)
            blocked = call_tool(server_blocked, "audit_all_sites", {})
            self.assertTrue(blocked["result"]["isError"])
            self.assertIn("OMADA_ALLOW_CROSS_SITE=true", blocked["result"]["content"][0]["text"])

            ctrl = MockController()
            ctrl.sites = [
                {"id": "mocksite0000000000000001", "name": "Mock Lab Site"},
                {"id": "mocksite0000000000000002", "name": "Branch Office"},
            ]
            cfg = make_write_config(tmp_dir=tmp, read_only=True, allow_cross_site=True)
            client = OmadaClient(cfg, transport=ctrl, sleep=lambda _s: None, clock=lambda: 10.0, log_fn=lambda _m: None)
            server_ok = Server(cfg, client=client)
            fleet = unwrap_ok(call_tool(server_ok, "audit_all_sites", {"maxSites": 10}))
            self.assertEqual(fleet["totalSites"], 2)
            self.assertEqual(fleet["auditedSites"], 2)
            self.assertFalse(fleet["truncated"])
            self.assertEqual([s["name"] for s in fleet["sites"]], ["Mock Lab Site", "Branch Office"])

    def test_tool_catalog_core_hides_hotspot_unless_explicitly_requested(self):
        base_env = {
            "OMADA_BASE_URL": "https://127.0.0.1:8043",
            "OMADA_USERNAME": "viewer",
            "OMADA_PASSWORD": "pw",
            "OMADA_READ_ONLY": "false",
            "OMADA_WRITE_TOOLS": ",".join(WRITE_TOOL_NAMES),
        }
        with mock.patch.dict("os.environ", {**base_env, "OMADA_TOOL_CATALOG": "core"}, clear=True):
            cfg_core = load_config()
            srv_core = Server(cfg_core)
            listed_core = {t["name"] for t in srv_core.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
            self.assertNotIn("list_hotspot_vouchers", listed_core)
            self.assertNotIn("create_hotspot_vouchers", listed_core)
            self.assertNotIn("revoke_hotspot_voucher", listed_core)
            self.assertIn("get_wan_ip_details", listed_core)

        with mock.patch.dict(
            "os.environ",
            {**base_env, "OMADA_TOOL_CATALOG": "core", "OMADA_TOOL_CATEGORIES": "hotspot"},
            clear=True,
        ):
            cfg_hs = load_config()
            srv_hs = Server(cfg_hs)
            listed_hs = {t["name"] for t in srv_hs.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
            self.assertEqual(
                listed_hs,
                {"list_hotspot_vouchers", "create_hotspot_vouchers", "revoke_hotspot_voucher"},
            )


class PhaseCWriteCrudAndRollbackTests(unittest.TestCase):
    def test_vpn_toggle_wireguard_crud_ref_guard_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.vpn_configs.append({"id": "vpn-1", "name": "HQ-IPsec", "status": False, "preSharedKey": "psk-hidden"})

            # 1) Toggle VPN status + rollback
            dry_vpn = unwrap_ok(call_tool(server, "set_vpn_tunnel_status", {"vpn": "HQ-IPsec", "enabled": True}))
            self.assertNotIn("psk-hidden", json.dumps(dry_vpn))
            commit_vpn = unwrap_ok(call_tool(server, "set_vpn_tunnel_status", {
                "vpn": "HQ-IPsec",
                "enabled": True,
                "dryRun": False,
                "confirm": dry_vpn["confirmToken"],
            }))
            self.assertTrue(ctrl.vpn_configs[0]["status"])

            rb_vpn = unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": Path(commit_vpn["snapshot"]).name,
                "dryRun": False,
                "confirm": f"rollback_from_snapshot:{Path(commit_vpn['snapshot']).name}",
            }))
            self.assertTrue(rb_vpn["applied"])
            self.assertFalse(ctrl.vpn_configs[0]["status"])

            # 2) WireGuard validation guards
            bad_key = call_tool(server, "upsert_wireguard_tunnel", {
                "name": "wg-bad",
                "localIp": "10.66.0.1/24",
                "privateKey": "not-a-valid-key",
            })
            self.assertTrue(bad_key["result"]["isError"])

            bad_cidr = call_tool(server, "upsert_wireguard_tunnel", {
                "name": "wg-bad",
                "localIp": "999.999.999.999/24",
            })
            self.assertTrue(bad_cidr["result"]["isError"])

            # 3) Create WireGuard tunnel with ephemeral controller keygen + zero secret leakage
            dry_wg = unwrap_ok(call_tool(server, "upsert_wireguard_tunnel", {
                "name": "wg-road",
                "localIp": "10.66.0.1/24",
                "listenPort": 51820,
            }))
            self.assertTrue(any("ephemeral" in w for w in dry_wg["warnings"]))
            commit_wg = unwrap_ok(call_tool(server, "upsert_wireguard_tunnel", {
                "name": "wg-road",
                "localIp": "10.66.0.1/24",
                "listenPort": 51820,
                "dryRun": False,
                "confirm": dry_wg["confirmToken"],
            }))
            wg_id = commit_wg["target"]
            self.assertEqual(commit_wg["after"]["localIp"], "10.66.0.1")
            snap_wg_text = (Path(tmp) / Path(commit_wg["snapshot"]).name).read_text(encoding="utf-8")
            self.assertNotIn("privateKey", snap_wg_text)
            self.assertNotIn("MOCK-WG-PRIVATE-KEY", json.dumps(commit_wg))

            # 4) Peer validation & create/update/rollback
            bad_pair = call_tool(server, "upsert_wireguard_peer", {
                "name": "laptop",
                "interface": "wg-road",
                "publicKey": VALID_KEY_B,
                "allowAddress": ["10.66.0.2/32"],
                "endPoint": "vpn.example.com",
            })
            self.assertTrue(bad_pair["result"]["isError"])

            dry_peer = unwrap_ok(call_tool(server, "upsert_wireguard_peer", {
                "name": "laptop",
                "interface": "wg-road",
                "publicKey": VALID_KEY_B,
                "allowAddress": ["10.66.0.2/32"],
                "presharedKey": VALID_PSK,
            }))
            self.assertNotIn(VALID_PSK, json.dumps(dry_peer))
            commit_peer = unwrap_ok(call_tool(server, "upsert_wireguard_peer", {
                "name": "laptop",
                "interface": "wg-road",
                "publicKey": VALID_KEY_B,
                "allowAddress": ["10.66.0.2/32"],
                "presharedKey": VALID_PSK,
                "dryRun": False,
                "confirm": dry_peer["confirmToken"],
            }))
            peer_id = commit_peer["target"]
            self.assertNotIn(VALID_PSK, (Path(tmp) / Path(commit_peer["snapshot"]).name).read_text(encoding="utf-8"))

            # Update peer keepAlive -> rollback restores keepAlive=25
            dry_upd = unwrap_ok(call_tool(server, "upsert_wireguard_peer", {
                "peerId": peer_id,
                "name": "laptop-pro",
                "interface": wg_id,
                "publicKey": VALID_KEY_B,
                "allowAddress": ["10.66.0.2/32"],
                "keepAlive": 45,
            }))
            commit_upd = unwrap_ok(call_tool(server, "upsert_wireguard_peer", {
                "peerId": peer_id,
                "name": "laptop-pro",
                "interface": wg_id,
                "publicKey": VALID_KEY_B,
                "allowAddress": ["10.66.0.2/32"],
                "keepAlive": 45,
                "dryRun": False,
                "confirm": dry_upd["confirmToken"],
            }))
            self.assertEqual(ctrl.wireguard_peers[0]["keepAlive"], 45)
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": Path(commit_upd["snapshot"]).name,
                "dryRun": False,
                "confirm": f"rollback_from_snapshot:{Path(commit_upd['snapshot']).name}",
            }))
            self.assertEqual(ctrl.wireguard_peers[0]["keepAlive"], 25)
            self.assertEqual(ctrl.wireguard_peers[0]["name"], "laptop")

            # 5) Delete tunnel refused while peer attached -> delete peer -> rollback tunnel creation deletes tunnel
            refused_del = call_tool(server, "delete_wireguard_tunnel", {"tunnel": wg_id})
            self.assertTrue(refused_del["result"]["isError"])
            self.assertIn("peer", refused_del["result"]["content"][0]["text"].lower())

            dry_del_peer = unwrap_ok(call_tool(server, "delete_wireguard_peer", {"peer": peer_id}))
            commit_del_peer = unwrap_ok(call_tool(server, "delete_wireguard_peer", {
                "peer": peer_id,
                "dryRun": False,
                "confirm": dry_del_peer["confirmToken"],
            }))
            self.assertEqual(ctrl.wireguard_peers, [])

            # Deleted peer rollback fails closed because presharedKey was redacted
            rb_del_peer = call_tool(server, "rollback_from_snapshot", {
                "snapshotId": Path(commit_del_peer["snapshot"]).name,
                "dryRun": True,
            })
            self.assertTrue(rb_del_peer["result"]["isError"])

            # Rollback initial tunnel create removes the interface cleanly
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": Path(commit_wg["snapshot"]).name,
                "dryRun": False,
                "confirm": f"rollback_from_snapshot:{Path(commit_wg['snapshot']).name}",
            }))
            self.assertEqual(ctrl.wireguard_configs, [])

    def test_ddns_crud_and_secret_safety(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            bad_iv = call_tool(server, "upsert_ddns", {
                "domainName": "home.example.org",
                "username": "u1",
                "password": SECRET_DDNS,
                "updateInterval": 5,
            })
            self.assertEqual(bad_iv["error"]["code"], -32602)

            dry_ddns = unwrap_ok(call_tool(server, "upsert_ddns", {
                "domainName": "home.example.org",
                "service": "noip",
                "username": "u1",
                "password": SECRET_DDNS,
                "updateInterval": 12,
            }))
            self.assertNotIn(SECRET_DDNS, json.dumps(dry_ddns))
            commit_ddns = unwrap_ok(call_tool(server, "upsert_ddns", {
                "domainName": "home.example.org",
                "service": "noip",
                "username": "u1",
                "password": SECRET_DDNS,
                "updateInterval": 12,
                "dryRun": False,
                "confirm": dry_ddns["confirmToken"],
            }))
            self.assertNotIn(SECRET_DDNS, (Path(tmp) / Path(commit_ddns["snapshot"]).name).read_text(encoding="utf-8"))
            self.assertEqual(len(ctrl.ddns["data"]), 1)

            # Delete + confirm fail-closed rollback
            dry_del = unwrap_ok(call_tool(server, "delete_ddns", {"ddns": "home.example.org"}))
            commit_del = unwrap_ok(call_tool(server, "delete_ddns", {
                "ddns": "home.example.org",
                "dryRun": False,
                "confirm": dry_del["confirmToken"],
            }))
            self.assertEqual(ctrl.ddns["data"], [])
            rb_del = call_tool(server, "rollback_from_snapshot", {
                "snapshotId": Path(commit_del["snapshot"]).name,
                "dryRun": True,
            })
            self.assertTrue(rb_del["result"]["isError"])

    def test_backup_export_safety_download_limit_and_hotspot_vouchers(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, client, ctrl, _ = make_write_env(tmp)

            # Path traversal rejected
            bad_file = call_tool(server, "export_controller_backup", {"fileName": "../secret.cfg"})
            self.assertTrue(bad_file["result"]["isError"])

            # Retention enum validation (schema rejects with -32602 before handler)
            bad_ret = call_tool(server, "export_controller_backup", {"retentionDays": 15})
            self.assertEqual(bad_ret["error"]["code"], -32602)

            # Viewer / read-only refused
            srv_ro, _c2, _ctrl2, _s2 = make_write_env(tmp, read_only=True)
            self.assertEqual(call_tool(srv_ro, "export_controller_backup", {})["error"]["code"], -32003)

            # Manual backup export writes bounded file under snapshot_dir/backups
            dry_bkp = unwrap_ok(call_tool(server, "export_controller_backup", {"retentionDays": -1}))
            commit_bkp = unwrap_ok(call_tool(server, "export_controller_backup", {
                "retentionDays": -1,
                "dryRun": False,
                "confirm": dry_bkp["confirmToken"],
            }))
            out_path = Path(commit_bkp["after"]["outputPath"])
            self.assertTrue(out_path.exists())
            self.assertEqual(out_path.parent.name, "backups")
            self.assertEqual(out_path.read_bytes(), ctrl.backup_bytes)

            # Download cap guard
            client.authenticate()
            with self.assertRaises(OmadaError):
                client.download("autoBackup/autoBackupFile?fileName=autobackup_20261115.cfg", max_bytes=8)

            # Hotspot voucher validation & group create + single voucher revoke + group revoke
            bad_code_len = call_tool(server, "create_hotspot_vouchers", {
                "name": "TooShort",
                "codeLength": 5,
            })
            self.assertEqual(bad_code_len["error"]["code"], -32602)

            dry_v = unwrap_ok(call_tool(server, "create_hotspot_vouchers", {
                "name": "Cafe-2H",
                "amount": 5,
                "durationMinutes": 120,
                "codeFormat": "numbers",
            }))
            commit_v = unwrap_ok(call_tool(server, "create_hotspot_vouchers", {
                "name": "Cafe-2H",
                "amount": 5,
                "durationMinutes": 120,
                "codeFormat": "numbers",
                "dryRun": False,
                "confirm": dry_v["confirmToken"],
            }))
            created_gid = commit_v["target"]
            self.assertTrue(any(g["name"] == "Cafe-2H" for g in ctrl.voucher_groups))

            dry_rev_single = unwrap_ok(call_tool(server, "revoke_hotspot_voucher", {
                "target": "123456",
                "targetType": "voucher",
            }))
            unwrap_ok(call_tool(server, "revoke_hotspot_voucher", {
                "target": "123456",
                "targetType": "voucher",
                "dryRun": False,
                "confirm": dry_rev_single["confirmToken"],
            }))
            self.assertEqual(ctrl.vouchers, [])

            dry_rev_grp = unwrap_ok(call_tool(server, "revoke_hotspot_voucher", {
                "target": created_gid,
                "targetType": "group",
            }))
            unwrap_ok(call_tool(server, "revoke_hotspot_voucher", {
                "target": created_gid,
                "targetType": "group",
                "dryRun": False,
                "confirm": dry_rev_grp["confirmToken"],
            }))
            self.assertFalse(any(g["id"] == created_gid for g in ctrl.voucher_groups))

    def test_snapshot_and_diff_parity_for_phase_c_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            ctrl.vpn_configs.append({"id": "vpn-s1", "name": "S2S-HQ", "status": True, "preSharedKey": "topsecret"})
            ctrl.wireguard_configs.append({
                "id": "wg-s1", "name": "wg0", "status": True, "mtu": 1420,
                "listenPort": 51820, "localIp": "10.66.0.1/24", "privateKey": VALID_KEY_A,
            })
            ctrl.wireguard_peers.append({
                "id": "wgp-s1", "name": "peer1", "status": True, "interfaceId": "wg-s1",
                "publicKey": VALID_KEY_B, "allowAddress": ["10.66.0.2/32"], "presharedKey": VALID_PSK,
            })
            ctrl.ddns["data"] = [{
                "id": "d-1", "service": 0, "domainName": "a.example.org", "password": SECRET_DDNS,
            }]
            ctrl.url_filtering_gw = [{"id": "uf-1", "name": "Filter-1", "status": True}]
            ctrl.qos_bwc = [{"id": "bwc-1", "name": "Qos-1"}]

            objs = ["vpns", "wireguard", "wireguardPeers", "ddns", "trafficRules", "qos"]
            snap1 = unwrap_ok(call_tool(server, "get_config_snapshot", {"objects": objs}))
            snap1_txt = json.dumps(snap1)
            for secret in ("topsecret", VALID_KEY_A, VALID_PSK, SECRET_DDNS):
                self.assertNotIn(secret, snap1_txt)

            no_diff = unwrap_ok(call_tool(server, "diff_config_snapshots", {"baseline": snap1, "current": copy.deepcopy(snap1)}))
            self.assertFalse(no_diff["hasChanges"])

            snap2 = copy.deepcopy(snap1)
            snap2["vpns"][0]["status"] = False
            snap2["wireguard"].append({"id": "wg-s2", "name": "wg1", "localIp": "10.67.0.1/24"})
            snap2["wireguardPeers"] = []
            snap2["ddns"][0]["domainName"] = "b.example.org"
            snap2["trafficRules"]["gatewayUrlFilteringCount"] = 2
            snap2["qos"]["gatewayBwcRules"][0]["name"] = "Qos-2"

            drifted = unwrap_ok(call_tool(server, "diff_config_snapshots", {"baseline": snap1, "current": snap2}))
            self.assertTrue(drifted["hasChanges"])
            self.assertEqual(set(drifted["sections"].keys()), set(objs))
            self.assertGreater(drifted["summary"]["changed"], 0)
            self.assertGreater(drifted["summary"]["added"], 0)
            self.assertGreater(drifted["summary"]["removed"], 0)


class PhaseCRegistryCountSanityTests(unittest.TestCase):
    def test_exact_tool_inventory_counts(self):
        self.assertEqual(len(_READ_ONLY_TOOL_NAMES), 54)
        self.assertEqual(len(WRITE_TOOL_NAMES), 78)
        self.assertEqual(len(_READ_ONLY_TOOL_NAMES | set(WRITE_TOOL_NAMES)), 132)


if __name__ == "__main__":
    unittest.main()
