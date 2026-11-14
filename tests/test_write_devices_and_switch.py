"""Client/device operations and Milestone 2 switch port/PoE/AP radio write tests."""

from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SRC = ROOT / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from write_harness import call_tool, make_write_env, unwrap_ok  # noqa: E402


class ClientAndDeviceOpsTests(unittest.TestCase):
    def test_client_block_reconnect_rename_and_device_ops(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Refuses managed device MAC (-41011)
            dev_blk = call_tool(server, "set_client_blocked", {"mac": "AA-BB-CC-00-00-01", "blocked": True})
            self.assertTrue(dev_blk["result"]["isError"])

            # Block & unblock client
            blk_dry = unwrap_ok(call_tool(server, "set_client_blocked", {"mac": "AA-BB-CC-11-11-01", "blocked": True}))
            blk = unwrap_ok(call_tool(server, "set_client_blocked", {
                "mac": "AA-BB-CC-11-11-01",
                "blocked": True,
                "dryRun": False,
                "confirm": blk_dry["confirmToken"],
            }))
            self.assertIs(blk["after"]["blocked"], True)
            unblk = unwrap_ok(call_tool(server, "set_client_blocked", {
                "mac": "AA-BB-CC-11-11-01",
                "blocked": False,
                "dryRun": False,
                "confirm": blk_dry["confirmToken"],
            }))
            self.assertIs(unblk["after"]["blocked"], False)

            # Reconnect wireless client + refuse wired client
            ctrl.clients["AA-BB-CC-11-11-01"]["wireless"] = False
            wired_rec = call_tool(server, "reconnect_client", {"mac": "AA-BB-CC-11-11-01"})
            self.assertTrue(wired_rec["result"]["isError"])

            rec_dry = unwrap_ok(call_tool(server, "reconnect_client", {"mac": "AA-BB-CC-11-11-02"}))
            rec = unwrap_ok(call_tool(server, "reconnect_client", {
                "mac": "AA-BB-CC-11-11-02",
                "dryRun": False,
                "confirm": rec_dry["confirmToken"],
            }))
            self.assertTrue(rec["applied"])

            # Rename client
            ren_dry = unwrap_ok(call_tool(server, "update_client", {"mac": "AA-BB-CC-11-11-01", "name": "workstation-1"}))
            ren = unwrap_ok(call_tool(server, "update_client", {
                "mac": "AA-BB-CC-11-11-01",
                "name": "workstation-1",
                "dryRun": False,
                "confirm": ren_dry["confirmToken"],
            }))
            self.assertEqual(ren["after"]["name"], "workstation-1")

            # Rename device, LED setting, locate blink, and reboot
            dev_dry = unwrap_ok(call_tool(server, "update_device", {
                "mac": "ap-living",
                "name": "ap-kitchen",
                "ledSetting": "off",
                "locate": True,
            }))
            dev_res = unwrap_ok(call_tool(server, "update_device", {
                "mac": "ap-living",
                "name": "ap-kitchen",
                "ledSetting": "off",
                "locate": True,
                "dryRun": False,
                "confirm": dev_dry["confirmToken"],
            }))
            self.assertEqual(dev_res["after"]["name"], "ap-kitchen")
            self.assertIs(dev_res["after"]["locateEnable"], True)

            reb_dry = unwrap_ok(call_tool(server, "reboot_device", {"mac": "ap-kitchen"}))
            reb = unwrap_ok(call_tool(server, "reboot_device", {
                "mac": "ap-kitchen",
                "dryRun": False,
                "confirm": reb_dry["confirmToken"],
            }))
            self.assertTrue(reb["applied"])

            unknown_dev = call_tool(server, "update_device", {"mac": "AA-BB-CC-99-99-99", "name": "ghost"})
            self.assertTrue(unknown_dev["result"]["isError"])


class Milestone2SwitchAndApTests(unittest.TestCase):
    def test_update_switch_port_poe_override_disable_and_anti_stranding_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # 1. Non-uplink port 4: PoE disable forces profileOverrideEnable=True + clean verification
            dry = unwrap_ok(call_tool(server, "update_switch_port", {
                "deviceMac": "sw-access",
                "port": 4,
                "name": "Lab-Cam",
                "poeEnabled": False,
                "linkSpeed": "1000m",
            }))
            self.assertTrue(dry["dryRun"])
            self.assertEqual(dry["confirmToken"], "update_switch_port:aa:bb:cc:00:00:02:4")
            applied = unwrap_ok(call_tool(server, "update_switch_port", {
                "deviceMac": "sw-access",
                "port": 4,
                "name": "Lab-Cam",
                "poeEnabled": False,
                "linkSpeed": "1000m",
                "dryRun": False,
                "confirm": dry["confirmToken"],
            }))
            self.assertEqual(applied["after"]["name"], "Lab-Cam")
            self.assertEqual(applied["after"]["poe"], 0)
            self.assertIs(applied["after"]["profileOverrideEnable"], True)

            # Disable port -> switches to built-in Disable profile, then re-enable -> All
            dis_dry = unwrap_ok(call_tool(server, "update_switch_port", {
                "deviceMac": "AA-BB-CC-00-00-02",
                "port": 4,
                "enabled": False,
            }))
            dis = unwrap_ok(call_tool(server, "update_switch_port", {
                "deviceMac": "AA-BB-CC-00-00-02",
                "port": 4,
                "enabled": False,
                "dryRun": False,
                "confirm": dis_dry["confirmToken"],
            }))
            self.assertEqual(dis["after"]["profileName"], "Disable")
            self.assertIs(dis["after"]["disable"], True)

            # 2. Anti-stranding: port 17 has uplink / downlink gateway AA-BB-CC-00-00-01 -> blocked
            before_writes = ctrl.write_request_count
            uplink_err = call_tool(server, "update_switch_port", {
                "deviceMac": "sw-access",
                "port": 17,
                "profileName": "Management",
            })
            self.assertTrue(uplink_err["result"]["isError"])
            self.assertEqual(ctrl.write_request_count, before_writes)

            # 3. Anti-stranding: LAG member port -> blocked unless allowUplinkMutation=True
            ctrl.switch_lags["AA-BB-CC-00-00-02"] = [{"id": "lag-1", "name": "LAG1", "ports": [1, 2]}]
            lag_err = call_tool(server, "update_switch_port", {
                "deviceMac": "sw-access",
                "port": 1,
                "enabled": False,
            })
            self.assertTrue(lag_err["result"]["isError"])
            self.assertIn("lag", lag_err["result"]["content"][0]["text"].lower())

            # With allowUplinkMutation=True, dryRun warns & succeeds
            lag_ok = unwrap_ok(call_tool(server, "update_switch_port", {
                "deviceMac": "sw-access",
                "port": 1,
                "profileName": "Management",
                "allowUplinkMutation": True,
            }))
            self.assertTrue(any("ANTI-STRANDING GUARD BYPASSED" in w for w in lag_ok["warnings"]))

            # 4. Anti-stranding: port carrying controller/MCP host downlink
            for ctp in ctrl.cable_test_ports["AA-BB-CC-00-00-02"]:
                if int(ctp.get("port", 0)) == 5:
                    ctp["downlinkDevices"] = [{"mac": "AA-BB-CC-11-11-99", "name": "Omada Controller", "type": "controller", "ip": "controller.test"}]
            ctrl_err = call_tool(server, "update_switch_port", {
                "deviceMac": "sw-access",
                "port": 5,
                "poeEnabled": False,
            })
            self.assertTrue(ctrl_err["result"]["isError"])
            self.assertIn("controller", ctrl_err["result"]["content"][0]["text"].lower())

    def test_cycle_poe_port_warns_downstream_ap_and_guards_uplink(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Port 3 powers ap-living -> warns clearly in dryRun, executes POST restart on commit
            dry = unwrap_ok(call_tool(server, "cycle_poe_port", {"deviceMac": "sw-access", "port": 3}))
            self.assertTrue(any("ap-living" in w for w in dry["warnings"]))
            res = unwrap_ok(call_tool(server, "cycle_poe_port", {
                "deviceMac": "sw-access",
                "port": 3,
                "dryRun": False,
                "confirm": dry["confirmToken"],
            }))
            self.assertTrue(res["applied"])
            p3 = next(p for p in ctrl.switch_ports["AA-BB-CC-00-00-02"] if p["port"] == 3)
            self.assertIn("lastPoeCycleAt", p3)

            # Port 17 carries controller/uplink (make port 17 host controller client to ensure guard)
            ctrl.clients["AA-BB-CC-11-11-99"] = {
                "mac": "AA-BB-CC-11-11-99",
                "ip": "127.0.0.1",
                "wireless": False,
                "active": True,
                "switchMac": "AA-BB-CC-00-00-02",
                "port": 17,
            }
            blocked = call_tool(server, "cycle_poe_port", {"deviceMac": "sw-access", "port": 17})
            self.assertTrue(blocked["result"]["isError"])

    def test_upsert_port_profile_create_update_and_prohibit_modify(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Protected built-in Disable profile refuses edits
            prot = call_tool(server, "upsert_port_profile", {
                "profileId": "65000000000000000000001d",
                "name": "Disable-Hacked",
            })
            self.assertTrue(prot["result"]["isError"])

            # Create new profile
            cr_dry = unwrap_ok(call_tool(server, "upsert_port_profile", {
                "name": "IoT-Trunk",
                "poeMode": "on",
                "nativeNetworkId": "net-iot-20",
                "taggedNetworkIds": ["net-lab-40"],
                "portIsolationEnable": True,
            }))
            cr = unwrap_ok(call_tool(server, "upsert_port_profile", {
                "name": "IoT-Trunk",
                "poeMode": "on",
                "nativeNetworkId": "net-iot-20",
                "taggedNetworkIds": ["net-lab-40"],
                "portIsolationEnable": True,
                "dryRun": False,
                "confirm": cr_dry["confirmToken"],
            }))
            pid = cr["after"]["id"]
            self.assertEqual(cr["after"]["name"], "IoT-Trunk")
            self.assertIs(cr["after"]["portIsolationEnable"], True)

            # Update existing profile
            up_dry = unwrap_ok(call_tool(server, "upsert_port_profile", {
                "profileId": pid,
                "name": "IoT-Trunk",
                "poeMode": "off",
            }))
            up = unwrap_ok(call_tool(server, "upsert_port_profile", {
                "profileId": pid,
                "name": "IoT-Trunk",
                "poeMode": "off",
                "dryRun": False,
                "confirm": up_dry["confirmToken"],
            }))
            self.assertEqual(up["after"]["poe"], 0)

            # Protected built-in Disable profile refuses deletion
            prot_del = call_tool(server, "delete_port_profile", {
                "profile": "Disable",
            })
            self.assertTrue(prot_del["result"]["isError"])

            # Delete custom profile and restore via rollback_from_snapshot
            del_dry = unwrap_ok(call_tool(server, "delete_port_profile", {"profile": "IoT-Trunk"}))
            del_res = unwrap_ok(call_tool(server, "delete_port_profile", {
                "profile": "IoT-Trunk",
                "dryRun": False,
                "confirm": del_dry["confirmToken"],
            }))
            self.assertTrue(del_res["applied"])
            self.assertFalse(any(p.get("name") == "IoT-Trunk" for p in ctrl.port_profiles))

            rb_del_sid = Path(del_res["snapshot"]).name
            rb_del_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": rb_del_sid}))
            unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": rb_del_sid,
                "dryRun": False,
                "confirm": rb_del_dry["confirmToken"],
            }))
            self.assertTrue(any(p.get("name") == "IoT-Trunk" for p in ctrl.port_profiles))

    def test_update_ap_radio_rf_scan_and_assign_wlan_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Invalid channel rejected BEFORE write
            bad_ch = call_tool(server, "update_ap_radio", {
                "deviceMac": "ap-living",
                "band": "5g",
                "channel": 999,
            })
            self.assertTrue(bad_ch["result"]["isError"])
            self.assertEqual(ctrl.write_request_count, 0)

            # Unsupported width (e.g. 320 on 5g) rejected BEFORE write
            bad_w = call_tool(server, "update_ap_radio", {
                "deviceMac": "ap-living",
                "band": "5g",
                "channel": 36,
                "channelWidth": "320",
            })
            self.assertTrue(bad_w["result"]["isError"])
            self.assertEqual(ctrl.write_request_count, 0)

            # Valid 5g update preserves sibling radioSetting2g unchanged
            before_2g = copy.deepcopy(ctrl.eap_details["AA-BB-CC-00-00-03"]["radioSetting2g"])
            rad_dry = unwrap_ok(call_tool(server, "update_ap_radio", {
                "deviceMac": "ap-living",
                "band": "5g",
                "channel": 36,
                "channelWidth": "40",
                "txPowerLevel": "medium",
            }))
            rad = unwrap_ok(call_tool(server, "update_ap_radio", {
                "deviceMac": "ap-living",
                "band": "5g",
                "channel": 36,
                "channelWidth": "40",
                "txPowerLevel": "medium",
                "dryRun": False,
                "confirm": rad_dry["confirmToken"],
            }))
            self.assertEqual(str(rad["after"]["channel"]), "1")
            self.assertEqual(rad["after"]["txPowerLevel"], "medium")
            self.assertEqual(ctrl.eap_details["AA-BB-CC-00-00-03"]["radioSetting2g"], before_2g)

            # RF scan warns on dryRun & posts scan command
            rf_dry = unwrap_ok(call_tool(server, "start_rf_scan", {"deviceMac": "ap-living", "bands": ["2g", "5g"]}))
            self.assertTrue(any("disconnect" in w.lower() for w in rf_dry["warnings"]))
            rf = unwrap_ok(call_tool(server, "start_rf_scan", {
                "deviceMac": "ap-living",
                "bands": ["2g", "5g"],
                "dryRun": False,
                "confirm": rf_dry["confirmToken"],
            }))
            self.assertTrue(rf["applied"])

            # Assign AP WLAN group while preserving ssidOverrides
            ctrl.wlans.append({"id": "wlan-grp-2", "name": "Guest-WLAN", "primary": False})
            ctrl.eap_details["AA-BB-CC-00-00-03"]["ssidOverrides"] = [{"ssidId": "ssid-guest", "vlan": 30}]
            wg_dry = unwrap_ok(call_tool(server, "assign_ap_wlan_group", {
                "deviceMac": "ap-living",
                "wlanGroup": "Guest-WLAN",
            }))
            wg = unwrap_ok(call_tool(server, "assign_ap_wlan_group", {
                "deviceMac": "ap-living",
                "wlanGroup": "Guest-WLAN",
                "dryRun": False,
                "confirm": wg_dry["confirmToken"],
            }))
            self.assertEqual(wg["after"]["wlanId"], "wlan-grp-2")
            self.assertEqual(
                ctrl.eap_details["AA-BB-CC-00-00-03"]["ssidOverrides"],
                [{"ssidId": "ssid-guest", "vlan": 30, "vlanPoolIds": "1"}],
            )

