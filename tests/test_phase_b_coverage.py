"""Phase B tests: deep Switch L2 (LAG/STP/mirror/PoE schedules) & Wi-Fi/RF coverage."""

from __future__ import annotations

import json
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


def _commit(server, tool: str, args: dict) -> dict:
    dry = unwrap_ok(call_tool(server, tool, {**args, "dryRun": True}))
    self_args = {**args, "dryRun": False, "confirm": dry["confirmToken"]}
    return unwrap_ok(call_tool(server, tool, self_args))


class PhaseBReadToolsAndSnapshotsTests(unittest.TestCase):
    def test_all_seven_phase_b_read_tools_and_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True)
            # Inject raw plaintext PSK in override fixture to verify read tool strips it
            ctrl.eap_details["AA-BB-CC-00-00-03"]["ssidOverrides"][1]["psk"] = "secret-ap-override-pass"

            wf = unwrap_ok(call_tool(server, "get_wifi_radio_features"))
            self.assertEqual(wf["source"], "setting/wireless/feature")
            self.assertTrue(wf["roaming"]["fastRoaming80211r"])
            self.assertTrue(wf["bandSteering"]["enable"])
            self.assertTrue(wf["airtimeFairness"]["enable5g"])
            self.assertTrue(wf["mesh"]["meshEnable"])
            self.assertTrue(wf["lldpEnable"])

            ov = unwrap_ok(call_tool(server, "get_ap_ssid_overrides", {"mac": "AA-BB-CC-00-00-03"}))
            self.assertEqual(ov["mac"], "aa:bb:cc:00:00:03")
            self.assertEqual(ov["totalSsids"], 2)
            self.assertNotIn("secret-ap-override-pass", json.dumps(ov))
            iot_ov = next(item for item in ov["overrides"] if item["globalSsid"] == "IoTWiFi")
            self.assertTrue(iot_ov["hasPresharedKey"])
            self.assertNotIn("psk", iot_ov)

            mesh = unwrap_ok(call_tool(server, "get_mesh_status", {"mac": "AA-BB-CC-00-00-03"}))
            self.assertTrue(mesh["siteMesh"]["meshEnable"])
            self.assertEqual(mesh["apCount"], 1)
            self.assertTrue(mesh["aps"][0]["supportMesh"])
            self.assertEqual(mesh["aps"][0]["candidateParents"][0]["name"], "ap-mesh-root")

            rfp = unwrap_ok(call_tool(server, "get_wlan_optimization_status"))
            self.assertEqual(rfp["scanStatus"]["statusLabel"], "idle")
            self.assertEqual(rfp["experienceHistory"][0]["score"], 92)
            self.assertTrue(rfp["firstDeploy"])

            lags = unwrap_ok(call_tool(server, "list_switch_lags", {"mac": "AA-BB-CC-00-00-02"}))
            self.assertEqual(lags["lagCount"], 1)
            self.assertEqual(lags["lags"][0]["lagTypeLabel"], "lacp")
            self.assertEqual(lags["lags"][0]["ports"], [1, 2])
            self.assertEqual(lags["maxLagNum"], 4)

            sw_feat = unwrap_ok(call_tool(server, "get_switch_global_features", {"mac": "AA-BB-CC-00-00-02"}))
            self.assertEqual(sw_feat["stp"]["modeLabel"], "off")
            self.assertTrue(sw_feat["loopbackDetectEnable"])
            self.assertFalse(sw_feat["jumbo"]["enable"])
            self.assertTrue(sw_feat["capabilities"]["mirrorSupport"])

            # Link seeded PoE schedule to Work-Hours so scheduleName resolves cleanly
            ctrl.poe_schedules[0]["turnOnTime"] = "sched-seed-1"
            poe = unwrap_ok(call_tool(server, "list_poe_schedules"))
            self.assertEqual(poe["count"], 1)
            self.assertEqual(poe["items"][0]["scheduleName"], "Work-Hours")
            self.assertEqual(poe["items"][0]["portBindings"][0]["ports"], [1])

    def test_config_snapshot_and_diff_optional_phase_b_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True)
            snap1 = unwrap_ok(call_tool(server, "get_config_snapshot", {
                "objects": ["rateLimitProfiles", "poeSchedules", "wirelessFeature", "rfPlanning"],
            }))
            self.assertIn("rateLimitProfiles", snap1)
            self.assertIn("poeSchedules", snap1)
            self.assertIn("wirelessFeature", snap1)
            self.assertIn("rfPlanning", snap1)

            # Mutate wirelessFeature and PoE schedules and diff against snap1
            ctrl.wireless_feature["roaming"]["aiRoamingEnable"] = True
            ctrl.poe_schedules.append({
                "id": "poe-sched-2",
                "name": "PoE-Weekend",
                "status": True,
                "turnOnTime": "",
                "poePortsMap": {},
            })
            diff = unwrap_ok(call_tool(server, "diff_config_snapshots", {
                "baseline": snap1,
                "objects": ["rateLimitProfiles", "poeSchedules", "wirelessFeature", "rfPlanning"],
            }))
            self.assertTrue(diff["hasChanges"])
            self.assertIn("wirelessFeature", diff["sections"])
            self.assertEqual(len(diff["sections"]["poeSchedules"]["added"]), 1)

    def test_read_only_blocks_all_phase_b_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp, read_only=True)
            for name in (
                "upsert_rate_limit_profile",
                "delete_rate_limit_profile",
                "set_ap_ssid_overrides",
                "run_wlan_optimization",
                "upsert_switch_lag",
                "delete_switch_lag",
                "update_switch_global_features",
                "set_switch_port_mirror",
                "upsert_poe_schedule",
                "bind_poe_schedule",
                "delete_poe_schedule",
            ):
                resp = call_tool(server, name, {})
                self.assertEqual(resp["error"]["code"], -32003, name)
            self.assertEqual(ctrl.write_request_count, 0)


class PhaseBWifiWriteTests(unittest.TestCase):
    def test_rate_limit_profile_crud_guards_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(
                tmp,
                write_tools=("upsert_rate_limit_profile", "delete_rate_limit_profile", "rollback_from_snapshot"),
            )
            created = _commit(server, "upsert_rate_limit_profile", {
                "name": "Stream-15M",
                "downLimitEnable": True,
                "downLimitKbps": 15000,
                "upLimitEnable": True,
                "upLimitKbps": 5000,
            })
            self.assertTrue(created["applied"])
            pid = created["after"]["id"]

            updated = _commit(server, "upsert_rate_limit_profile", {
                "profileId": pid,
                "name": "Stream-20M",
                "downLimitKbps": 20000,
            })
            self.assertEqual(updated["after"]["downLimit"], 20000)

            # Rollback update restores previous name & limit
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(updated["snapshot"]).name})
            restored = next(r for r in ctrl.rate_limit_profiles if r["id"] == pid)
            self.assertEqual(restored["name"], "Stream-15M")

            # Cannot delete Default profile or a profile in use by an SSID/client
            ctrl.rate_limit_profiles.append({"id": "rl-def", "name": "Default", "isDefault": True})
            err_def = call_tool(server, "delete_rate_limit_profile", {"profile": "rl-def"})
            self.assertTrue(err_def["result"]["isError"])

            ctrl.clients["AA-BB-CC-11-11-01"]["rateLimit"] = {"enable": True, "rateLimitId": pid}
            err_used = call_tool(server, "delete_rate_limit_profile", {"profile": pid})
            self.assertTrue(err_used["result"]["isError"])

            ctrl.clients["AA-BB-CC-11-11-01"].pop("rateLimit", None)
            deleted = _commit(server, "delete_rate_limit_profile", {"profile": pid})
            self.assertTrue(deleted["applied"])
            self.assertFalse(any(r["id"] == pid for r in ctrl.rate_limit_profiles))

            # Rollback delete recreates it
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(deleted["snapshot"]).name})
            self.assertTrue(any(r["name"] == "Stream-15M" for r in ctrl.rate_limit_profiles))

    def test_ap_ssid_overrides_redacts_psk_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(
                tmp,
                write_tools=("set_ap_ssid_overrides", "rollback_from_snapshot"),
            )
            secret = "TopSecret-AP-Override-Key-99"
            for override in ctrl.eap_details["AA-BB-CC-00-00-03"]["ssidOverrides"]:
                override.pop("psk", None)
            committed = _commit(server, "set_ap_ssid_overrides", {
                "mac": "AA-BB-CC-00-00-03",
                "overrides": [
                    {"globalSsid": "CorpWiFi", "enable": True, "newSsid": "Living-Corp", "vlanEnable": True, "vlanId": 20},
                ],
            })
            self.assertTrue(committed["applied"])
            self.assertNotIn(secret, json.dumps(committed))
            snap_text = (Path(tmp) / committed["snapshot"]).read_text(encoding="utf-8")
            self.assertNotIn(secret, snap_text)

            corp = next(o for o in ctrl.eap_details["AA-BB-CC-00-00-03"]["ssidOverrides"] if o["globalSsid"] == "CorpWiFi")
            self.assertEqual(corp["ssid"], "Living-Corp")
            self.assertTrue(corp["vlanEnable"])
            self.assertEqual(corp["vlanId"], 20)

            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(committed["snapshot"]).name})
            corp_after = next(o for o in ctrl.eap_details["AA-BB-CC-00-00-03"]["ssidOverrides"] if o["globalSsid"] == "CorpWiFi")
            self.assertEqual(corp_after["ssid"], "CorpWiFi")
            self.assertFalse(corp_after["enable"])

            secret_change = _commit(server, "set_ap_ssid_overrides", {
                "mac": "AA-BB-CC-00-00-03",
                "overrides": [{"globalSsid": "IoTWiFi", "enable": True, "psk": secret}],
            })
            self.assertTrue(secret_change["manualRecoveryRequired"])
            self.assertEqual(secret_change["outcome"], "accepted")
            self.assertNotIn(secret, json.dumps(secret_change))
            secret_snapshot = Path(tmp) / secret_change["snapshot"]
            self.assertNotIn(secret, secret_snapshot.read_text(encoding="utf-8"))
            refused = call_tool(server, "rollback_from_snapshot", {"snapshotId": secret_snapshot.name})
            self.assertTrue(refused["result"]["isError"])
            self.assertIn("manual restoration", refused["result"]["content"][0]["text"])

    def test_run_wlan_optimization_configure_trigger_cancel_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(
                tmp,
                write_tools=("run_wlan_optimization", "rollback_from_snapshot"),
            )
            cfg_res = _commit(server, "run_wlan_optimization", {
                "action": "configure",
                "mode": "custom",
                "channelDeployEnable6g": False,
                "scheduleEnable": True,
                "timingType": 2,
                "dayOfWeek": 1,
                "hour": 4,
                "minute": 30,
            })
            self.assertEqual(cfg_res["after"]["mode"], 1)
            self.assertTrue(cfg_res["after"]["scheduleEnable"])
            self.assertFalse(ctrl.rf_planning["channelDeployEnable6g"])

            # Rollback schedule snapshot
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(cfg_res["snapshot"]).name})
            self.assertFalse(ctrl.rf_planning["scheduleEnable"])

            trig = _commit(server, "run_wlan_optimization", {"action": "trigger"})
            self.assertTrue(trig["warnings"])
            self.assertEqual(ctrl.rf_planning_result["status"], 2)

            _commit(server, "run_wlan_optimization", {"action": "cancel"})
            self.assertEqual(ctrl.rf_planning_result["status"], 1)


class PhaseBSwitchL2WriteTests(unittest.TestCase):
    def test_switch_lag_guards_create_update_delete_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(
                tmp,
                write_tools=("upsert_switch_lag", "delete_switch_lag", "rollback_from_snapshot"),
            )
            # Uplink port 17 and controller port 15 must be blocked unless allowUplinkMutation=True
            err_uplink = call_tool(server, "upsert_switch_lag", {
                "mac": "AA-BB-CC-00-00-02",
                "lagId": 2,
                "ports": [4, 17],
            })
            self.assertTrue(err_uplink["result"]["isError"])

            # Port 1 already belongs to LAG 1 -> refused
            err_dup = call_tool(server, "upsert_switch_lag", {
                "mac": "AA-BB-CC-00-00-02",
                "lagId": 2,
                "ports": [1, 4],
            })
            self.assertTrue(err_dup["result"]["isError"])

            # Delete seeded LAG 1, then create LAG 2 on [1, 2], update name, rollback delete/create
            deleted = _commit(server, "delete_switch_lag", {"mac": "AA-BB-CC-00-00-02", "lagId": 1})
            self.assertEqual(ctrl.switch_lags["AA-BB-CC-00-00-02"], [])

            created = _commit(server, "upsert_switch_lag", {
                "mac": "AA-BB-CC-00-00-02",
                "lagId": 2,
                "ports": [1, 2],
                "lagType": "lacp",
                "name": "Core-Trunk",
            })
            self.assertEqual(created["after"]["name"], "Core-Trunk")
            self.assertEqual(ctrl.switch_lags["AA-BB-CC-00-00-02"][0]["ports"], [1, 2])

            updated = _commit(server, "upsert_switch_lag", {
                "mac": "AA-BB-CC-00-00-02",
                "lagId": 2,
                "ports": [1, 2],
                "lagType": "static",
                "name": "Core-Static",
            })
            self.assertEqual(updated["after"]["lagType"], 1)

            # Rollback update -> restores lacp/Core-Trunk
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(updated["snapshot"]).name})
            self.assertEqual(ctrl.switch_lags["AA-BB-CC-00-00-02"][0]["name"], "Core-Trunk")

            # Rollback create -> deletes LAG 2 (force=True since updated touched lag:2 before being rolled back); rollback delete -> restores LAG 1
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(created["snapshot"]).name, "force": True})
            self.assertEqual(ctrl.switch_lags["AA-BB-CC-00-00-02"], [])
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(deleted["snapshot"]).name})
            self.assertEqual(ctrl.switch_lags["AA-BB-CC-00-00-02"][0]["lagId"], 1)

    def test_switch_global_features_validation_es_routing_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(
                tmp,
                write_tools=("update_switch_global_features", "rollback_from_snapshot"),
            )
            bad_prio = call_tool(server, "update_switch_global_features", {
                "mac": "AA-BB-CC-00-00-02",
                "stpPriority": 1234,
            })
            self.assertTrue(bad_prio["result"]["isError"])

            # Standard managed switch path: test STP transitions (off -> rstp -> off -> rollback)
            ctrl.switch_details["AA-BB-CC-00-00-02"]["es"] = False
            rstp_on = _commit(server, "update_switch_global_features", {
                "mac": "AA-BB-CC-00-00-02",
                "stpMode": "rstp",
            })
            self.assertEqual(ctrl.switch_details["AA-BB-CC-00-00-02"]["stp"], 2)

            svc_upd = _commit(server, "update_switch_global_features", {
                "mac": "AA-BB-CC-00-00-02",
                "stpMode": "off",
                "stpPriority": 4096,
            })
            self.assertTrue(any("Disabling spanning tree" in w for w in svc_upd["warnings"]))
            self.assertEqual(ctrl.switch_details["AA-BB-CC-00-00-02"]["stp"], 0)
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(svc_upd["snapshot"]).name})
            self.assertEqual(ctrl.switch_details["AA-BB-CC-00-00-02"]["stp"], 2)
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(rstp_on["snapshot"]).name, "force": True})
            self.assertEqual(ctrl.switch_details["AA-BB-CC-00-00-02"]["stp"], 0)

            # Test Easy Smart (es=True) uses switches/es/{mac}/config/general
            ctrl.switch_details["AA-BB-CC-00-00-02"]["es"] = True
            gen_upd = _commit(server, "update_switch_global_features", {
                "mac": "AA-BB-CC-00-00-02",
                "jumboEnable": True,
                "jumbo": 9216,
            })
            self.assertEqual(ctrl.switch_details["AA-BB-CC-00-00-02"]["jumbo"], 9216)
            self.assertTrue(any("/switches/es/" in req["path"] for req in ctrl.requests))
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(gen_upd["snapshot"]).name})
            self.assertEqual(ctrl.switch_details["AA-BB-CC-00-00-02"]["jumbo"], 1518)

    def test_switch_port_mirror_guards_commit_clear_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(
                tmp,
                write_tools=("set_switch_port_mirror", "rollback_from_snapshot"),
            )
            bad_self = call_tool(server, "set_switch_port_mirror", {
                "mac": "AA-BB-CC-00-00-02",
                "mirroringPort": 4,
                "mirroredPorts": [3, 4],
            })
            self.assertTrue(bad_self["result"]["isError"])

            bad_uplink = call_tool(server, "set_switch_port_mirror", {
                "mac": "AA-BB-CC-00-00-02",
                "mirroringPort": 17,
                "mirroredPorts": [4],
            })
            self.assertTrue(bad_uplink["result"]["isError"])

            mir = _commit(server, "set_switch_port_mirror", {
                "mac": "AA-BB-CC-00-00-02",
                "mirroringPort": 4,
                "mirroredPorts": [3],
            })
            self.assertEqual(mir["after"]["operation"], "mirroring")
            self.assertEqual(mir["after"]["mirroredPorts"], [3])

            sw_feat = unwrap_ok(call_tool(server, "get_switch_global_features", {"mac": "AA-BB-CC-00-00-02"}))
            self.assertEqual(len(sw_feat["portMirrors"]), 1)
            self.assertEqual(sw_feat["portMirrors"][0]["mirroringPort"], 4)

            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(mir["snapshot"]).name})
            port4 = next(p for p in ctrl.switch_ports["AA-BB-CC-00-00-02"] if p["port"] == 4)
            self.assertEqual(port4["operation"], "switching")


class PhaseBPoeScheduleTests(unittest.TestCase):
    def test_poe_schedule_crud_bind_put_id_quirk_and_schedule_ref_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(
                tmp,
                write_tools=(
                    "upsert_poe_schedule",
                    "bind_poe_schedule",
                    "delete_poe_schedule",
                    "delete_schedule",
                    "rollback_from_snapshot",
                ),
            )
            # Simulate Omada 6.2 PUT minting a brand new PoE schedule ID on update!
            ctrl.poe_put_mints_new_id = True

            created = _commit(server, "upsert_poe_schedule", {
                "name": "PoE-Office",
                "schedule": "Work-Hours",
                "enabled": True,
                "portBindings": {"AA-BB-CC-00-00-02": [3]},
            })
            self.assertTrue(created["applied"])
            self.assertEqual(created["after"]["turnOnTime"], "sched-seed-1")

            # delete_schedule must refuse deleting Work-Hours while referenced by PoE-Office
            err_ref = call_tool(server, "delete_schedule", {"schedule": "sched-seed-1"})
            self.assertTrue(err_ref["result"]["isError"])

            # Bind an extra port via bind_poe_schedule even as PUT mints a new ID
            old_id = created["after"]["id"]
            bound = _commit(server, "bind_poe_schedule", {
                "poeSchedule": "PoE-Office",
                "mac": "AA-BB-CC-00-00-02",
                "ports": [4],
                "replace": False,
            })
            self.assertNotEqual(bound["after"]["id"], old_id)
            self.assertEqual(bound["after"]["poePortsMap"]["AA-BB-CC-00-00-02"], [3, 4])

            # Rollback bind restores [3]
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(bound["snapshot"]).name})
            office_now = next(p for p in ctrl.poe_schedules if p["name"] == "PoE-Office")
            self.assertEqual(office_now["poePortsMap"]["AA-BB-CC-00-00-02"], [3])

            deleted = _commit(server, "delete_poe_schedule", {"poeSchedule": "PoE-Office"})
            self.assertFalse(any(p["name"] == "PoE-Office" for p in ctrl.poe_schedules))

            # Rollback delete recreates PoE-Office cleanly
            _commit(server, "rollback_from_snapshot", {"snapshotId": Path(deleted["snapshot"]).name})
            self.assertTrue(any(p["name"] == "PoE-Office" for p in ctrl.poe_schedules))


if __name__ == "__main__":
    unittest.main()
