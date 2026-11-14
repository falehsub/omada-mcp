"""Phase 2 tests: CI lab bootstrap, fixture capture/anonymization, and v5/v6 hardware compat."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
for p in (str(SRC), str(TESTS), str(SCRIPTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

import anonymize_capture as anon_mod  # noqa: E402
import capture_fixtures as cap_mod  # noqa: E402
import docker_lab_init as lab_mod  # noqa: E402
import read_selftest  # noqa: E402
from fake_controller import CONTROLLER_ID, SITE_ID, FakeController, make_config  # noqa: E402
from mock_controller import MockController  # noqa: E402
from write_harness import call_tool, make_write_config, make_write_env, unwrap_ok  # noqa: E402

from omada_mcp._projections import project_controller_row  # noqa: E402
from omada_mcp.client import OmadaClient, OmadaError  # noqa: E402
from omada_mcp.domains.clients_read import project_client  # noqa: E402
from omada_mcp.domains.devices_read import project_device  # noqa: E402
from omada_mcp.server import Server  # noqa: E402


class AnonymizeCaptureTests(unittest.TestCase):
    def test_deterministic_scrubbing_and_strict_verification(self):
        sample = {
            "omadacId": "deadbeef0123456789abcdef01234567",
            "site": "691234567890abcdef123456",
            "siteName": "Villa Home",
            "ssid": "MyPrivateWiFi",
            "password": "super-secret-password",
            "pskSetting": {"securityKey": "wifi-passphrase-123"},
            "device": {
                "mac": "DC-62-79-11-22-33",
                "name": "Core-Switch-Upstairs",
                "sn": "2245109001234",
                "ip": "192.168.50.10",
                "subnetMask": "255.255.255.0",
                "publicIp": "82.167.44.99",
                "ipv6": "2a02:cb00:1234::55/64",
            },
            "deviceDetails": {
                "DC-62-79-11-22-33": {
                    "mac": "dc:62:79:11:22:33",
                    "uplinkUrl": "https://ctrl.local:8043/0123456789abcdef01234567/api/v2/test?token=leak123&cookie=Cookie:%20abc",
                },
            },
            "operator": "admin@myhouse.org",
            "emptyIp": "0.0.0.0",
        }
        # Unscrubbed sample must fail strict verification.
        pre_findings = anon_mod.verify_anonymized(sample, strict_private=True)
        self.assertTrue(pre_findings)

        scrubbed = anon_mod.anonymize_capture(sample)
        self.assertEqual(scrubbed["password"], "REDACTED")
        self.assertEqual(scrubbed["pskSetting"]["securityKey"], "REDACTED")
        self.assertEqual(scrubbed["device"]["subnetMask"], "255.255.255.0")
        self.assertEqual(scrubbed["emptyIp"], "0.0.0.0")
        self.assertEqual(scrubbed["device"]["ip"], "172.16.1.10")
        self.assertTrue(scrubbed["device"]["publicIp"].startswith("198.51."))
        self.assertTrue(scrubbed["device"]["ipv6"].startswith("2001:db8::"))
        self.assertNotIn("Villa Home", json.dumps(scrubbed))
        self.assertNotIn("MyPrivateWiFi", json.dumps(scrubbed))
        self.assertNotIn("leak123", json.dumps(scrubbed))
        self.assertNotIn("admin@myhouse.org", json.dumps(scrubbed))

        # Dict key and nested mac must resolve to same synthetic MAC prefix.
        scrubbed_key_mac = scrubbed["device"]["mac"]
        self.assertTrue(scrubbed_key_mac.startswith("00-11-22-"))
        self.assertIn(scrubbed_key_mac, scrubbed["deviceDetails"])
        nested_mac = scrubbed["deviceDetails"][scrubbed_key_mac]["mac"]
        self.assertEqual(nested_mac.replace(":", "-").upper(), scrubbed_key_mac)

        post_findings = anon_mod.verify_anonymized(scrubbed, strict_private=True)
        self.assertEqual(post_findings, [])

    def test_cli_anonymize_and_verify_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw_path = Path(tmp) / "raw.json"
            out_path = Path(tmp) / "clean.json"
            raw_path.write_text(
                json.dumps({"mac": "EC-75-0C-AA-BB-CC", "ip": "10.0.0.5", "token": "abc"}),
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(anon_mod.main([str(raw_path), "--verify-clean", "--strict-private"]), 1)
                self.assertEqual(anon_mod.main([str(raw_path), "-o", str(out_path)]), 0)
                self.assertEqual(anon_mod.main([str(out_path), "--verify-clean", "--strict-private"]), 0)


class CaptureFixturesTests(unittest.TestCase):
    def test_capture_transport_blocks_mutations_except_login(self):
        transport = cap_mod.CaptureTransport(None, timeout=1.0)
        with self.assertRaises(OmadaError):
            transport.request("POST", "https://127.0.0.1:8043/cid/api/v2/sites/s1/setting/wlans")
        with self.assertRaises(OmadaError):
            transport.request("DELETE", "https://127.0.0.1:8043/cid/api/v2/sites/s1/devices/mac")

    def test_capture_controller_bundle_against_mock_controller(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctrl = MockController()
            cfg = make_write_config(tmp_dir=tmp)
            client = OmadaClient(
                cfg,
                transport=ctrl,
                sleep=lambda _s: None,
                clock=lambda: 0.0,
                log_fn=lambda _m: None,
            )
            bundle = cap_mod.capture_controller_bundle(client)
        self.assertEqual(ctrl.write_request_count, 0)
        self.assertTrue(bundle["devices"])
        self.assertTrue(bundle["clients"])
        self.assertTrue(bundle["deviceDetails"])
        self.assertTrue(bundle["switchPorts"])
        self.assertTrue(bundle["apChannels"])
        self.assertEqual(anon_mod.verify_anonymized(bundle, strict_private=True), [])


class DockerLabInitTests(unittest.TestCase):
    def test_role_and_path_helpers(self):
        roles = [{"id": "r1", "name": "Administrator"}, {"id": "r2", "roleName": "Viewer"}]
        self.assertEqual(lab_mod._find_viewer_role(roles)["id"], "r2")
        self.assertEqual(lab_mod._find_viewer_role([{"name": "Admin"}]), {})
        self.assertEqual(
            lab_mod._api_paths("https://127.0.0.1:8043", "abc", "/api/v2/roles"),
            ["https://127.0.0.1:8043/abc/api/v2/roles", "https://127.0.0.1:8043/api/v2/roles"],
        )

    def _run_mocked_init(self, *, family: str, tmp: str) -> dict[str, object]:
        calls: list[tuple[str, str, dict[str, object] | None]] = []
        state = {"configured": False, "registered": family == "v5", "viewer_created": False}

        def fake_json_req(
            _opener: object,
            method: str,
            url: str,
            body: dict[str, object] | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            calls.append((method, url, body))
            if url.endswith("/api/info"):
                return {
                    "errorCode": 0,
                    "result": {
                        "omadacId": CONTROLLER_ID,
                        "controllerVer": "6.2.14.11" if family == "v6" else "5.15.24.19",
                        "registeredRoot": state["registered"],
                        "configured": state["configured"],
                    },
                }
            if url.endswith("/api/v2/anon/register"):
                state["registered"] = True
                return {"errorCode": 0, "result": {}}
            if url.endswith("/wizardConfigForLocal") and family == "v5":
                return {"errorCode": -1, "msg": "not found"}
            if url.endswith(("/wizardConfigForLocal", "/wizardConfig")):
                state["configured"] = True
                return {"errorCode": 0, "result": {}}
            if url.endswith("/api/v2/login"):
                assert body is not None
                if body.get("username") == "lab_viewer" and not state["viewer_created"]:
                    return {"errorCode": -1, "msg": "bad credentials"}
                return {"errorCode": 0, "result": {"token": "lab-tok"}}
            if "/user/sites" in url or "/sites?" in url:
                return {"errorCode": 0, "result": {"data": [{"id": SITE_ID, "name": "DockerLab"}]}}
            if "/api/v2/roles" in url:
                return {"errorCode": 0, "result": [{"id": "role-viewer", "name": "Viewer"}]}
            if "/api/v2/account/users" in url and family == "v5":
                return {"errorCode": -1, "msg": "legacy v5 uses /users"}
            if url.endswith("/users?token=lab-tok") or "/api/v2/account/users" in url:
                state["viewer_created"] = True
                return {"errorCode": 0, "result": {}}
            return {"errorCode": -1, "msg": f"unhandled {method} {url}"}

        class _FakeJar:
            def __iter__(self):
                return iter([])

        out = Path(tmp)
        with (
            mock.patch.object(lab_mod, "_json_req", side_effect=fake_json_req),
            mock.patch.object(lab_mod, "fetch_server_certificate", return_value=("PEM", "Omada")),
            mock.patch.object(lab_mod, "_make_opener", return_value=(object(), _FakeJar())),
            mock.patch.object(lab_mod.ssl, "create_default_context", return_value=mock.Mock()),
        ):
            summary = lab_mod.init_lab(
                base_url="https://127.0.0.1:8043",
                admin_user="lab_admin",
                admin_password="AdmPassword!1",
                viewer_user="lab_viewer",
                viewer_password="VwrPassword!1",
                site_name="DockerLab",
                ca_out=out / "ca.pem",
                admin_env_out=out / "admin.env",
                viewer_env_out=out / "viewer.env",
                timeout_s=5.0,
            )
        viewer_env = (out / "viewer.env").read_text(encoding="utf-8")
        self.assertIn("OMADA_VERIFY_SSL=true", viewer_env)
        self.assertIn("OMADA_TLS_SERVER_NAME=Omada", viewer_env)
        self.assertIn("OMADA_USERNAME=lab_viewer", viewer_env)
        return {"summary": summary, "calls": calls}

    def test_v6_and_v5_bootstrap_flows(self):
        with tempfile.TemporaryDirectory() as tmp:
            v6 = self._run_mocked_init(family="v6", tmp=tmp)
            urls_v6 = [u for _, u, _ in v6["calls"]]  # type: ignore[misc]
            self.assertTrue(any(u.endswith("/api/v2/anon/register") for u in urls_v6))
            self.assertTrue(any("/wizardConfigForLocal" in u for u in urls_v6))
            self.assertEqual(v6["summary"]["controllerVer"], "6.2.14.11")  # type: ignore[index]

        with tempfile.TemporaryDirectory() as tmp:
            v5 = self._run_mocked_init(family="v5", tmp=tmp)
            urls_v5 = [u for _, u, _ in v5["calls"]]  # type: ignore[misc]
            self.assertFalse(any(u.endswith("/api/v2/anon/register") for u in urls_v5))
            self.assertTrue(any("/wizardConfig" in u for u in urls_v5))
            self.assertTrue(any("/api/v2/users" in u for u in urls_v5))
            self.assertEqual(v5["summary"]["controllerVer"], "5.15.24.19")  # type: ignore[index]


class ReadSelftestHardwareSweepTests(unittest.TestCase):
    def test_read_selftest_33_of_33_pass_with_zero_skips_on_hardware_mock(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctrl = MockController()
            client = OmadaClient(
                make_write_config(tmp_dir=tmp),
                transport=ctrl,
                sleep=lambda _s: None,
                clock=lambda: 0.0,
                log_fn=lambda _m: None,
            )
            report = read_selftest.run_checks(client)
        self.assertEqual(len(report["results"]), 33)
        self.assertEqual(report["passed"], 33)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["skipped"], 0)
        self.assertEqual(ctrl.write_request_count, 0)

    def test_read_selftest_skips_only_hardware_tools_when_site_empty(self):
        fake = FakeController(devices=[], clients=[])
        client = OmadaClient(
            make_config(),
            transport=fake,
            sleep=lambda _s: None,
            clock=lambda: 0.0,
            log_fn=lambda _m: None,
        )
        report = read_selftest.run_checks(client)
        skipped = sorted(r["tool"] for r in report["results"] if r["status"] == "skip")
        self.assertEqual(report["failed"], 0)
        self.assertEqual(
            skipped,
            ["diagnose_client", "get_ap_radios", "get_client", "get_device", "get_rf_scan", "get_switch_ports"],
        )


class HardwareAndV5V6CompatTests(unittest.TestCase):
    def test_project_client_uses_rich_clients_traffic_and_ipsetting_fallbacks(self):
        raw_topo = json.loads((TESTS / "fixtures" / "topology_and_wan.json").read_text(encoding="utf-8"))
        sample_row = copy.deepcopy(raw_topo["client_wireless_detail"])
        sample_row.pop("ip", None)
        sample_row["ipSetting"] = {"useFixedAddr": False, "ip": "172.16.20.44"}

        proj = project_client(sample_row)
        self.assertEqual(proj["ip"], "172.16.20.44")
        self.assertEqual(proj["download"], sample_row["trafficDown"])
        self.assertEqual(proj["upload"], sample_row["trafficUp"])
        self.assertEqual(proj["duration"], sample_row["uptime"])

    def test_project_device_and_acl_calibration(self):
        dev = project_device({"mac": "AA-BB-CC-00-00-01", "compoundModel": "ER7206 v2.20"})
        self.assertEqual(dev["model"], "ER7206 v2.20")

        acl = project_controller_row(
            "acls",
            {
                "id": "a1",
                "index": 0,
                "name": "v5-rule",
                "status": True,
                "policy": 0,
                "sourceFilter": ["n20"],
                "destinationFilter": ["n1"],
                "protocol": 6,
                "unexpectedSecret": "must-strip",
            },
        )
        self.assertEqual(acl["sourceFilter"], ["n20"])
        self.assertEqual(acl["destinationFilter"], ["n1"])
        self.assertEqual(acl["protocol"], 6)
        self.assertNotIn("unexpectedSecret", acl)

    def test_oc200_hardware_v5_and_oc300_hardware_v6_shapes(self):
        oc200 = FakeController(
            cookie_name="TPEAP_SESSIONID",
            controller_ver="5.14.32.56",
            controller_info_extra={"hardware": True, "model": "OC200", "type": 1},
            legacy_login_shape=True,
        )
        oc200_client = OmadaClient(
            make_config(),
            transport=oc200,
            sleep=lambda _s: None,
            clock=lambda: 0.0,
            log_fn=lambda _m: None,
        )
        auth_v5 = oc200_client.authenticate()
        self.assertEqual(auth_v5.controller_family, "hardware-5.x")
        self.assertEqual(auth_v5.privilege, "viewer")
        srv_v5 = Server(oc200_client.config, client=oc200_client)
        acls_res = unwrap_ok(srv_v5.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "list_acls", "arguments": {}},
        }))
        self.assertEqual(len(acls_res["items"]), 1)

        oc300 = FakeController(
            cookie_name="TPOMADA_SESSIONID",
            controller_ver="6.1.0.21",
            controller_info_extra={"hardware": True, "model": "OC300", "type": 1},
            legacy_login_shape=False,
        )
        oc300_client = OmadaClient(
            make_config(),
            transport=oc300,
            sleep=lambda _s: None,
            clock=lambda: 0.0,
            log_fn=lambda _m: None,
        )
        auth_v6 = oc300_client.authenticate()
        self.assertEqual(auth_v6.controller_family, "hardware-6.x")
        self.assertEqual(auth_v6.privilege, "viewer")

    def test_client_lock_to_ap_dryrun_apply_and_unlock(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            dry = unwrap_ok(call_tool(server, "set_client_lock_to_ap", {
                "clientMac": "AA-BB-CC-11-11-01",
                "enabled": True,
                "apMacs": ["ap-living"],
            }))
            self.assertTrue(dry["dryRun"])
            self.assertEqual(ctrl.write_request_count, 0)

            applied = unwrap_ok(call_tool(server, "set_client_lock_to_ap", {
                "clientMac": "AA-BB-CC-11-11-01",
                "enabled": True,
                "apMacs": ["ap-living"],
                "dryRun": False,
                "confirm": dry["confirmToken"],
            }))
            self.assertTrue(applied["applied"])
            self.assertTrue(applied["after"]["enable"])

            unlock_dry = unwrap_ok(call_tool(server, "set_client_lock_to_ap", {
                "clientMac": "AA-BB-CC-11-11-01",
                "enabled": False,
            }))
            unlocked = unwrap_ok(call_tool(server, "set_client_lock_to_ap", {
                "clientMac": "AA-BB-CC-11-11-01",
                "enabled": False,
                "dryRun": False,
                "confirm": unlock_dry["confirmToken"],
            }))
            self.assertFalse(unlocked["after"]["enable"])


if __name__ == "__main__":
    unittest.main()
