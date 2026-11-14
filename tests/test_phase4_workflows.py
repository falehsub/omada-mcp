"""Phase 4 workflow tests: multi-site, diff_config_snapshots, and client roaming diagnostics."""

from __future__ import annotations

import concurrent.futures
import copy
import json
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from mock_controller import MOCK_SITE_ID, MockController  # noqa: E402
from write_harness import call_tool, make_write_config  # noqa: E402

from omada_mcp.client import OmadaClient  # noqa: E402
from omada_mcp.config import Config  # noqa: E402
from omada_mcp.server import Server  # noqa: E402
from omada_mcp.tools import TOOL_MAP  # noqa: E402

SITE_B_ID = "mocksite0000000000000002"


class MultiSiteMockController(MockController):
    """Two-site stateful mock controller isolating devices/clients/LANs/groups by site ID."""

    def __init__(self, *, visible_site_b: bool = True, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.visible_site_b = visible_site_b
        self.sites[0]["name"] = "Site-Alpha"
        site_b = {
            "id": SITE_B_ID,
            "name": "Site-Beta",
            "type": 0,
            "wan": True,
            "lan": True,
            "wlan": False,
        }
        if visible_site_b:
            self.sites.append(site_b)

        self._site_lock = threading.Lock()
        self.site_requests: list[tuple[str, str]] = []
        self._site_b_devices: list[dict[str, Any]] = [
            {
                "mac": "AA-BB-CC-22-00-01",
                "name": "Beta-AP-Main",
                "type": "ap",
                "model": "EAP653",
                "showModel": "EAP653 v1.0",
                "ip": "10.99.0.10",
                "status": 14,
                "statusCategory": 1,
                "clientCount": 1,
            }
        ]
        self._site_b_lan: list[dict[str, Any]] = [
            {
                "id": "beta-net-1",
                "name": "Beta-Core",
                "vlan": 100,
                "gatewaySubnet": "10.99.0.1/24",
                "purpose": 1,
            }
        ]
        self._site_b_groups: list[dict[str, Any]] = [
            {
                "id": "beta-grp-1",
                "name": "Beta-Servers",
                "type": 0,
                "ipList": [{"ip": "10.99.0.50"}],
            }
        ]
        self._alpha_devices = self.devices
        self._alpha_lan = self.lan_collection
        self._alpha_groups = self.groups

    def _dispatch(self, method: str, raw_path: str, query: str, body: Any) -> tuple[int, bytes]:
        with self._site_lock:
            ep = self._strip_api_prefix(raw_path)
            m = re.match(r"sites/([^/]+)", ep)
            if m:
                target_id = m.group(1)
                self.site_requests.append((method, target_id))
                if target_id == SITE_B_ID:
                    self.devices = self._site_b_devices
                    self.lan_collection = self._site_b_lan
                    self.groups = self._site_b_groups
                else:
                    self.devices = self._alpha_devices
                    self.lan_collection = self._alpha_lan
                    self.groups = self._alpha_groups
            try:
                return super()._dispatch(method, raw_path, query, body)
            finally:
                self.devices = self._alpha_devices
                self.lan_collection = self._alpha_lan
                self.groups = self._alpha_groups


def _make_server(
    ctrl: MockController,
    *,
    tmp: str,
    site_name: str | None = None,
    site_id: str | None = None,
    allow_cross_site: bool = False,
    read_only: bool = True,
    write_tools: tuple[str, ...] = (),
) -> tuple[Server, OmadaClient]:
    cfg: Config = make_write_config(
        tmp_dir=tmp,
        read_only=read_only,
        write_tools=write_tools,
    )
    cfg.username = ctrl.username
    cfg.password = ctrl.password
    cfg.site_name = site_name
    cfg.site_id = site_id
    cfg.allow_cross_site = allow_cross_site
    client = OmadaClient(
        cfg,
        transport=ctrl,
        sleep=lambda _s: None,
        clock=lambda: 0.0,
        log_fn=lambda _m: None,
    )
    return Server(cfg, client=client), client


class MultiSiteWorkflowTests(unittest.TestCase):
    def test_list_sites_respects_rbac_and_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctrl_all = MultiSiteMockController(username="viewer-ro", role="Viewer", visible_site_b=True)
            server_all, _ = _make_server(ctrl_all, tmp=tmp)
            resp = call_tool(server_all, "list_sites", {})
            self.assertFalse(resp["result"]["isError"])
            sc = resp["result"]["structuredContent"]
            self.assertEqual(sc["count"], 2)
            self.assertEqual([s["name"] for s in sc["items"]], ["Site-Alpha", "Site-Beta"])
            self.assertTrue(sc["items"][0]["isConfiguredDefault"])
            self.assertFalse(sc["items"][1]["isConfiguredDefault"])

            ctrl_restricted = MultiSiteMockController(username="viewer-a", role="Viewer", visible_site_b=False)
            server_a, _ = _make_server(ctrl_restricted, tmp=tmp)
            resp_a = call_tool(server_a, "list_sites", {})
            self.assertEqual(resp_a["result"]["structuredContent"]["count"], 1)
            denied = call_tool(server_a, "get_site_info", {"site": "Site-Beta"})
            self.assertTrue(denied["result"]["isError"])

    def test_unpinned_per_call_site_override_is_stateless_and_cache_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctrl = MultiSiteMockController(visible_site_b=True)
            server, client = _make_server(ctrl, tmp=tmp)

            alpha = call_tool(server, "get_site_info", {})["result"]["structuredContent"]
            beta = call_tool(server, "get_site_info", {"site": "Site-Beta"})["result"]["structuredContent"]
            after_alpha = call_tool(server, "get_site_info", {})["result"]["structuredContent"]

            self.assertEqual(alpha["id"], MOCK_SITE_ID)
            self.assertEqual(beta["id"], SITE_B_ID)
            self.assertEqual(beta["name"], "Site-Beta")
            self.assertEqual(after_alpha["id"], MOCK_SITE_ID)
            self.assertEqual(client.site.site_id, MOCK_SITE_ID)

            # Scoped cache across both sites must never leak Site-Alpha devices into Site-Beta.
            with client.scoped_cache():
                with client.use_site("Site-Alpha"):
                    devs_a = TOOL_MAP["list_devices"].handler(client)
                with client.use_site(SITE_B_ID):
                    devs_b = TOOL_MAP["list_devices"].handler(client)
            self.assertEqual(devs_b[0]["name"], "Beta-AP-Main")
            self.assertNotEqual(devs_a[0]["name"], devs_b[0]["name"])
            self.assertEqual(client.site.site_id, MOCK_SITE_ID)

    def test_concurrent_site_calls_have_zero_thread_interference(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctrl = MultiSiteMockController(visible_site_b=True)
            server, client = _make_server(ctrl, tmp=tmp)
            # Pre-authenticate so worker threads exercise pure per-call thread-local routing.
            client.authenticate()

            def call_site(site_arg: str | None) -> str:
                args = {"site": site_arg} if site_arg else {}
                out = call_tool(server, "list_devices", args)["result"]["structuredContent"]
                return out["items"][0]["name"]

            targets = ["Site-Beta" if i % 2 else "Site-Alpha" for i in range(12)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(call_site, targets))

            for target, first_dev_name in zip(targets, results, strict=True):
                if target == "Site-Beta":
                    self.assertEqual(first_dev_name, "Beta-AP-Main")
                else:
                    self.assertNotEqual(first_dev_name, "Beta-AP-Main")

    def test_strict_site_pinning_blocks_cross_site_until_allow_cross_site_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctrl = MultiSiteMockController(visible_site_b=True)
            server_pinned, _ = _make_server(
                ctrl,
                tmp=tmp,
                site_name="Site-Alpha",
                allow_cross_site=False,
                read_only=False,
                write_tools=("create_ip_group",),
            )
            # Same-site explicit override works while pinned.
            same = call_tool(server_pinned, "get_site_info", {"site": "Site-Alpha"})
            self.assertFalse(same["result"]["isError"])

            ctrl.site_requests.clear()
            blocked_read = call_tool(server_pinned, "get_site_info", {"site": "Site-Beta"})
            self.assertTrue(blocked_read["result"]["isError"])
            self.assertIn("OMADA_ALLOW_CROSS_SITE=true", blocked_read["result"]["content"][0]["text"])
            # Cross-site refusal must fire before any Site-Beta API request is made.
            self.assertFalse(any(sid == SITE_B_ID for _, sid in ctrl.site_requests))

            blocked_write = call_tool(
                server_pinned,
                "create_ip_group",
                {"name": "Remote", "cidrs": ["10.99.0.0/24"], "site": "Site-Beta"},
            )
            self.assertTrue(blocked_write["result"]["isError"])
            self.assertEqual(ctrl.write_request_count, 0)

            server_cross, _ = _make_server(
                ctrl,
                tmp=tmp,
                site_name="Site-Alpha",
                allow_cross_site=True,
                read_only=False,
                write_tools=("create_ip_group",),
            )
            beta_snap = call_tool(server_cross, "get_config_snapshot", {"site": "Site-Beta", "objects": ["groups"]})
            self.assertFalse(beta_snap["result"]["isError"])
            self.assertEqual(beta_snap["result"]["structuredContent"]["groups"]["all"][0]["name"], "Beta-Servers")

            beta_write_dry = call_tool(
                server_cross,
                "create_ip_group",
                {"name": "Beta-New", "cidrs": ["10.99.1.0/24"], "site": "Site-Beta", "dryRun": True},
            )
            self.assertFalse(beta_write_dry["result"]["isError"])
            self.assertTrue(beta_write_dry["result"]["structuredContent"]["dryRun"])

    def test_global_tools_omit_site_parameter(self):
        self.assertNotIn("site", TOOL_MAP["list_sites"].input_schema["properties"])
        self.assertNotIn("site", TOOL_MAP["explain_error"].input_schema["properties"])
        self.assertIn("site", TOOL_MAP["get_site_info"].input_schema["properties"])
        self.assertIn("site", TOOL_MAP["diff_config_snapshots"].input_schema["properties"])


class ConfigDiffWorkflowTests(unittest.TestCase):
    def test_offline_diff_ignores_volatile_telemetry_and_reordering_and_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctrl = MultiSiteMockController()
            server, client = _make_server(ctrl, tmp=tmp)

            baseline = {
                "site": {"id": MOCK_SITE_ID, "name": "Site-Alpha"},
                "objects": ["networks", "acls", "wlans", "devices"],
                "networks": [
                    {"id": "n1", "name": "LAN", "vlan": 1, "dhcpEnabled": True},
                    {"id": "n2", "name": "IoT", "vlan": 20, "dhcpEnabled": True},
                ],
                "acls": {
                    "aclDisable": False,
                    "aclDisableReliable": False,
                    "warning": "old note",
                    "count": 1,
                    "rules": [{"id": "acl-1", "name": "Block-IoT", "status": True, "policy": 1}],
                },
                "wlans": [
                    {"id": "w1", "name": "Corp", "vlan": 1, "securityKey": "super-secret-psk-1"},
                ],
                "devices": [
                    {"mac": "aa:bb:cc:00:00:01", "name": "GW", "uptimeSec": 100, "cpuUtil": 5},
                ],
                "warnings": ["old warning"],
            }

            # Same logical config with different order, volatile telemetry, and warnings -> no changes.
            noisy_same = copy.deepcopy(baseline)
            noisy_same["networks"] = list(reversed(baseline["networks"]))
            noisy_same["devices"][0]["uptimeSec"] = 99999
            noisy_same["devices"][0]["cpuUtil"] = 44
            noisy_same["warnings"] = ["different warning"]
            noisy_same["acls"]["warning"] = "changed advisory"

            no_drift = call_tool(server, "diff_config_snapshots", {"baseline": baseline, "current": noisy_same})
            self.assertFalse(no_drift["result"]["isError"])
            sc_clean = no_drift["result"]["structuredContent"]
            self.assertFalse(sc_clean["hasChanges"])
            self.assertEqual(sc_clean["comparedSource"], "snapshot")
            self.assertEqual(client.request_count, 0)

            # Mutated config -> deterministic added / removed / changed + secret redaction.
            drifted = copy.deepcopy(baseline)
            drifted["networks"].pop(1)  # IoT removed
            drifted["networks"].append({"id": "n3", "name": "Cameras", "vlan": 30, "dhcpEnabled": True})  # added
            drifted["acls"]["aclDisable"] = True
            drifted["acls"]["rules"][0]["policy"] = 0
            drifted["wlans"][0]["securityKey"] = "new-secret-psk-2"

            drift_resp = call_tool(server, "diff_config_snapshots", {"baseline": baseline, "current": drifted})
            sc = drift_resp["result"]["structuredContent"]
            self.assertTrue(sc["hasChanges"])
            self.assertEqual(sc["summary"], {"sectionsChanged": 2, "added": 1, "removed": 1, "changed": 2})
            self.assertEqual(sc["sections"]["networks"]["added"][0]["label"], "Cameras")
            self.assertEqual(sc["sections"]["networks"]["removed"][0]["label"], "IoT")
            self.assertEqual(sc["sections"]["acls"]["changed"][0]["changes"]["policy"], {"before": 1, "after": 0})
            self.assertEqual(
                sc["sections"]["acls"]["changed"][1]["changes"]["aclDisable"],
                {"before": False, "after": True},
            )
            rendered = json.dumps(sc)
            self.assertNotIn("super-secret-psk-1", rendered)
            self.assertNotIn("new-secret-psk-2", rendered)
            self.assertEqual(client.request_count, 0)

    def test_live_diff_and_cross_site_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctrl = MultiSiteMockController(visible_site_b=True)
            server, _ = _make_server(ctrl, tmp=tmp, allow_cross_site=True)

            alpha_snap = call_tool(
                server,
                "get_config_snapshot",
                {"objects": ["networks", "devices", "groups"]},
            )["result"]["structuredContent"]

            # Live comparison against Site-Alpha immediately after capture -> zero drift.
            same_live = call_tool(server, "diff_config_snapshots", {"baseline": alpha_snap})["result"]["structuredContent"]
            self.assertEqual(same_live["comparedSource"], "live")
            self.assertFalse(same_live["crossSite"])
            self.assertFalse(same_live["hasChanges"])

            # Cross-site diff against Site-Beta -> detects Site-Beta differences cleanly.
            cross_live = call_tool(
                server,
                "diff_config_snapshots",
                {"baseline": alpha_snap, "site": "Site-Beta"},
            )["result"]["structuredContent"]
            self.assertTrue(cross_live["crossSite"])
            self.assertTrue(cross_live["hasChanges"])
            self.assertEqual(cross_live["currentSite"]["id"], SITE_B_ID)


class ClientRoamingDiagnosticsTests(unittest.TestCase):
    def test_missing_or_empty_history_reports_honest_availability_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctrl = MultiSiteMockController()
            server, _ = _make_server(ctrl, tmp=tmp)

            # Empty pastConnection -> ROAM_HISTORY_UNAVAILABLE info finding, historyAvailable=False.
            empty_diag = call_tool(server, "diagnose_client", {"mac": "AA-BB-CC-11-11-02"})["result"]["structuredContent"]
            self.assertEqual(empty_diag["telemetryAvailability"]["pastConnections"], "empty")
            self.assertFalse(empty_diag["roamingSummary"]["historyAvailable"])
            codes = {f["code"] for f in empty_diag["findings"]}
            self.assertIn("ROAM_HISTORY_UNAVAILABLE", codes)
            self.assertNotIn("Live link and observed connection/roam history show no faults", " ".join(empty_diag["nextSteps"]))

            # Controller refuses pastConnection & logs/events (-1007) -> TELEMETRY_PARTIAL + ROAM_HISTORY_UNAVAILABLE.
            ctrl.next_fault_hook = lambda method, path, _body: (
                (200, {"errorCode": -1007, "msg": "History/logs restricted."})
                if method == "GET" and ("/insight/pastConnection" in path or "/logs/events" in path)
                else None
            )
            partial_diag = call_tool(server, "diagnose_client", {"mac": "AA-BB-CC-11-11-02"})["result"]["structuredContent"]
            self.assertEqual(partial_diag["telemetryAvailability"]["pastConnections"], "unavailable")
            self.assertEqual(partial_diag["telemetryAvailability"]["logs"], "partial")
            p_codes = {f["code"] for f in partial_diag["findings"]}
            self.assertIn("TELEMETRY_PARTIAL", p_codes)
            self.assertIn("ROAM_HISTORY_UNAVAILABLE", p_codes)

    def test_roaming_transitions_short_sessions_and_lock_mismatch_correlation(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctrl = MultiSiteMockController()
            mac_raw = "AA-BB-CC-11-11-02"
            ctrl.clients[mac_raw]["lockToApMac"] = "AA-BB-CC-00-00-99"
            ctrl.past_connections = [
                {
                    "mac": mac_raw, "name": "iphone-roamer", "ssid": "Lab-Main",
                    "apMac": "AA-BB-CC-00-00-03", "apName": "AP-Lobby",
                    "firstSeen": 1700000100000, "duration": 60,
                },
                {
                    "mac": mac_raw, "name": "iphone-roamer", "ssid": "Lab-Main",
                    "apMac": "AA-BB-CC-00-00-04", "apName": "AP-Hall",
                    "firstSeen": 1700000200000, "duration": 45,
                },
                {
                    "mac": mac_raw, "name": "iphone-roamer", "ssid": "Lab-Main",
                    "apMac": "AA-BB-CC-00-00-03", "apName": "AP-Lobby",
                    "firstSeen": 1700000300000, "duration": 90,
                },
                {
                    "mac": mac_raw, "name": "iphone-roamer", "ssid": "Lab-Main",
                    "apMac": "AA-BB-CC-00-00-05", "apName": "AP-Office",
                    "firstSeen": 1700000400000, "duration": 500,
                },
            ]
            now_ms = 1700000500000
            ctrl.logs_events = [
                {"id": "e1", "time": now_ms, "level": 4, "content": f"Client {mac_raw} roamed from AP-Lobby to AP-Hall"},
                {"id": "e2", "time": now_ms, "level": 4, "content": f"Client {mac_raw} disconnected from AP-Hall"},
                {"id": "e3", "time": now_ms, "level": 4, "content": f"Client {mac_raw} disconnected from AP-Lobby"},
                {"id": "e4", "time": now_ms, "level": 4, "content": f"Client {mac_raw} disconnected from AP-Office"},
            ]

            server, _ = _make_server(ctrl, tmp=tmp)
            diag = call_tool(server, "diagnose_client", {"mac": mac_raw, "hours": 0})["result"]["structuredContent"]
            roam = diag["roamingSummary"]
            self.assertTrue(roam["historyAvailable"])
            self.assertEqual(roam["sessionCount"], 4)
            self.assertEqual(roam["uniqueApCount"], 3)
            self.assertEqual(roam["apTransitionCount"], 3)
            self.assertEqual(roam["shortSessionCount"], 3)
            self.assertEqual(roam["disconnectLogCount"], 3)
            self.assertEqual(len(roam["roamLogEvents"]), 1)

            codes = {f["code"] for f in diag["findings"]}
            self.assertIn("FREQUENT_DISCONNECTS", codes)
            self.assertIn("FREQUENT_AP_ROAMING", codes)
            self.assertIn("LOCK_TO_AP_MISMATCH", codes)
            self.assertNotIn("ROAM_HISTORY_UNAVAILABLE", codes)


if __name__ == "__main__":
    unittest.main()
