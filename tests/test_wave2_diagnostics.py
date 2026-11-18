from __future__ import annotations

import tempfile
import time
import unittest
from unittest.mock import patch

from write_harness import call_tool, make_write_env, unwrap_ok


class DiagnosticEvidenceTests(unittest.TestCase):
    def test_wan_next_step_uses_gateway_and_reachability_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _, ctrl, _ = make_write_env(tmp, read_only=True)
            ctrl.has_gateway = False
            ctrl.devices = [row for row in ctrl.devices if row["type"] != "gateway"]
            result = unwrap_ok(call_tool(server, "diagnose_wan", {}))
            self.assertEqual(result["status"], "no_gateway")
            self.assertTrue(result["nextSteps"])
            self.assertNotIn("look operational", " ".join(result["nextSteps"]))

    def test_wan_ip_alone_does_not_prove_internet_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _, ctrl, _ = make_write_env(tmp, read_only=True)
            ctrl.next_fault_hook = lambda method, endpoint, _: (
                (200, {"errorCode": -1007}) if method == "GET" and "/gateways/" in endpoint else None
            )
            result = unwrap_ok(call_tool(server, "diagnose_wan", {}))
            self.assertTrue(result["wan"]["ports"])
            self.assertEqual(result["status"], "unknown")
            self.assertNotIn("look operational", " ".join(result["nextSteps"]))

    def test_client_findings_only_count_direct_events_and_in_window_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _, ctrl, _ = make_write_env(tmp, read_only=True)
            client_mac = "AA-BB-CC-11-11-02"
            parent_ap = ctrl.clients[client_mac]["apName"]
            now_ms = int(time.time() * 1000)
            ctrl.past_connections = [
                {"mac": client_mac, "firstSeen": now_ms - 3 * 3600 * 1000, "duration": 60},
                {"mac": client_mac, "firstSeen": now_ms - 30 * 1000, "duration": 20, "unexpected": "unprojected"},
                {"mac": client_mac, "duration": 10},
            ]
            ctrl.logs_events = [
                {"id": "direct", "time": now_ms, "content": f"Disconnected client {client_mac}."},
                {"id": "parent", "time": now_ms, "content": f"AP {parent_ap} disconnected"},
                {"id": "other", "time": now_ms, "content": f"Client AA-BB-CC-11-11-01 disconnected from {parent_ap}"},
                {"id": "outside-window", "time": now_ms - 3 * 3600 * 1000,
                 "content": f"Client {client_mac} disconnected"},
            ]
            result = unwrap_ok(call_tool(server, "diagnose_client", {"mac": client_mac, "hours": 1}))
            self.assertEqual(result["roamingSummary"]["disconnectLogCount"], 1)
            self.assertEqual(result["roamingSummary"]["sessionCount"], 1)
            self.assertEqual([log["id"] for log in result["recentLogs"]], ["direct"])
            self.assertEqual({log["id"] for log in result["infrastructureLogs"]}, {"parent", "other"})
            self.assertEqual(result["telemetryAvailability"]["pastConnections"], "partial")
            self.assertEqual(result["coverage"]["pastConnections"]["outsideWindow"], 1)
            self.assertEqual(result["coverage"]["pastConnections"]["undated"], 1)
            self.assertEqual(result["timeWindow"]["hours"], 1)
            self.assertTrue(result["nextSteps"])
            self.assertNotIn("unexpected", result["pastConnections"][0])
            self.assertNotIn("FREQUENT_DISCONNECTS", {f["code"] for f in result["findings"]})


class AuditBudgetTests(unittest.TestCase):
    def test_lan_failure_is_visible_without_asserting_unknown_vlan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _, ctrl, _ = make_write_env(tmp, read_only=True)
            ctrl.next_fault_hook = lambda method, endpoint, _: (
                (200, {"errorCode": -1007})
                if method == "GET" and endpoint.partition("?")[0].endswith("/setting/lan/networks") else None
            )
            result = unwrap_ok(call_tool(server, "network_audit", {}))
            self.assertEqual(result["coverage"]["lanNetworks"], "unavailable")
            self.assertTrue(any("LAN networks" in w and "-1007" in w for w in result["warnings"]))
            self.assertNotIn("CLIENT_UNEXPECTED_VLAN", {f["code"] for f in result["findings"]})
            self.assertEqual(result["dhcpPools"], [])

    def test_network_audit_preserves_partial_result_after_budget_exhaustion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _, _, _ = make_write_env(tmp, read_only=True)
            with patch("omada_mcp.domains.audit_snapshot._NETWORK_AUDIT_REQUEST_LIMIT", 2):
                result = unwrap_ok(call_tool(server, "network_audit", {}))
            self.assertEqual(result["controllerRequests"], 2)
            self.assertFalse(result["complete"])
            self.assertEqual(result["coverage"]["lanNetworks"], "unavailable")

    def test_fleet_retains_partial_site_and_continues_to_next_site(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _, ctrl, _ = make_write_env(tmp, read_only=True)
            server.config.allow_cross_site = True
            second = "mocksite0000000000000002"
            ctrl.sites.append({"id": second, "name": "Mock Branch", "wan": True})
            first = ctrl.sites[0]["id"]
            ctrl.next_fault_hook = lambda method, endpoint, _: (
                (200, {"errorCode": -1007})
                if method == "GET" and endpoint.partition("?")[0].endswith(f"/sites/{first}/devices") else None
            )
            result = unwrap_ok(call_tool(server, "audit_all_sites", {}))
            self.assertEqual(result["auditedSites"], 2)
            self.assertEqual(result["completeSites"], 1)
            self.assertEqual(result["partialSites"], 1)
            self.assertFalse(result["complete"])
            unavailable, available = result["sites"]
            self.assertEqual(unavailable["status"], "partial")
            self.assertIsNone(unavailable["deviceCount"])
            self.assertIsNone(unavailable["healthy"])
            self.assertEqual(available["id"], second)
            self.assertEqual(available["status"], "complete")

    def test_fleet_limits_requests_per_site_and_across_sites(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _, ctrl, _ = make_write_env(tmp, read_only=True)
            server.config.allow_cross_site = True
            first = ctrl.sites[0]["id"]
            second = "mocksite0000000000000002"
            ctrl.sites.append({"id": second, "name": "Mock Branch", "wan": True})
            ctrl.next_fault_hook = lambda method, endpoint, _: (
                (200, {"errorCode": 0, "result": {"data": [ctrl.devices[0]], "totalRows": 250}})
                if method == "GET" and endpoint.partition("?")[0].endswith(f"/sites/{first}/devices") else None
            )
            with patch("omada_mcp.domains.fleet_vpn_read._FLEET_SITE_REQUEST_LIMIT", 2):
                result = unwrap_ok(call_tool(server, "audit_all_sites", {}))
            self.assertEqual([site["controllerRequests"] for site in result["sites"]], [2, 2])
            self.assertEqual([site["status"] for site in result["sites"]], ["partial", "complete"])
            with patch("omada_mcp.domains.fleet_vpn_read._FLEET_AUDIT_REQUEST_LIMIT", 2):
                bounded = unwrap_ok(call_tool(server, "audit_all_sites", {}))
            self.assertTrue(bounded["truncated"])
            self.assertEqual(bounded["controllerRequests"], 2)
            self.assertEqual(bounded["auditedSites"], 1)
