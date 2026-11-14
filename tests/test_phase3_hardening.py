"""Phase 3 hardening tests: schema validation, 47-tool write/rollback safety, pagination, monitor lifecycle & MCP conformance."""

from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SRC = ROOT / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from mock_controller import MockController, MockControllerHTTPServer  # noqa: E402
from write_harness import call_tool, make_write_env, unwrap_ok  # noqa: E402

from omada_mcp.client import OmadaClient, OmadaError  # noqa: E402
from omada_mcp.config import WRITE_TOOL_NAMES, Config  # noqa: E402
from omada_mcp.monitor import export_metrics_once, run_watch, serve_metrics_http  # noqa: E402
from omada_mcp.schema_validation import SchemaValidationError, validate_tool_arguments  # noqa: E402
from omada_mcp.server import DEFAULT_PROTOCOL_VERSION, PROTOCOL_VERSIONS, Server  # noqa: E402
from omada_mcp.tools import TOOL_MAP  # noqa: E402


def _make_config(
    base_url: str,
    *,
    read_only: bool = True,
    state_dir: str | None = None,
    write_tools: tuple[str, ...] = (),
) -> Config:
    return Config(
        base_url=base_url,
        username="admin-writer",
        password="pw",
        site_name="Mock Lab Site",
        verify_ssl=False,
        timeout=5.0,
        read_only=read_only,
        write_tools=write_tools,
        snapshot_dir=Path(state_dir) if state_dir else None,
        schema_mode="slim",
    )


def _rpc(server: Server, method: str, params: Any = None, req_id: Any = 1) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    out = server.handle(msg)
    assert out is not None
    return out


class _CountingClient(OmadaClient):
    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.closed_count = 0

    def close(self) -> None:
        self.closed_count += 1
        super().close()


class _FlakyMonitorClient(_CountingClient):
    """Emulates transient controller outages followed by recovery."""

    def __init__(self, config: Config, fail_polls: int = 0) -> None:
        super().__init__(config)
        self.fail_polls = fail_polls
        self.force_outage = False
        self.api_calls = 0
        self._poll_outage_active = False

    def api(self, endpoint: str, method: str = "GET", data: Any = None, **kwargs: Any) -> Any:
        self.api_calls += 1
        if endpoint.startswith("sites/") and self.site is not None:
            if "/devices" in endpoint:
                if self.fail_polls > 0:
                    self.fail_polls -= 1
                    self._poll_outage_active = True
                else:
                    self._poll_outage_active = False
            if self.force_outage or self._poll_outage_active:
                raise OmadaError("transient controller outage")
        return super().api(endpoint, method, data, **kwargs)


class Phase3RecursiveSchemaValidationTests(unittest.TestCase):
    def test_nested_required_and_type_errors_fail_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            baseline_requests = len(ctrl.requests)

            # Nested missing required field ('type') inside source object
            bad_missing = call_tool(server, "create_gateway_acl", {
                "name": "gw-acl-bad",
                "policy": "deny",
                "source": {"ids": ["net-guest-30"]},
                "destination": {"type": "network", "ids": ["net-mgmt-1"]},
                "direction": {"lanToLan": True},
            })
            self.assertEqual(bad_missing["error"]["code"], -32602)
            self.assertIn("source", bad_missing["error"]["message"])
            self.assertEqual(len(ctrl.requests), baseline_requests)

            # Nested unknown property with camelCase hint inside direction
            bad_prop = call_tool(server, "create_gateway_acl", {
                "name": "gw-acl-bad-dir",
                "policy": "deny",
                "source": {"type": "network", "ids": ["net-guest-30"]},
                "destination": {"type": "network", "ids": ["net-mgmt-1"]},
                "direction": {"lan_to_lan": True},
            })
            self.assertEqual(bad_prop["error"]["code"], -32602)
            self.assertIn("lanToLan", bad_prop["error"]["data"]["hint"])

            # Nested anyOf rejection inside pools[0] on set_vlan_dhcp_pools
            bad_pool = call_tool(server, "set_vlan_dhcp_pools", {
                "vlan": 20,
                "pools": [{"start": "192.168.20.10"}],
            })
            self.assertEqual(bad_pool["error"]["code"], -32602)
            self.assertIn("pools[0]", bad_pool["error"]["message"])

            # Boolean passed where integer is required
            bad_bool = call_tool(server, "cycle_poe_port", {
                "deviceMac": "AA-BB-CC-00-00-02",
                "port": True,
            })
            self.assertEqual(bad_bool["error"]["code"], -32602)
            self.assertEqual(len(ctrl.requests), baseline_requests)

    def test_schema_keywords_bounds_patterns_unique_and_aliases(self) -> None:
        from omada_mcp.tools import Tool

        synthetic = Tool(
            name="synthetic_schema_probe",
            title="Synthetic Schema Probe",
            description="probe",
            input_schema={
                "type": "object",
                "required": ["tag", "items"],
                "properties": {
                    "tag": {"type": "string", "minLength": 2, "maxLength": 8, "pattern": r"^[a-z0-9-]+$"},
                    "ratio": {"type": "number", "exclusiveMinimum": 0, "maximum": 1},
                    "items": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 3,
                        "uniqueItems": True,
                        "items": {"type": "integer", "minimum": 1},
                    },
                    "choice": {
                        "oneOf": [
                            {"type": "string", "minLength": 3},
                            {"type": "integer", "minimum": 10},
                        ]
                    },
                },
                "additionalProperties": False,
            },
            output_schema=None,
            read_only=True,
            handler=lambda _c, **_kw: {},
        )
        validate_tool_arguments(
            synthetic,
            {"tag": "lab-1", "ratio": 0.5, "items": [1, 2], "choice": 12},
        )
        for bad_args in (
            {"tag": "x", "items": [1]},
            {"tag": "BAD_TAG", "items": [1]},
            {"tag": "lab-1", "ratio": 0, "items": [1]},
            {"tag": "lab-1", "items": []},
            {"tag": "lab-1", "items": [1, 1]},
            {"tag": "lab-1", "items": [1], "choice": "no"},
        ):
            with self.assertRaises(SchemaValidationError):
                validate_tool_arguments(synthetic, dict(bad_args))

        # Preserve limit clamping and root aliases
        limit_args: dict[str, Any] = {"limit": 99999}
        validate_tool_arguments(TOOL_MAP["list_clients"], limit_args)
        self.assertEqual(limit_args["limit"], 5000)

        ssid_args: dict[str, Any] = {"name": "Alias-Test", "security": "wpa3", "psk": "synthetic-secret-123"}
        validate_tool_arguments(TOOL_MAP["create_ssid"], ssid_args)
        self.assertTrue(ssid_args["dryRun"])


class Phase3WriteMatrixRedactionAndRollbackTests(unittest.TestCase):
    def test_all_47_write_tools_dry_run_confirm_and_secret_redaction(self) -> None:
        secret_tokens = [
            "synthetic-secret-psk-9911",
            "synthetic-guest-secret-never-leak",
            "synthetic-test-passphrase-never-leak",
            "synthetic-lan-secret-password-8822",
            "-----BEGIN PRIVATE KEY-----MOCKKEYDATA-----END PRIVATE KEY-----",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Inject synthetic secret fields onto controller records to verify deep_redact across all 47 envelopes
            ctrl.lan_collection[1]["password"] = secret_tokens[3]
            ctrl.lan_collection[1]["nestedAuth"] = {"privateKey": secret_tokens[4]}
            ctrl.ssids_by_group["wlan-grp-1"][0]["pskSetting"]["securityKey"] = secret_tokens[0]
            ctrl.dhcp_reservations.append({
                "id": "dhcp-seed-1",
                "mac": "AA-BB-CC-11-11-01",
                "ip": "192.168.20.50",
                "netId": "net-iot-20",
                "description": "seed-fixed",
                "status": True,
                "securityKey": secret_tokens[0],
            })
            ctrl.dhcp_reservations.append({
                "id": "dhcp-seed-del",
                "mac": "AA-BB-CC-11-22-99",
                "ip": "192.168.20.99",
                "netId": "net-iot-20",
                "description": "seed-del",
                "status": True,
            })
            ctrl.lan_dns_rules.append({
                "id": "dns-seed-1",
                "name": "seed-dns",
                "domain": "seed.lab.arpa",
                "type": 0,
                "status": True,
                "ipAddressList": ["192.168.20.30"],
            })
            ctrl.mdns_rules.append({
                "id": "mdns-seed-1",
                "name": "seed-mdns",
                "type": 0,
                "status": True,
                "profileIds": ["buildIn-1"],
                "serviceNetworks": ["net-iot-20"],
                "clientNetworks": ["net-mgmt-1"],
            })
            ctrl.policy_routes.append({
                "id": "pr-seed-1",
                "name": "seed-pr",
                "status": True,
                "protocols": [0],
                "sourceType": 0,
                "sourceIds": ["net-iot-20"],
                "destinationType": 0,
                "destinationIds": ["net-lab-40"],
                "interfaceIds": ["2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            })
            ctrl.port_forwards.append({
                "id": "pf-seed-1",
                "name": "seed-pf",
                "enable": True,
                "sourcePort": "8443",
                "ip": "192.168.40.10",
                "destinationPort": "443",
                "protocol": 3,
            })
            ctrl.static_routes.append({
                "id": "sr-seed-1",
                "name": "seed-sr",
                "enable": True,
                "subnet": "10.77.0.0/16",
                "nextHop": "192.168.40.254",
                "interfaceId": "net-lab-40",
                "type": 0,
                "distance": 1,
            })

            # Create one real reversible write so rollback_from_snapshot has a live snapshot target
            prep_dry = unwrap_ok(call_tool(server, "set_vlan_isolation", {"vlan": 20, "isolation": True}))
            prep_commit = unwrap_ok(call_tool(server, "set_vlan_isolation", {
                "vlan": 20,
                "isolation": True,
                "dryRun": False,
                "confirm": prep_dry["confirmToken"],
            }))
            snap_id = Path(prep_commit["snapshot"]).name
            writes_after_prep = ctrl.write_request_count

            sample_args: dict[str, dict[str, Any]] = {
                "assign_ap_wlan_group": {"deviceMac": "AA-BB-CC-00-00-03", "wlanGroup": "Default"},
                "create_eap_acl": {
                    "name": "eap-test",
                    "policy": "deny",
                    "source": {"type": "network", "ids": ["net-guest-30"]},
                    "destination": {"type": "ip_group", "ids": ["grp-printers-02"]},
                },
                "create_gateway_acl": {
                    "name": "gw-test",
                    "policy": "deny",
                    "source": {"type": "network", "ids": ["net-guest-30"]},
                    "destination": {"type": "network", "ids": ["net-mgmt-1"]},
                    "direction": {"lanToLan": True},
                },
                "create_ip_group": {"name": "test-grp-new", "cidrs": ["10.99.0.0/24"]},
                "create_lan_network": {
                    "name": "Sandbox",
                    "vlan": 99,
                    "gatewaySubnet": "192.168.99.1/24",
                    "pools": [{"start": "192.168.99.50", "end": "192.168.99.200"}],
                },
                "create_ssid": {"name": "Lab-New", "security": "wpa2-psk", "psk": secret_tokens[0]},
                "create_switch_acl": {
                    "name": "sw-test",
                    "policy": "deny",
                    "source": {"type": "network", "ids": ["net-guest-30"]},
                    "destination": {"type": "network", "ids": ["net-mgmt-1"]},
                },
                "cycle_poe_port": {"deviceMac": "AA-BB-CC-00-00-02", "port": 3},
                "delete_dhcp_reservation": {"mac": "AA-BB-CC-11-22-99"},
                "delete_gateway_acl": {"rule": "acl-001", "aclType": "gateway"},
                "delete_ip_group": {"group": "grp-printers-02"},
                "delete_lan_dns_rule": {"ruleId": "dns-seed-1"},
                "delete_lan_network": {"vlan": 40},
                "delete_mdns_rule": {"rule": "mdns-seed-1"},
                "delete_policy_route": {"routeId": "pr-seed-1"},
                "delete_port_forward": {"rule": "pf-seed-1"},
                "delete_port_profile": {"profile": "65000000000000000000001e"},
                "delete_ssid": {"ssid": "Lab-Guest", "wlanGroup": "Default"},
                "delete_static_route": {"rule": "sr-seed-1"},
                "reboot_device": {"mac": "AA-BB-CC-00-00-03"},
                "reconnect_client": {"mac": "AA-BB-CC-11-11-02"},
                "release_client_fixed_ip": {"mac": "AA-BB-CC-11-11-01"},
                "replace_ip_group": {"group": "grp-printers-02", "cidrs": ["10.20.30.0/24"]},
                "rollback_from_snapshot": {"snapshotId": snap_id},
                "set_acl_rule_status": {"rule": "acl-001", "status": False, "aclType": "gateway"},
                "set_client_blocked": {"mac": "AA-BB-CC-11-11-01", "blocked": True},
                "set_client_fixed_ip": {"mac": "AA-BB-CC-11-11-01", "ip": "192.168.20.55", "vlan": 20},
                "set_client_lock_to_ap": {"clientMac": "AA-BB-CC-11-11-01", "enabled": True, "apMacs": ["AA-BB-CC-00-00-03"]},
                "set_client_rate_limit": {"clientMac": "AA-BB-CC-11-11-01", "enabled": True, "rateLimitProfileId": "rl-prof-1"},
                "set_upnp": {"enable": True},
                "set_vlan_dhcp_pools": {"vlan": 20, "pools": [{"start": "192.168.20.100", "end": "192.168.20.200"}]},
                "set_vlan_isolation": {"vlan": 20, "isolation": False},
                "start_rf_scan": {"deviceMac": "AA-BB-CC-00-00-03"},
                "update_ap_radio": {"deviceMac": "AA-BB-CC-00-00-03", "band": "5g", "channel": 36},
                "update_client": {"mac": "AA-BB-CC-11-11-01", "name": "workstation-1"},
                "update_device": {"mac": "AA-BB-CC-00-00-03", "name": "ap-living-renamed"},
                "update_gateway_acl": {"rule": "acl-001", "aclType": "gateway", "status": False},
                "update_lan_network": {"vlan": 20, "domain": "iot.local"},
                "update_ssid": {"ssid": "Lab-Main", "wlanGroup": "Default", "broadcast": False, "psk": secret_tokens[0]},
                "update_switch_port": {"deviceMac": "AA-BB-CC-00-00-02", "port": 3, "name": "ap-port"},
                "upsert_dhcp_reservation": {"mac": "AA-BB-CC-11-22-88", "ip": "192.168.20.88", "vlan": 20},
                "upsert_lan_dns_rule": {"name": "printer-host", "domain": "printer.lab.arpa", "ipAddresses": ["192.168.20.44"]},
                "upsert_mdns_rule": {
                    "name": "cast-rule",
                    "profiles": ["buildIn-1"],
                    "serviceNetworks": ["net-iot-20"],
                    "clientNetworks": ["net-mgmt-1"],
                },
                "upsert_policy_route": {
                    "name": "lab-wan",
                    "sourceType": 0,
                    "sourceIds": ["net-iot-20"],
                    "destinationType": 0,
                    "destinationIds": ["net-lab-40"],
                    "interfaceIds": ["2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                },
                "upsert_port_forward": {
                    "name": "ssh-lab",
                    "externalPort": "2222",
                    "forwardIp": "192.168.40.10",
                    "forwardPort": "22",
                },
                "upsert_port_profile": {"name": "IoT-Access", "nativeNetworkId": "net-iot-20"},
                "upsert_static_route": {"name": "lab-subnet", "destination": "10.88.0.0/16", "nextHop": "192.168.40.254"},
            }
            self.assertEqual(len(WRITE_TOOL_NAMES), 47)
            self.assertEqual(set(sample_args.keys()), set(WRITE_TOOL_NAMES))

            for tool_name in sorted(WRITE_TOOL_NAMES):
                args = copy.deepcopy(sample_args[tool_name])
                dry_resp = call_tool(server, tool_name, args)
                self.assertFalse(
                    dry_resp.get("result", {}).get("isError", False),
                    f"{tool_name} dryRun failed: {dry_resp}",
                )
                payload = unwrap_ok(dry_resp)
                self.assertTrue(payload["dryRun"], f"{tool_name} missing dryRun=True")
                self.assertFalse(payload["applied"], f"{tool_name} should not apply on dryRun")
                serialized = json.dumps(dry_resp)
                for secret in secret_tokens:
                    self.assertNotIn(secret, serialized, f"{tool_name} leaked secret in dryRun")
                self.assertEqual(
                    ctrl.write_request_count,
                    writes_after_prep,
                    f"{tool_name} performed unexpected write during dryRun",
                )

                # Invalid confirm must be refused when dryRun=False
                bad_confirm_args = copy.deepcopy(sample_args[tool_name])
                bad_confirm_args["dryRun"] = False
                bad_confirm_args["confirm"] = "wrong-token:mismatch"
                refused = call_tool(server, tool_name, bad_confirm_args)
                self.assertTrue(
                    refused.get("result", {}).get("isError", False),
                    f"{tool_name} accepted invalid confirm token",
                )
                self.assertEqual(ctrl.write_request_count, writes_after_prep)

    def test_stale_superseded_snapshot_refusal_and_fault_injected_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server, _client, ctrl, _ = make_write_env(tmp)
            # Commit #1 on VLAN 20
            d1 = unwrap_ok(call_tool(server, "set_vlan_isolation", {"vlan": 20, "isolation": True}))
            c1 = unwrap_ok(call_tool(server, "set_vlan_isolation", {
                "vlan": 20,
                "isolation": True,
                "dryRun": False,
                "confirm": d1["confirmToken"],
            }))
            snap1 = Path(c1["snapshot"]).name

            # Commit #2 on same target (VLAN 20) supersedes snap1
            d2 = unwrap_ok(call_tool(server, "update_lan_network", {"vlan": 20, "domain": "iot-v2.local"}))
            unwrap_ok(call_tool(server, "update_lan_network", {
                "vlan": 20,
                "domain": "iot-v2.local",
                "dryRun": False,
                "confirm": d2["confirmToken"],
            }))

            # Rolling back snap1 without force must refuse cleanly
            stale_refused = call_tool(server, "rollback_from_snapshot", {"snapshotId": snap1})
            self.assertTrue(stale_refused["result"]["isError"])
            self.assertIn("stale snapshot", stale_refused["result"]["content"][0]["text"].lower())

            # Missing target entity refuses before attempting controller mutation
            assert _client.config.snapshot_dir is not None
            snap_file = _client.config.snapshot_dir / snap1
            self.assertTrue(snap_file.exists())
            saved_nets = copy.deepcopy(ctrl.lan_collection)
            ctrl.lan_collection = [n for n in saved_nets if n.get("id") != "net-iot-20"]
            missing_target = call_tool(server, "rollback_from_snapshot", {"snapshotId": snap1, "force": True})
            self.assertTrue(missing_target["result"]["isError"])
            self.assertIn("no longer exists", missing_target["result"]["content"][0]["text"].lower())
            ctrl.lan_collection = saved_nets

            # Partial-failure fault injection during rollback preserves snapshot and records audit error
            rb_dry = unwrap_ok(call_tool(server, "rollback_from_snapshot", {"snapshotId": snap1, "force": True}))
            def _fail_patch(method: str, _path: str, _body: Any) -> tuple[int, dict[str, Any]] | None:
                if method == "PATCH":
                    return 500, {"errorCode": -1, "msg": "injected controller failure"}
                return None

            ctrl.next_fault_hook = _fail_patch
            rb_fail = call_tool(server, "rollback_from_snapshot", {
                "snapshotId": snap1,
                "force": True,
                "dryRun": False,
                "confirm": rb_dry["confirmToken"],
            })
            self.assertTrue(rb_fail["result"]["isError"])
            self.assertTrue(snap_file.exists())
            audit_lines = [json.loads(line) for line in (_client.config.snapshot_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertTrue(any(entry.get("tool") == "rollback_from_snapshot" and entry.get("result") == "error" for entry in audit_lines))

            # Clean retry succeeds and restores isolation=False
            ctrl.next_fault_hook = None
            rb_ok = unwrap_ok(call_tool(server, "rollback_from_snapshot", {
                "snapshotId": snap1,
                "force": True,
                "dryRun": False,
                "confirm": rb_dry["confirmToken"],
            }))
            self.assertTrue(rb_ok["applied"])
            iot_after = next(n for n in ctrl.lan_collection if n.get("id") == "net-iot-20")
            self.assertFalse(iot_after["isolation"])


class Phase3TruncatedReadReportingTests(unittest.TestCase):
    def test_paginated_reads_surface_truncation_metadata_compatibly(self) -> None:
        ctrl = MockController()
        base_client = copy.deepcopy(ctrl.clients["AA-BB-CC-11-11-01"])
        # Populate 8 clients (6 wireless, 2 wired) and 12 events
        ctrl.clients = {}
        for idx in range(1, 9):
            mac = f"AA-BB-CC-22-00-{idx:02X}"
            row = copy.deepcopy(base_client)
            row.update({
                "mac": mac,
                "name": f"host-{idx}",
                "ip": f"192.168.20.{10 + idx}",
                "wireless": idx <= 6,
                "ssid": "Lab-Main" if idx <= 6 else None,
            })
            ctrl.clients[mac] = row
        now_ms = int(time.time() * 1000)
        ctrl.logs_events = [
            {"id": f"ev-{i}", "level": 4, "type": 10, "module": 2, "content": f"Event {i}", "time": now_ms - i * 1000}
            for i in range(1, 13)
        ]

        with MockControllerHTTPServer(ctrl) as srv:
            cfg = _make_config(srv.base_url)
            server = Server(cfg, OmadaClient(cfg))

            # list_clients hitting limit -> backward-compatible JSON array + structuredContent truncation metadata
            r_clients = _rpc(server, "tools/call", {"name": "list_clients", "arguments": {"limit": 3}})
            self.assertFalse(r_clients["result"]["isError"])
            arr_clients = json.loads(r_clients["result"]["content"][0]["text"])
            self.assertEqual(len(arr_clients), 3)
            self.assertGreater(len(r_clients["result"]["content"]), 1)
            sc = r_clients["result"]["structuredContent"]
            self.assertTrue(sc["truncated"])
            self.assertEqual(sc["count"], 3)
            self.assertEqual(sc["totalRows"], 8)
            self.assertEqual(sc["limit"], 3)

            # list_clients without hitting limit -> not truncated
            r_all = _rpc(server, "tools/call", {"name": "list_clients", "arguments": {"limit": 25}})
            self.assertEqual(len(json.loads(r_all["result"]["content"][0]["text"])), 8)
            self.assertFalse(r_all["result"]["structuredContent"]["truncated"])

            # list_wifi_clients / list_wired_clients / search_clients truncation
            r_wifi = _rpc(server, "tools/call", {"name": "list_wifi_clients", "arguments": {"limit": 2}})
            self.assertTrue(r_wifi["result"]["structuredContent"]["truncated"])
            self.assertEqual(r_wifi["result"]["structuredContent"]["totalRows"], 6)

            r_wired = _rpc(server, "tools/call", {"name": "list_wired_clients", "arguments": {"limit": 1}})
            self.assertTrue(r_wired["result"]["structuredContent"]["truncated"])
            self.assertEqual(r_wired["result"]["structuredContent"]["totalRows"], 2)

            r_search = _rpc(server, "tools/call", {"name": "search_clients", "arguments": {"query": "host-", "limit": 2}})
            self.assertTrue(r_search["result"]["structuredContent"]["truncated"])
            self.assertEqual(r_search["result"]["structuredContent"]["totalRows"], 8)

            # list_logs hitting limit
            r_logs = _rpc(server, "tools/call", {"name": "list_logs", "arguments": {"category": "events", "hours": 24, "limit": 4}})
            self.assertEqual(len(json.loads(r_logs["result"]["content"][0]["text"])), 4)
            self.assertTrue(r_logs["result"]["structuredContent"]["truncated"])
            self.assertEqual(r_logs["result"]["structuredContent"]["totalRows"], 12)

            # OmadaClient.paginate max_pages boundary metadata
            client = server.client
            site = client.resolve_site()
            rows, meta = client.paginate(
                f"sites/{site.site_id}/logs/events?filters.timeStart=1&filters.timeEnd={int(time.time() * 1000)}",
                page_size=3,
                max_pages=2,
            )
            self.assertEqual(len(rows), 6)
            self.assertTrue(meta["_pagination"]["truncated"])
            self.assertEqual(meta["_pagination"]["pagesFetched"], 2)
            self.assertEqual(meta["_pagination"]["maxPages"], 2)
            self.assertEqual(meta["_pagination"]["truncationReason"], "pagination reached maxPages=2")


class Phase3MonitorAndLifecycleResilienceTests(unittest.TestCase):
    def test_watch_backoff_recovery_and_guaranteed_client_close(self) -> None:
        ctrl = MockController()
        with MockControllerHTTPServer(ctrl) as srv:
            cfg = _make_config(srv.base_url)
            created: list[_FlakyMonitorClient] = []
            sleeps: list[float] = []

            def factory(c: Config) -> _FlakyMonitorClient:
                inst = _FlakyMonitorClient(c, fail_polls=2)
                created.append(inst)
                return inst

            out = io.StringIO()
            rc = run_watch(
                cfg,
                interval=1.0,
                iterations=4,
                out=out,
                sleep_fn=sleeps.append,
                client_factory=factory,
                max_backoff=4.0,
            )
            self.assertEqual(rc, 0)
            self.assertEqual(len(created), 1)
            self.assertEqual(created[0].closed_count, 1)
            events = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
            self.assertEqual([e["event"] for e in events], ["degraded", "degraded", "snapshot", "heartbeat"])
            self.assertGreaterEqual(sleeps[0], 1.0)
            self.assertGreater(sleeps[1], sleeps[0])

            # export_metrics_once also closes client cleanly
            exported_clients: list[_CountingClient] = []
            buf = io.StringIO()
            export_rc = export_metrics_once(
                cfg,
                out=buf,
                client_factory=lambda c: exported_clients.append(_CountingClient(c)) or exported_clients[-1],
            )
            self.assertEqual(export_rc, 0)
            self.assertEqual(exported_clients[0].closed_count, 1)
            self.assertIn("omada_device_up", buf.getvalue())

    def test_metrics_http_healthz_degraded_stale_recovery_and_close(self) -> None:
        ctrl = MockController()
        with MockControllerHTTPServer(ctrl) as srv:
            cfg = _make_config(srv.base_url)
            managed = _FlakyMonitorClient(cfg)
            httpd = serve_metrics_http(
                cfg,
                port=0,
                min_scrape_interval=0.0,
                client_factory=lambda _c: managed,
                stale_after=1.0,
            )
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                host, port = httpd.server_address[:2]
                base = f"http://{host}:{port}"

                # Initial healthy /healthz
                with urllib.request.urlopen(f"{base}/healthz", timeout=3) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.read().decode("utf-8").strip(), "ok")

                # Trigger successful /metrics scrape then wait for stale_after (clamped to >=1.0s)
                with urllib.request.urlopen(f"{base}/metrics", timeout=3) as resp:
                    self.assertEqual(resp.status, 200)
                time.sleep(1.1)
                with self.assertRaises(urllib.error.HTTPError) as stale_err:
                    urllib.request.urlopen(f"{base}/healthz?format=json", timeout=3)
                self.assertEqual(stale_err.exception.code, 503)
                stale_body = json.loads(stale_err.exception.read().decode("utf-8"))
                self.assertEqual(stale_body["status"], "stale")

                # Failed scrape transitions /healthz to 503 degraded
                managed.force_outage = True
                with self.assertRaises(urllib.error.HTTPError) as scrape_err:
                    urllib.request.urlopen(f"{base}/metrics", timeout=3)
                self.assertEqual(scrape_err.exception.code, 503)

                with self.assertRaises(urllib.error.HTTPError) as deg_err:
                    urllib.request.urlopen(f"{base}/healthz?format=json", timeout=3)
                self.assertEqual(deg_err.exception.code, 503)
                deg_body = json.loads(deg_err.exception.read().decode("utf-8"))
                self.assertEqual(deg_body["status"], "degraded")
                self.assertIn("outage", deg_body["lastError"])

                # Next successful scrape restores /healthz to 200 ok
                managed.force_outage = False
                with urllib.request.urlopen(f"{base}/metrics", timeout=3) as resp:
                    self.assertEqual(resp.status, 200)
                with urllib.request.urlopen(f"{base}/healthz", timeout=3) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.read().decode("utf-8").strip(), "ok")
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=2)
            self.assertGreaterEqual(managed.closed_count, 1)


class Phase3ProtocolConformanceTests(unittest.TestCase):
    def test_protocol_versions_framing_annotations_and_error_taxonomy(self) -> None:
        ctrl = MockController()
        with MockControllerHTTPServer(ctrl) as srv:
            # Verify initialize negotiates all supported versions with zero network calls
            for ver in PROTOCOL_VERSIONS:
                cfg_ro = _make_config(srv.base_url, read_only=True)
                client = _CountingClient(cfg_ro)
                server = Server(cfg_ro, client)
                init_resp = _rpc(server, "initialize", {"protocolVersion": ver})
                self.assertEqual(init_resp["result"]["protocolVersion"], ver)
                self.assertTrue(init_resp["result"]["capabilities"]["tools"])
                self.assertEqual(len(ctrl.requests), 0)

                # Unknown protocol version falls back to DEFAULT_PROTOCOL_VERSION
                fallback_resp = _rpc(server, "initialize", {"protocolVersion": "1999-01-01"})
                self.assertEqual(fallback_resp["result"]["protocolVersion"], DEFAULT_PROTOCOL_VERSION)

            # LF-only framing, serve() closes client on EOF, and tools/list annotations & outputSchema
            cfg_ro = _make_config(srv.base_url, read_only=True)
            client = _CountingClient(cfg_ro)
            server = Server(cfg_ro, client)
            stdin_lines = "\n".join([
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": DEFAULT_PROTOCOL_VERSION}}),
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
                json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
                json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_site_info", "arguments": {}}}),
                "{not-valid-json",
                json.dumps([1, 2, 3]),
                json.dumps({"jsonrpc": "2.0", "id": 5, "method": "no/such/method"}),
                json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "nonexistent_tool", "arguments": {}}}),
                json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "set_client_blocked", "arguments": {"mac": "AA-BB-CC-11-11-01", "blocked": True}}}),
            ]) + "\n"
            stdout_buf = io.StringIO()
            server.serve(stdin=io.StringIO(stdin_lines), stdout=stdout_buf)
            self.assertEqual(client.closed_count, 1)

            raw_out = stdout_buf.getvalue()
            self.assertNotIn("\r\n", raw_out)
            frames = [json.loads(line) for line in raw_out.splitlines() if line.strip()]
            by_id = {f["id"]: f for f in frames if f.get("id") is not None}

            self.assertEqual(by_id[2]["result"], {})
            listed_tools = by_id[3]["result"]["tools"]
            self.assertTrue(all(t["annotations"]["readOnlyHint"] is True for t in listed_tools))
            self.assertTrue(any("outputSchema" in t for t in listed_tools))
            self.assertFalse(by_id[4]["result"]["isError"])
            self.assertIn("structuredContent", by_id[4]["result"])

            # JSON-RPC / MCP error taxonomy
            parse_errors = [f for f in frames if f.get("error", {}).get("code") == -32700]
            invalid_reqs = [f for f in frames if f.get("error", {}).get("code") == -32600]
            self.assertEqual(len(parse_errors), 1)
            self.assertEqual(len(invalid_reqs), 1)
            self.assertEqual(by_id[5]["error"]["code"], -32601)
            # In read-only mode, both unknown tools and write tools fail closed with -32003
            self.assertEqual(by_id[6]["error"]["code"], -32003)
            self.assertEqual(by_id[7]["error"]["code"], -32003)

            # Invalid schema args -> -32602; read_only=False + empty write_tools -> unknown tool -32601 & write -32003
            invalid_arg_resp = _rpc(server, "tools/call", {"name": "list_clients", "arguments": {"limit": "bad"}})
            self.assertEqual(invalid_arg_resp["error"]["code"], -32602)

            rw_empty_cfg = _make_config(srv.base_url, read_only=False, write_tools=())
            rw_empty_server = Server(rw_empty_cfg, _CountingClient(rw_empty_cfg))
            self.assertEqual(
                _rpc(rw_empty_server, "tools/call", {"name": "nonexistent_tool", "arguments": {}})["error"]["code"],
                -32601,
            )
            self.assertEqual(
                _rpc(rw_empty_server, "tools/call", {"name": "set_client_blocked", "arguments": {"mac": "AA-BB-CC-11-11-01", "blocked": True}})["error"]["code"],
                -32003,
            )

        # Auth failure -> -32002 (unreachable or invalid credentials)
        bad_auth_ctrl = MockController(password="different-pw")
        with MockControllerHTTPServer(bad_auth_ctrl) as bad_srv:
            bad_cfg = _make_config(bad_srv.base_url)
            bad_server = Server(bad_cfg, _CountingClient(bad_cfg))
            auth_err = _rpc(bad_server, "tools/call", {"name": "get_site_info", "arguments": {}})
            self.assertEqual(auth_err["error"]["code"], -32002)


if __name__ == "__main__":
    unittest.main()
