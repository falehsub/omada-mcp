"""Exercise accepted but incorrect controller writes against synthetic fixtures."""

from __future__ import annotations

import tempfile
import unittest

from write_harness import call_confirmed, make_write_env, unwrap_ok


class WriteVerificationTests(unittest.TestCase):
    def assert_verification_error(self, response, detail):
        result = response["result"]
        self.assertTrue(result["isError"], result)
        self.assertIn(detail, result["content"][0]["text"])

    def test_lan_create_detects_a_wrong_dhcp_pool(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)

            def alter_dhcp_pool(method, endpoint, body):
                if method == "POST" and endpoint.partition("?")[0].endswith("/setting/lan/networks"):
                    body["dhcpSettings"]["ipRangePool"][0]["ipaddrStart"] = "198.51.100.70"
                return None

            controller.next_fault_hook = alter_dhcp_pool
            response = call_confirmed(server, "create_lan_network", {
                "name": "Fixture LAN", "vlan": 88, "gatewaySubnet": "198.51.100.1/24",
                "pools": [{"start": "198.51.100.50", "end": "198.51.100.100"}],
            })
            self.assert_verification_error(response, "LAN DHCP pools did not match intent")

    def test_lan_create_accepts_equivalent_dhcp_field_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)

            def normalize_dhcp(method, endpoint, body):
                if method == "POST" and endpoint.partition("?")[0].endswith("/setting/lan/networks"):
                    dhcp = body["dhcpSettings"]
                    dhcp["leaseTime"] = dhcp.pop("leasetime")
                    pool = dhcp.pop("ipRangePool")[0]
                    dhcp["ipaddrStart"], dhcp["ipaddrEnd"] = pool["ipaddrStart"], pool["ipaddrEnd"]
                return None

            controller.next_fault_hook = normalize_dhcp
            result = unwrap_ok(call_confirmed(server, "create_lan_network", {
                "name": "Fixture LAN", "vlan": 88, "gatewaySubnet": "198.51.100.1/24",
                "pools": [{"start": "198.51.100.50", "end": "198.51.100.100"}],
            }))
            self.assertTrue(result["verified"])

    def test_scoped_acl_create_checks_endpoints_protocols_and_switch_binding(self):
        changes = {"sourceIds": ["net-lab-40"], "destinationIds": ["net-iot-20"], "protocols": [17], "bindingType": 0}
        for field, replacement in changes.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                server, _, controller, _ = make_write_env(tmp)

                def alter_acl_field(method, endpoint, body, key=field, value=replacement):
                    if method == "POST" and endpoint.partition("?")[0].endswith("/setting/firewall/acls"):
                        body[key] = value
                    return None

                controller.next_fault_hook = alter_acl_field
                response = call_confirmed(server, "create_switch_acl", {
                    "name": "Fixture ACL", "policy": "permit",
                    "source": {"type": "network", "ids": ["IoT"]},
                    "destination": {"type": "network", "ids": ["Lab"]},
                    "protocols": [6], "bindingType": "vlan", "networkId": "net-iot-20",
                })
                self.assert_verification_error(response, field)

    def test_missing_acl_bidirectionality_reports_accepted_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            acl = controller.acls[0]
            acl.pop("biDirectional", None)
            endpoint_suffix = f"/setting/firewall/acls/{acl['id']}"

            def omit_legacy_flag(method, endpoint, body):
                if method == "PUT" and endpoint.partition("?")[0].endswith(endpoint_suffix):
                    body.pop("biDirectional", None)
                return None

            controller.next_fault_hook = omit_legacy_flag
            result = unwrap_ok(call_confirmed(server, "update_gateway_acl", {
                "rule": acl["id"], "aclType": "gateway", "biDirectional": True,
            }))
            self.assertTrue(result["applied"])
            self.assertFalse(result["verified"])
            self.assertEqual(result["outcome"], "accepted")

    def test_ip_group_swap_detects_missing_sibling_acl_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _, controller, _ = make_write_env(tmp)
            target = next(group for group in controller.groups if group["name"] == "shared-printers")
            sibling = next(group for group in controller.groups if group["name"] == "lab-devices")
            target_id, sibling_id = target["id"], sibling["groupId"]
            original = controller.acls[0]
            original.update({"policy": 1, "sourceType": 1, "sourceIds": [target_id, sibling_id]})
            endpoint_suffix = f"/setting/firewall/acls/{original['id']}"

            def drop_sibling_reference(method, endpoint, body):
                if method == "PUT" and endpoint.partition("?")[0].endswith(endpoint_suffix):
                    body["sourceIds"] = [group_id for group_id in body["sourceIds"] if group_id != sibling_id]
                return None

            controller.next_fault_hook = drop_sibling_reference
            response = call_confirmed(server, "replace_ip_group", {"group": target_id, "cidrs": ["198.51.100.0/24"]})
            self.assert_verification_error(response, "ACL sourceIds did not preserve all intended references")
            self.assertEqual(response["result"]["structuredContent"]["outcome"], "uncertain")
            self.assertTrue(any((group.get("groupId") or group.get("id")) == target_id for group in controller.groups))


if __name__ == "__main__":
    unittest.main()
