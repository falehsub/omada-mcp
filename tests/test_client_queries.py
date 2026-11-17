"""Public client query contracts using isolated controller responses."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
for path in (TESTS.parent / "src", TESTS):
    sys.path.insert(0, str(path))

from client_fixtures import FakeOmadaClient, SyntheticClientSource  # noqa: E402
from fake_controller import make_config  # noqa: E402

from omada_mcp.client import OmadaError  # noqa: E402
from omada_mcp.client_cursors import CursorStore  # noqa: E402
from omada_mcp.domains._client_projection import project_client  # noqa: E402
from omada_mcp.domains.clients_read import (  # noqa: E402
    _get_client,
    _list_clients,
    _search_clients,  # noqa: E402
)
from omada_mcp.server import Server  # noqa: E402


class ClientQueryTests(unittest.TestCase):
    def server(self, count=205):
        client = FakeOmadaClient(SyntheticClientSource(count))
        client.config = make_config()
        client.authenticate()
        return Server(client.config, client=client), client.source

    def call(self, server, name="list_clients", **args):
        response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": name, "arguments": args}})
        self.assertNotIn("error", response, response)
        self.assertFalse(response["result"].get("isError"), response)
        return response["result"]

    def test_page_cursor_and_sparse_envelope(self):
        server, _ = self.server()
        first = self.call(server, pageSize=50, fields=["name", "ip"], resultFormat="envelope")
        data = first["structuredContent"]
        self.assertEqual(json.loads(first["content"][0]["text"]), data)
        self.assertEqual(len(first["content"]), 1)
        self.assertEqual(data["count"], 50)
        self.assertEqual(data["pagesFetched"], 1)
        self.assertEqual(data["selectedFields"], ["mac", "name", "ip"])
        self.assertEqual(set(data["items"][0]), {"mac", "name", "ip"})
        self.assertNotIn("totalRows", data)
        self.assertFalse(data["totalRowsExact"])
        second = self.call(server, cursor=data["nextCursor"])["structuredContent"]
        self.assertEqual(second["items"][0]["name"], server.client.source.row_at(50)["name"])
        self.assertEqual(second["pagesFetched"], 0)
        replay = self.call(server, cursor=data["nextCursor"])["structuredContent"]
        self.assertEqual(second["items"], replay["items"])

    def test_filtered_page_counts_matches(self):
        server, _ = self.server()
        data = self.call(server, "list_wifi_clients", pageSize=80)["structuredContent"]
        self.assertEqual(data["count"], 80)
        self.assertTrue(all(row["wireless"] for row in data["items"]))
        self.assertEqual(data["pagesFetched"], 2)

    def test_legacy_array_shape_and_full_fields(self):
        server, _ = self.server(13)
        result = self.call(server)
        self.assertIsInstance(json.loads(result["content"][0]["text"]), list)
        self.assertEqual(len(result["structuredContent"]["items"][0]), 25)

    def test_conflicting_cursor_options_and_unknown_fields_rejected(self):
        server, _ = self.server()
        data = self.call(server, pageSize=10)["structuredContent"]
        before = server.client.request_count
        for args in ({"pageSize": 10, "limit": 10}, {"fields": ["secret"]},
                     {"fields": []}, {"fields": ["mac", "mac"]},
                     {"cursor": data["nextCursor"], "pageSize": 11}):
            response = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                      "params": {"name": "list_clients", "arguments": args}})
            self.assertTrue("error" in response or response["result"].get("isError"), response)
        self.assertEqual(server.client.request_count, before)

    def test_legacy_small_limit_and_lookup_stop_after_first_native_page(self):
        server, _ = self.server(2000)
        data = _list_clients(server.client, limit=50)
        self.assertEqual(len(data), 50)
        self.assertEqual(data.pagination["totalRows"], 2000)
        self.assertFalse(data.pagination["totalRowsExact"])
        self.assertEqual(server.client.collection_request_count, 1)
        found = _get_client(server.client, server.client.source.row_at(0)["name"])
        self.assertEqual(found["name"], server.client.source.row_at(0)["name"])
        self.assertEqual(server.client.collection_request_count, 2)

    def test_legacy_search_incomplete_does_not_supply_exact_negative_total(self):
        server, _ = self.server(2501)
        result = _search_clients(server.client, active=True, query="absent")
        self.assertEqual(result, [])
        self.assertFalse(result.pagination["complete"])
        self.assertFalse(result.pagination["totalRowsExact"])
        self.assertNotIn("totalRows", result.pagination)

    def test_cursor_capacity_is_an_explicit_incomplete_stop(self):
        server, _ = self.server()
        server.client.client_cursors = CursorStore(max_bytes=1)
        data = self.call(server, pageSize=1)["structuredContent"]
        self.assertFalse(data["complete"])
        self.assertFalse(data["hasMore"])
        self.assertNotIn("nextCursor", data)
        self.assertEqual(data["stopReason"], "cursor_capacity")

    def test_lookup_on_bounded_prefix_cannot_claim_absence(self):
        server, _ = self.server(2501)
        with self.assertRaisesRegex(OmadaError, "incomplete"):
            _get_client(server.client, "02:FF:FF:FF:FF:FF")

    def test_untrusted_signal_is_projected_to_numeric_or_null(self):
        self.assertIsNone(project_client({"signalLevel": {"secret": "canary"}})["signal"])

    def test_legacy_combined_search_overlap_cannot_claim_exact_total(self):
        client = FakeOmadaClient(SyntheticClientSource(200, active_pattern="inactive"))
        original = client.api
        def overlapping(endpoint, **kwargs):
            payload = original(endpoint, **kwargs)
            if "filters.active=false" in endpoint and "currentPage=2&" in endpoint:
                payload["result"]["data"] = [client.source.row_at(i) for i in range(99, 199)]
            return payload
        client.api = overlapping
        data = _search_clients(client, limit=500)
        self.assertEqual(len(data), 199)
        self.assertFalse(data.pagination["complete"])
        self.assertFalse(data.pagination["totalRowsExact"])
        self.assertNotIn("totalRows", data.pagination)

    def test_macless_rows_are_retained_without_claiming_unique_total(self):
        server, _ = self.server(1)
        original = server.client.source.row_at
        def macless(index):
            return {key: value for key, value in original(index).items() if key != "mac"}
        server.client.source.row_at = macless
        result = self.call(server, pageSize=5)["structuredContent"]
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["mac"], "")
        self.assertTrue(result["complete"])
        self.assertFalse(result["totalRowsExact"])
        self.assertNotIn("totalRows", result)
        self.assertTrue(result["warnings"])

    def test_native_page_boundary_sizes(self):
        for count in (0, 1, 99, 100, 101, 2001):
            with self.subTest(count=count):
                server, _ = self.server(count)
                cursor = None
                identities = []
                while True:
                    args = {"cursor": cursor} if cursor else {"pageSize": 100}
                    data = self.call(server, **args)["structuredContent"]
                    identities.extend(row["mac"] for row in data["items"])
                    cursor = data.get("nextCursor")
                    if cursor is None:
                        self.assertTrue(data["complete"])
                        self.assertEqual(data["totalRows"], count)
                        break
                self.assertEqual(len(set(identities)), count)


if __name__ == "__main__":
    unittest.main()
