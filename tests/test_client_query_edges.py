"""Adversarial direct-handler cases for paged client collection traversal."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "src", ROOT / "tests"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from client_fixtures import FakeOmadaClient, SyntheticClientSource  # noqa: E402

from omada_mcp.client import OmadaError  # noqa: E402
from omada_mcp.domains._client_query import query_clients  # noqa: E402


class ScriptedClient(FakeOmadaClient):
    """Fixture client with a page callback for controller anomaly injection."""

    def __init__(self, source: SyntheticClientSource, callback):
        super().__init__(source)
        self.callback = callback

    def api(self, endpoint: str, **kwargs):
        payload = super().api(endpoint, **kwargs)
        scripted = self.callback(endpoint, payload)
        return payload if scripted is None else scripted


class ClientQueryEdgeTests(unittest.TestCase):
    def test_10k_inventory_is_reachable_across_bounded_calls(self):
        client = FakeOmadaClient(SyntheticClientSource(10_000))
        cursor = None
        collected = []
        calls = 0
        while True:
            result = query_clients(client, "list_clients", pageSize=500, cursor=cursor)
            collected.extend(result)
            calls += 1
            self.assertLessEqual(result.pagination["pagesFetched"], 20)
            self.assertLessEqual(result.pagination["controllerRequests"], 24)
            cursor = result.pagination.get("nextCursor")
            if cursor is None:
                self.assertTrue(result.pagination["complete"])
                break
            self.assertLess(calls, 30)
        self.assertEqual(len(collected), 10_000)
        self.assertEqual(len({row["mac"] for row in collected}), 10_000)
        self.assertEqual(client.collection_request_count, 100)

    def test_search_finds_match_after_initial_native_page(self):
        client = FakeOmadaClient(SyntheticClientSource(500))
        result = query_clients(
            client, "search_clients", pageSize=10,
            filters={"query": "synthetic-client-00150"},
        )
        self.assertEqual([row["name"] for row in result], ["synthetic-client-00150"])
        self.assertGreaterEqual(result.pagination["pagesFetched"], 2)

    def test_active_source_identity_wins_before_filter_match(self):
        source = SyntheticClientSource(13, active_pattern="alternating")

        def callback(endpoint, payload):
            if "filters.active=false" not in endpoint:
                return None
            duplicate = dict(source.row_at(0))
            duplicate.update({"active": False, "wireless": True, "name": "inactive-duplicate-match"})
            return {"errorCode": 0, "result": {"data": [duplicate], "totalRows": 1}}

        client = ScriptedClient(source, callback)
        result = query_clients(
            client, "search_clients", pageSize=10,
            filters={"query": "inactive-duplicate-match", "wireless": True},
        )
        self.assertEqual(result, [])
        self.assertTrue(result.pagination["complete"])

    def test_viewer_fallback_is_pinned_for_cursor_continuation(self):
        client = FakeOmadaClient(SyntheticClientSource(205, role="Viewer"))
        first = query_clients(client, "list_clients", pageSize=100)
        self.assertEqual(first.pagination["source"], "insight/clients")
        self.assertEqual(client.collection_request_count, 2)
        second = query_clients(
            client, "list_clients", pageSize=100,
            cursor=first.pagination["nextCursor"],
        )
        self.assertEqual(second.pagination["source"], "insight/clients")
        self.assertEqual(client.collection_request_count, 3)

    def test_repeated_page_with_volatile_fields_stops_without_duplicate_output(self):
        source = SyntheticClientSource(300)

        def callback(endpoint, payload):
            if "currentPage=2" not in endpoint:
                return None
            repeated = [dict(source.row_at(i), download=999_999) for i in range(100)]
            return {"errorCode": 0, "result": {"data": repeated, "totalRows": 300}}

        result = query_clients(ScriptedClient(source, callback), "list_clients", pageSize=250)
        self.assertEqual(result.pagination["stopReason"], "repeated_page")
        self.assertFalse(result.pagination["complete"])
        self.assertEqual(len(result), 100)
        self.assertEqual(len({row["mac"] for row in result}), len(result))

    def test_page_cycle_is_detected_by_identity_fingerprint(self):
        source = SyntheticClientSource(500)

        def callback(endpoint, payload):
            page = int(parse_qs(urlsplit(endpoint).query)["currentPage"][0])
            if page != 3:
                return None
            cycle = [dict(source.row_at(i), upload=888_888) for i in range(100)]
            return {"errorCode": 0, "result": {"data": cycle, "totalRows": 500}}

        result = query_clients(ScriptedClient(source, callback), "list_clients", pageSize=450)
        self.assertEqual(result.pagination["stopReason"], "repeated_page")
        self.assertEqual(len(result), 200)
        self.assertEqual(len({row["mac"] for row in result}), 200)

    def test_overlapping_page_boundary_is_deduplicated(self):
        source = SyntheticClientSource(201)

        def callback(endpoint, payload):
            page = int(parse_qs(urlsplit(endpoint).query)["currentPage"][0])
            if page != 2:
                return None
            overlap = [source.row_at(i) for i in range(99, 199)]
            return {"errorCode": 0, "result": {"data": overlap, "totalRows": 201}}

        result = query_clients(ScriptedClient(source, callback), "list_clients", pageSize=201)
        self.assertFalse(result.pagination["complete"])
        self.assertEqual(len(result), 200)
        self.assertEqual(len({row["mac"] for row in result}), 200)

    def test_expired_and_wrong_scope_cursors_are_rejected_without_io(self):
        client = FakeOmadaClient(SyntheticClientSource(205))
        first = query_clients(client, "list_clients", pageSize=10)
        token = first.pagination["nextCursor"]
        before = client.request_count
        client.client_cursors.clear()
        with self.assertRaises(OmadaError):
            query_clients(client, "list_clients", pageSize=10, cursor=token)
        self.assertEqual(client.request_count, before)

        first = query_clients(client, "list_clients", pageSize=10)
        token = first.pagination["nextCursor"]
        client.config.base_url = "https://other.synthetic.invalid"
        before = client.request_count
        with self.assertRaises(OmadaError):
            query_clients(client, "list_clients", pageSize=10, cursor=token)
        self.assertEqual(client.request_count, before)

    def test_query_request_metadata_stays_inside_budget(self):
        client = FakeOmadaClient(SyntheticClientSource(10_000))
        result = query_clients(client, "search_clients", pageSize=10, filters={"query": "not-present"})
        self.assertLessEqual(result.pagination["controllerRequests"], 24)
        self.assertEqual(result.pagination["controllerRequests"], client.request_count)
        self.assertFalse(result.pagination["complete"])

    def test_malformed_page_and_missing_filter_fields_are_incomplete(self):
        source = SyntheticClientSource(1)

        def malformed(_endpoint, _payload):
            return {"errorCode": 0, "result": {"data": "not-a-row-list", "totalRows": 1}}

        bad = query_clients(ScriptedClient(source, malformed), "list_clients", pageSize=10)
        self.assertFalse(bad.pagination["complete"])
        self.assertEqual(bad.pagination["stopReason"], "source_error")

        def missing(_endpoint, _payload):
            row = {"mac": "02:00:00:00:00:01", "name": "sparse"}
            return {"errorCode": 0, "result": {"data": [row], "totalRows": 1}}

        sparse = query_clients(
            ScriptedClient(source, missing), "search_clients", pageSize=10,
            filters={"active": True},
        )
        self.assertFalse(sparse.pagination["complete"])
        self.assertEqual(sparse.pagination["stopReason"], "field_unavailable")
        self.assertTrue(sparse.pagination["warnings"])


if __name__ == "__main__":
    unittest.main()
