"""Focused contracts for scalable synthetic client fixtures."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "src", ROOT / "tests"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from client_fixtures import (  # noqa: E402
    DEFAULT_SECRET_CANARY,
    SUPPORTED_ROW_COUNTS,
    FakeOmadaClient,
    SyntheticClientSource,
)

from omada_mcp.client import RequestBudgetExceeded  # noqa: E402
from omada_mcp.domains.clients_read import _get_client, _list_clients  # noqa: E402


class SyntheticClientFixtureTests(unittest.TestCase):
    def test_supported_sizes_generate_deterministic_unique_rows(self):
        self.assertEqual(SUPPORTED_ROW_COUNTS, (13, 50, 205, 500, 2_000, 5_000, 10_000))
        for size in SUPPORTED_ROW_COUNTS:
            source = SyntheticClientSource(size)
            self.assertEqual(source.row_count, size)
            if size:
                first = source.row_at(0)
                self.assertEqual(first, SyntheticClientSource(size).row_at(0))
                self.assertEqual(len({source.row_at(index)["mac"] for index in range(size)}), size)
                self.assertEqual(first["mac"], "02:00:00:00:00:00")
                last = size - 1
                self.assertEqual(
                    source.row_at(last)["mac"],
                    f"02:00:{(last >> 24) & 255:02x}:{(last >> 16) & 255:02x}:{(last >> 8) & 255:02x}:{last & 255:02x}",
                )
                self.assertEqual(first["secretCanary"], DEFAULT_SECRET_CANARY)

    def test_fake_serves_only_requested_native_page(self):
        client = FakeOmadaClient(SyntheticClientSource(10_000))
        response = client.api(
            "sites/fixture-site/clients?filters.active=true&currentPage=2&currentPageSize=100"
        )
        rows = response["result"]["data"]
        self.assertEqual(len(rows), 100)
        self.assertEqual(rows[0]["name"], "synthetic-client-00100")
        self.assertEqual(response["result"]["totalRows"], 10_000)
        self.assertEqual(client.collection_request_count, 1)
        self.assertEqual(client.request_count, 1)
        self.assertEqual(
            client.response_body_bytes,
            len(json.dumps(response, separators=(",", ":")).encode()),
        )

    def test_active_inactive_patterns_and_viewer_fallback_are_controlled(self):
        source = SyntheticClientSource(13, active_pattern="alternating")
        rich = FakeOmadaClient(source).api("sites/fixture-site/clients?filters.active=true")
        self.assertEqual(rich["result"]["totalRows"], 7)
        self.assertTrue(all(row["active"] for row in rich["result"]["data"]))

        viewer = FakeOmadaClient(SyntheticClientSource(13, role="Viewer"))
        result = _list_clients(viewer, limit=50)
        self.assertEqual(len(result), 13)
        self.assertEqual(viewer.collection_request_count, 2)  # denied rich, then insight

    def test_current_small_projection_and_lookup_do_not_leak_canary(self):
        client = FakeOmadaClient(SyntheticClientSource(13))
        listed = _list_clients(client, limit=50)
        self.assertEqual(len(listed), 13)
        self.assertEqual(listed[0]["mac"], "02:00:00:00:00:00")
        self.assertNotIn("secretCanary", listed[0])

        client = FakeOmadaClient(SyntheticClientSource(2_000))
        first = _get_client(client, "02:00:00:00:00:00")
        self.assertEqual(first["name"], "synthetic-client-00000")
        self.assertNotIn("secretCanary", first)
        self.assertEqual(client.collection_request_count, 1)

    def test_request_budget_caps_fixture_dispatch(self):
        client = FakeOmadaClient(SyntheticClientSource(205))
        with self.assertRaises(RequestBudgetExceeded), client.request_budget(1):
            client.api("sites/fixture-site/clients?filters.active=true&currentPage=1&currentPageSize=100")
            client.api("sites/fixture-site/clients?filters.active=true&currentPage=2&currentPageSize=100")


if __name__ == "__main__":
    unittest.main()
