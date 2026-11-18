"""Legacy client-search collection preserves merge semantics and completeness."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
for path in (TESTS.parent / "src", TESTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from client_fixtures import FakeOmadaClient, SyntheticClientSource  # noqa: E402
from fake_controller import make_client  # noqa: E402

from omada_mcp.client import OmadaError, RequestBudgetExceeded  # noqa: E402
from omada_mcp.domains._client_search import collect_search_rows  # noqa: E402


def row(mac: str, name: str, active: bool, **extra):
    return {"mac": mac, "name": name, "active": active, "wireless": True,
            "guest": False, "vid": 10, **extra}


class LegacyClientSearchTests(unittest.TestCase):
    def test_unfiltered_merge_keeps_inactive_position_but_active_value_wins(self):
        client, fake, _ = make_client()
        client.authenticate()
        fake.clients = [
            row("AA-BB-CC-00-00-01", "inactive-first", False),
            row("AA-BB-CC-00-00-02", "inactive-only", False),
            row("AA-BB-CC-00-00-01", "active-replacement", True),
            row("AA-BB-CC-00-00-03", "active-only", True),
            {"name": "no-mac-active", "active": True},
            {"name": "no-mac-inactive", "active": False},
        ]

        collected, meta = collect_search_rows(client, client.site, active=None)

        self.assertEqual(
            [item["name"] for item in collected],
            ["active-replacement", "inactive-only", "active-only"],
        )
        self.assertTrue(meta["complete"])
        self.assertTrue(meta["totalRowsExact"])
        self.assertEqual(meta["source"], "clients")
        self.assertEqual(meta["pagesFetched"], 2)
        self.assertEqual(meta["controllerRequests"], 2)

    def test_explicit_active_keeps_first_observed_duplicate_and_macless_rows(self):
        client, fake, _ = make_client()
        client.authenticate()
        fake.clients = [
            row("AA-BB-CC-00-00-01", "first", True),
            row("AA-BB-CC-00-00-01", "second", True),
            {"name": "no-mac", "active": True},
        ]

        collected, meta = collect_search_rows(client, client.site, active=True)

        self.assertEqual([item["name"] for item in collected], ["first", "no-mac"])
        # FakeController repeats its page instead of serving an empty page 2;
        # the collector must not claim exactness in that anomalous traversal.
        self.assertFalse(meta["complete"])
        self.assertEqual(meta["pagesFetched"], 2)

    def test_viewer_fallback_is_scoped_and_reported(self):
        source = SyntheticClientSource(205, role="Viewer")
        client = FakeOmadaClient(source)

        collected, meta = collect_search_rows(client, client.current_site(), active=True)

        self.assertEqual(len(collected), 205)
        self.assertTrue(meta["complete"])
        self.assertFalse(meta["totalRowsExact"])
        self.assertNotIn("totalRows", meta)
        self.assertEqual(meta["source"], "insight/clients")
        self.assertTrue(meta["warnings"])
        # One denied rich request plus three native insight pages.
        self.assertEqual(meta["controllerRequests"], 4)
        self.assertEqual(meta["pagesFetched"], 4)

    def test_incomplete_source_never_reports_an_exact_total(self):
        source = SyntheticClientSource(2_501)
        client = FakeOmadaClient(source)

        collected, meta = collect_search_rows(client, client.current_site(), active=True)

        self.assertEqual(len(collected), 2_000)
        self.assertFalse(meta["complete"])
        self.assertTrue(meta["truncated"])
        self.assertFalse(meta["totalRowsExact"])
        self.assertNotIn("totalRows", meta)
        self.assertEqual(meta["sourceTotalRows"], 2_501)
        self.assertEqual(meta["pagesFetched"], 20)
        self.assertEqual(meta["controllerRequests"], 20)

    def test_page_attempt_limit_is_shared_between_active_sources(self):
        source = SyntheticClientSource(3_000, active_pattern="alternating")
        client = FakeOmadaClient(source)

        collected, meta = collect_search_rows(client, client.current_site(), active=None)

        self.assertEqual(len(collected), 2_000)
        self.assertFalse(meta["complete"])
        self.assertEqual(meta["pagesFetched"], 20)
        self.assertEqual(meta["controllerRequests"], 20)
        self.assertEqual(meta["maxPages"], 20)

    def test_fallback_at_page_budget_boundary_drops_partial_rich_rows(self):
        source = SyntheticClientSource(1_900, active_pattern="inactive")

        class DenyActiveSource(FakeOmadaClient):
            def api(self, endpoint: str, **kwargs):
                if "filters.active=true" in endpoint:
                    for budget in self._budgets:
                        if budget.used >= budget.limit:
                            raise RequestBudgetExceeded(used=budget.used, limit=budget.limit)
                    for budget in self._budgets:
                        budget.used += 1
                    self.request_count += 1
                    return {"errorCode": -1007, "msg": "Permission denied", "result": {}}
                return super().api(endpoint, **kwargs)

        client = DenyActiveSource(source)

        collected, meta = collect_search_rows(client, client.current_site(), active=None)

        self.assertEqual(collected, [])
        self.assertEqual(meta["source"], "insight/clients")
        self.assertFalse(meta["complete"])
        self.assertFalse(meta["totalRowsExact"])
        self.assertNotIn("totalRows", meta)
        self.assertEqual(meta["pagesFetched"], 20)
        self.assertEqual(meta["rowsScanned"], 1_900)
        self.assertEqual(meta["controllerRequests"], 20)
        self.assertTrue(meta["warnings"])

    def test_mid_source_permission_fallback_keeps_all_successful_row_scans(self):
        source = SyntheticClientSource(205)

        class DenyRichSecondPage(FakeOmadaClient):
            def api(self, endpoint: str, **kwargs):
                if "filters.active=true" in endpoint and "currentPage=2" in endpoint:
                    for budget in self._budgets:
                        if budget.used >= budget.limit:
                            raise RequestBudgetExceeded(used=budget.used, limit=budget.limit)
                    for budget in self._budgets:
                        budget.used += 1
                    self.request_count += 1
                    raise OmadaError("Permission denied", code=-1007)
                return super().api(endpoint, **kwargs)

        client = DenyRichSecondPage(source)

        collected, meta = collect_search_rows(client, client.current_site(), active=True)

        self.assertEqual(len(collected), 205)
        self.assertTrue(meta["complete"])
        self.assertEqual(meta["source"], "insight/clients")
        self.assertEqual(meta["rowsScanned"], 305)  # 100 rich + 205 insight
        self.assertEqual(meta["pagesFetched"], 5)  # 2 rich attempts + 3 fallback pages
        self.assertEqual(meta["controllerRequests"], 5)


if __name__ == "__main__":
    unittest.main()
