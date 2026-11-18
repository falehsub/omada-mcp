"""Viewer client results separate activity evidence from historical rows."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
for path in (TESTS.parent / "src", TESTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from client_fixtures import FakeOmadaClient, SyntheticClientSource  # noqa: E402

from omada_mcp.domains.clients_read import (  # noqa: E402
    _get_client,
    _list_clients,
    _list_wifi_clients,
    _list_wired_clients,
    _search_clients,
)


class ViewerHistory(SyntheticClientSource):
    def __init__(self) -> None:
        super().__init__(6, role="Viewer")

    def row_at(self, index: int) -> dict:
        row = super().row_at(index)
        if index == 0:
            row.update(active=True, wireless=False)
        elif index == 1:
            row.update(active=False, wireless=True)
        elif index == 2:
            row.pop("active")
        elif index == 3:
            row.update(active=None, wireless=None, guest=None, vid=None, vlan="invalid")
        elif index == 4:
            row.update(active="false", wireless=2, guest={}, vid=False)
        else:
            row.update(active="true", wireless="true", vid="0")
        return row


class ViewerClientContractTests(unittest.TestCase):
    def test_viewer_list_filters_activity_before_counting_a_page(self):
        for tool, expected_indices in (
            (_list_clients, [0, 5]),
            (_list_wifi_clients, [5]),
            (_list_wired_clients, [0]),
        ):
            for options in ({}, {"pageSize": 10}):
                with self.subTest(tool=tool.__name__, options=options):
                    source = ViewerHistory()
                    result = tool(FakeOmadaClient(source), **options)
                    self.assertEqual([row["mac"] for row in result],
                                     [source.row_at(i)["mac"] for i in expected_indices])
                    self.assertTrue(all(row["active"] is True for row in result))
                    self.assertFalse(result.pagination["complete"])
                    self.assertFalse(result.pagination["totalRowsExact"])
                    self.assertEqual(result.pagination["sourceTotalRows"], source.row_count)
                    self.assertTrue(result.pagination["warnings"])

    def test_viewer_lookup_and_unfiltered_search_keep_explicit_unknown_activity(self):
        source = ViewerHistory()
        for options in ({}, {"pageSize": 10}):
            with self.subTest(options=options):
                client = FakeOmadaClient(source)
                result = _search_clients(client, **options)
                self.assertEqual([row["active"] for row in result], [True, False, None, None, False, True])
                self.assertTrue(result.pagination["complete"])
                self.assertFalse(result.pagination["totalRowsExact"])
                self.assertNotIn("totalRows", result.pagination)
        found = _get_client(FakeOmadaClient(source), source.row_at(2)["mac"])
        self.assertIsNone(found["active"])

    def test_viewer_totals_are_inexact_even_when_the_history_was_fully_read(self):
        source = SyntheticClientSource(8, role="Viewer", active_pattern="alternating")
        legacy = _list_clients(FakeOmadaClient(source))
        paged = _list_clients(FakeOmadaClient(source), pageSize=10)
        for result in (legacy, paged):
            self.assertEqual(len(result), 4)
            self.assertTrue(result.pagination["complete"])
            self.assertFalse(result.pagination["totalRowsExact"])
            self.assertEqual(result.pagination["sourceTotalRows"], 8)
        self.assertEqual(legacy.pagination["totalRows"], 4)
        self.assertNotIn("totalRows", paged.pagination)

    def test_viewer_legacy_limit_counts_matches_after_inactive_first_page(self):
        class LastActive(SyntheticClientSource):
            def row_at(self, index: int) -> dict:
                return dict(super().row_at(index), active=index == 100)

        source = LastActive(101, role="Viewer")
        client = FakeOmadaClient(source)
        result = _list_clients(client, limit=1)
        self.assertEqual([row["mac"] for row in result], [source.row_at(100)["mac"]])
        self.assertEqual(client.request_count, 3)  # Rich denial, then two insight pages.

    def test_invalid_source_values_do_not_match_false_or_zero(self):
        class Source(SyntheticClientSource):
            def row_at(self, index: int) -> dict:
                row = super().row_at(index)
                if index == 0:
                    row.update(active=None, wireless=None, guest=None, vid=None, vlan={})
                elif index == 1:
                    row.update(active="0", wireless="false", guest=0, vid="invalid", vlan="0")
                else:
                    row.update(active=None, wireless=True)
                return row

        source = Source(3, role="Viewer")
        for options in ({}, {"pageSize": 10}):
            with self.subTest(options=options):
                result = _search_clients(FakeOmadaClient(source), active=False, wireless=False,
                                         guest=False, vlan=0, **options)
                self.assertEqual([row["mac"] for row in result], [source.row_at(1)["mac"]])
                self.assertIs(result[0]["wireless"], False)
                self.assertIs(result[0]["active"], False)
                self.assertEqual(result[0]["vlan"], 0)
                self.assertFalse(result.pagination["complete"])

    def test_definite_nonmatch_wins_over_an_unavailable_filter(self):
        source = ViewerHistory()
        client = FakeOmadaClient(source)
        result = _search_clients(client, active=False, vlan=4094, pageSize=10)
        self.assertEqual(result, [])
        # One row lacks both activity and VLAN evidence, so the result stays incomplete.
        self.assertFalse(result.pagination["complete"])

        class KnownVlan(SyntheticClientSource):
            def row_at(self, index: int) -> dict:
                row = dict(super().row_at(index), vid=20)
                row.pop("active")
                return row

        for options in ({}, {"pageSize": 10}):
            with self.subTest(options=options):
                rejected = _search_clients(FakeOmadaClient(KnownVlan(1, role="Viewer")),
                                           active=False, vlan=4094, **options)
                self.assertEqual(rejected, [])
                self.assertTrue(rejected.pagination["complete"])
