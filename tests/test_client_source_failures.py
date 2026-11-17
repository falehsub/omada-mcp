"""Regression coverage for malformed and unstable client-page sources."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

TESTS = Path(__file__).resolve().parent
for path in (TESTS.parent / "src", TESTS):
    sys.path.insert(0, str(path))

from client_fixtures import FakeOmadaClient, SyntheticClientSource  # noqa: E402

from omada_mcp.client import OmadaError  # noqa: E402
from omada_mcp.domains._client_query import query_clients  # noqa: E402


def row(index: int) -> dict[str, Any]:
    return {
        "mac": f"02:00:00:00:00:{index:02x}",
        "name": f"client-{index}",
        "hostName": f"host-{index}",
        "ip": f"192.0.2.{index + 1}",
        "active": True,
        "wireless": True,
        "guest": False,
        "ssid": "Test SSID",
        "networkName": "Test LAN",
        "vid": 10,
    }


class ScriptedClient(FakeOmadaClient):
    def __init__(self, responses: list[dict[str, Any] | BaseException]) -> None:
        super().__init__(SyntheticClientSource(0))
        self.responses = iter(responses)
        self.endpoints: list[str] = []

        def api(endpoint: str, **_kwargs: Any) -> dict[str, Any]:
            self.endpoints.append(endpoint)
            response = next(self.responses)
            if isinstance(response, BaseException):
                raise response
            return response

        self.api = api  # type: ignore[method-assign]


def page(rows: list[dict[str, Any]], total: int | None) -> dict[str, Any]:
    result: dict[str, Any] = {"data": rows}
    if total is not None:
        result["totalRows"] = total
    return {"errorCode": 0, "result": result}


class ClientSourceFailureTests(unittest.TestCase):
    def test_malformed_result_and_missing_data_are_incomplete(self) -> None:
        responses = [
            {"errorCode": 0, "result": []},
            {"errorCode": 0, "result": {"totalRows": 1}},
        ]
        for response in responses:
            with self.subTest(response=response):
                client = ScriptedClient([response])
                result = query_clients(client, "list_clients", pageSize=10)

                self.assertEqual(result.pagination["stopReason"], "source_error")
                self.assertFalse(result.pagination["complete"])
                self.assertFalse(result.pagination["hasMore"])
                self.assertEqual(list(result), [])

    def test_empty_page_with_positive_total_is_not_complete(self) -> None:
        client = ScriptedClient([page([], 3)])

        result = query_clients(client, "list_clients", pageSize=10)

        self.assertEqual(result.pagination["stopReason"], "source_changed")
        self.assertFalse(result.pagination["complete"])
        self.assertNotIn("totalRows", result.pagination)

    def test_short_page_that_cannot_satisfy_known_total_is_not_complete(self) -> None:
        client = ScriptedClient([page([row(i) for i in range(100)], 200),
                                 page([row(i) for i in range(100, 150)], 200)])

        result = query_clients(client, "list_clients", pageSize=200)

        self.assertEqual(len(result), 150)
        self.assertEqual(result.pagination["stopReason"], "source_changed")
        self.assertFalse(result.pagination["complete"])
        self.assertFalse(result.pagination["hasMore"])

    def test_missing_total_after_known_total_does_not_erase_completion_evidence(self) -> None:
        client = ScriptedClient([page([row(i) for i in range(100)], 200),
                                 page([row(i) for i in range(100, 150)], None)])

        result = query_clients(client, "list_clients", pageSize=200)

        self.assertEqual(len(result), 150)
        self.assertFalse(result.pagination["complete"])
        self.assertEqual(result.pagination["stopReason"], "source_changed")

    def test_changed_total_on_cursor_resume_is_reported(self) -> None:
        client = ScriptedClient([page([row(i) for i in range(100)], 200),
                                 page([row(i) for i in range(100, 200)], 201)])

        first = query_clients(client, "list_clients", pageSize=50)
        second = query_clients(client, "list_clients", cursor=first.pagination["nextCursor"])
        third = query_clients(client, "list_clients", cursor=second.pagination["nextCursor"])

        self.assertEqual(len(first), 50)
        self.assertEqual(len(second), 50)
        self.assertEqual(third.pagination["stopReason"], "source_changed")
        self.assertFalse(third.pagination["complete"])

    def test_missing_filter_data_cannot_produce_a_complete_negative_result(self) -> None:
        client = ScriptedClient([page([{"mac": row(0)["mac"], "active": True}], 1)])

        result = query_clients(client, "list_clients", pageSize=10,
                               filters={"wireless": True})

        self.assertEqual(list(result), [])
        self.assertEqual(result.pagination["stopReason"], "field_unavailable")
        self.assertFalse(result.pagination["complete"])
        self.assertTrue(result.pagination["truncated"])

    def test_failure_in_second_search_source_after_emission_does_not_fallback_or_mix(self) -> None:
        client = ScriptedClient([page([row(0)], 1), OmadaError("denied", code=-1007)])

        first = query_clients(client, "search_clients", pageSize=1)
        second = query_clients(client, "search_clients", cursor=first.pagination["nextCursor"])

        self.assertEqual(len(first), 1)
        self.assertEqual(first.pagination["source"], "clients")
        self.assertEqual(list(second), [])
        self.assertEqual(second.pagination["stopReason"], "source_error")
        self.assertFalse(second.pagination["complete"])
        self.assertEqual(second.pagination["source"], "clients")
        self.assertFalse(any("insight/clients" in endpoint for endpoint in client.endpoints))


if __name__ == "__main__":
    unittest.main()
