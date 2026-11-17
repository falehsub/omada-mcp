"""End-to-end retry accounting for paged client traversal over the real client."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

ROOT = Path(__file__).resolve().parent.parent
for path in (str(ROOT / "src"), str(ROOT / "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

from client_fixtures import FakeOmadaClient, SyntheticClientSource  # noqa: E402
from fake_controller import SITE_ID, make_client  # noqa: E402

from omada_mcp.domains._client_query import query_clients  # noqa: E402


class RetryEveryPageTransport:
    """Delegate auth/setup calls and synthesize each client page with one -1600 retry."""

    def __init__(self, delegate: Any, source: SyntheticClientSource) -> None:
        self.delegate = delegate
        self.synthetic = FakeOmadaClient(source, site_id=SITE_ID)
        self.cookie_jar = delegate.cookie_jar
        self.requests: list[dict[str, Any]] = []
        self.failed_pages: set[tuple[str, int]] = set()
        self.successful_pages: list[tuple[str, int, list[str]]] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self.delegate, name)

    def request(self, method: str, url: str, headers=None, data=None, timeout=None):
        request = {"method": method, "url": url, "headers": dict(headers or {}), "body": data}
        self.requests.append(request)
        parsed = urlsplit(url)
        marker = "/api/v2/"
        if method.upper() == "GET" and marker in parsed.path:
            endpoint_path = parsed.path.split(marker, 1)[1]
            if endpoint_path.startswith(f"sites/{SITE_ID}/clients"):
                params = parse_qs(parsed.query)
                page = int(params.get("currentPage", ["1"])[0])
                active = params.get("filters.active", ["true"])[0]
                key = (active, page)
                if key not in self.failed_pages:
                    self.failed_pages.add(key)
                    return 200, json.dumps({
                        "errorCode": -1600,
                        "msg": "synthetic one-time request burst",
                        "result": {},
                    }).encode()

                endpoint_params = [(name, value) for name, values in params.items()
                                   if name != "token" for value in values]
                endpoint = endpoint_path
                if endpoint_params:
                    endpoint += "?" + urlencode(endpoint_params)
                payload = self.synthetic.api(endpoint)
                data_rows = payload["result"]["data"]
                self.successful_pages.append((active, page, [row["mac"] for row in data_rows]))
                return 200, json.dumps(payload, separators=(",", ":")).encode()
        return self.delegate.request(method, url, headers=headers, data=data, timeout=timeout)


class ClientHttpBudgetTests(unittest.TestCase):
    def test_1600_once_per_native_page_is_charged_and_cursor_resumes_without_omissions(self):
        row_count = 3_000
        source = SyntheticClientSource(row_count, active_pattern="all")
        client, fake, _ = make_client(read_only=True, min_interval=0)
        transport = RetryEveryPageTransport(fake, source)
        client._transport = transport
        client.authenticate()
        client.current_site()
        # Do not include authentication or site discovery in query attempt deltas.
        transport.requests.clear()

        cursor = None
        pages = []
        transport_deltas = []
        while True:
            before = len(transport.requests)
            result = query_clients(
                client,
                "search_clients",
                pageSize=1,
                cursor=cursor,
                filters={"query": "no-such-fixture-client"},
            )
            actual_attempts = len(transport.requests) - before
            transport_deltas.append(actual_attempts)
            metadata = result.pagination
            self.assertLessEqual(actual_attempts, 24)
            self.assertLessEqual(metadata["controllerRequests"], 24)
            self.assertLessEqual(metadata["pagesFetched"], 20)
            self.assertEqual(list(result), [])
            pages.append(metadata)
            cursor = metadata.get("nextCursor")
            if cursor is None:
                break
            self.assertTrue(metadata["hasMore"])
            self.assertFalse(metadata["complete"])
            self.assertEqual(metadata["stopReason"], "scan_budget")

        self.assertEqual(len(pages), 3)
        self.assertEqual(transport_deltas[:2], [24, 24])
        self.assertEqual(pages[0]["pagesFetched"], 12)
        self.assertEqual(pages[1]["pagesFetched"], 12)
        self.assertEqual(pages[2]["pagesFetched"], 7)
        self.assertTrue(pages[-1]["complete"])
        self.assertEqual(pages[-1]["stopReason"], "complete")

        active_successes = [(page, macs) for active, page, macs in transport.successful_pages
                            if active == "true"]
        self.assertEqual([page for page, _ in active_successes], list(range(1, 31)))
        observed_macs = [mac for _, macs in active_successes for mac in macs]
        expected_macs = [source.row_at(index)["mac"] for index in range(row_count)]
        self.assertEqual(observed_macs, expected_macs)
        self.assertEqual(transport.successful_pages[-1], ("false", 1, []))
        self.assertEqual(len(transport.failed_pages), 31)

        writes = [request for request in transport.requests
                  if request["method"].upper() != "GET"
                  and not urlsplit(request["url"]).path.endswith("/api/v2/login")]
        self.assertEqual(writes, [])


if __name__ == "__main__":
    unittest.main()
