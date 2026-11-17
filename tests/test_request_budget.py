"""Scoped actual-transport request-budget regression tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for path in (str(ROOT / "src"), str(ROOT / "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

from fake_controller import SITE_ID, make_client  # noqa: E402

from omada_mcp.client import RequestBudgetExceeded  # noqa: E402


class RequestBudgetTests(unittest.TestCase):
    def test_counts_retry_attempts_and_stops_before_transport_above_cap(self):
        client, fake, _ = make_client()
        client.authenticate()
        fake.burst_once_for.add(f"sites/{SITE_ID}/devices")

        with client.request_budget(max_requests=1) as budget:
            with self.assertRaises(RequestBudgetExceeded):
                client.api(f"sites/{SITE_ID}/devices")

        device_requests = [request for request in fake.requests if "/devices?" in request["url"]]
        self.assertEqual(len(device_requests), 1)
        self.assertEqual(budget.used, 1)

    def test_counts_successful_retry_as_two_actual_attempts(self):
        client, fake, _ = make_client()
        client.authenticate()
        fake.burst_once_for.add(f"sites/{SITE_ID}/devices")

        with client.request_budget(max_requests=2) as budget:
            result = client.api(f"sites/{SITE_ID}/devices")

        self.assertEqual(result["errorCode"], 0)
        self.assertEqual(budget.used, 2)

    def test_nested_budgets_charge_every_active_scope_and_restore(self):
        client, fake, _ = make_client()
        client.authenticate()

        with client.request_budget(max_requests=1) as outer:
            client.api(f"sites/{SITE_ID}/devices")
            with client.request_budget(max_requests=1) as inner:
                with self.assertRaises(RequestBudgetExceeded):
                    client.api(f"sites/{SITE_ID}/clients")
            self.assertEqual(inner.used, 0)
            self.assertEqual(outer.used, 1)

        self.assertEqual(outer.used, 1)
        client.api(f"sites/{SITE_ID}/devices")  # calls outside a scope remain unrestricted

    def test_authentication_at_nested_scope_entry_counts_in_both_budgets(self):
        client, fake, _ = make_client()
        client.authenticate()

        with client.request_budget(max_requests=12) as outer:
            # Force the nested scope's entry-time authenticate() to dispatch.
            client.token = None
            client.auth_info = None
            client.site = None
            before = len(fake.requests)
            with client.request_budget(max_requests=8) as inner:
                auth_attempts = len(fake.requests) - before
                self.assertGreater(auth_attempts, 0)
                self.assertEqual(inner.used, auth_attempts)
                self.assertEqual(outer.used, auth_attempts)
                client.api(f"sites/{SITE_ID}/devices")
                self.assertEqual(inner.used, auth_attempts + 1)
                self.assertEqual(outer.used, auth_attempts + 1)

    def test_initial_authentication_is_outside_the_budget(self):
        client, fake, _ = make_client()

        with client.request_budget(max_requests=1) as budget:
            self.assertEqual(budget.used, 0)
            client.api(f"sites/{SITE_ID}/devices")

        self.assertEqual(budget.used, 1)
        self.assertGreaterEqual(len(fake.requests), 4)  # info, login, sites, devices

    def test_session_refresh_requests_are_charged_to_the_active_budget(self):
        client, fake, _ = make_client()
        client.authenticate()
        endpoint = f"sites/{SITE_ID}/devices"
        fake.html_once_for.add(endpoint)

        with client.request_budget(max_requests=7) as budget:
            result = client.api(endpoint)

        self.assertEqual(result["errorCode"], 0)
        # failed API call + info/login/users/current/sites refresh + replay
        self.assertEqual(budget.used, 6)


if __name__ == "__main__":
    unittest.main()
