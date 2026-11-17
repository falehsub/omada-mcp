"""Focused tests for bounded, process-local client cursors."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from omada_mcp.client_cursors import CursorCapacityError, CursorError, CursorStore


class CursorStoreTests(unittest.TestCase):
    def test_put_and_get_are_deeply_isolated_and_replayable(self) -> None:
        original = {"rows": [{"name": "one"}], "position": 3}
        store = CursorStore()
        token = store.put("site:tool:principal:query", original)

        original["rows"][0]["name"] = "changed after put"
        first = store.get(token, "site:tool:principal:query")
        first["rows"][0]["name"] = "changed after get"
        second = store.get(token, "site:tool:principal:query")

        self.assertEqual(second, {"rows": [{"name": "one"}], "position": 3})
        self.assertEqual(len(token), 43)  # token_urlsafe(32) has 43 characters.

    def test_unknown_and_wrong_scope_tokens_raise_cursor_error(self) -> None:
        store = CursorStore(token_factory=lambda: "fixed-test-token")
        token = store.put("expected", {"offset": 4})

        with self.assertRaises(CursorError):
            store.get("unknown", "expected")
        with self.assertRaises(CursorError):
            store.get(token, "other")

    def test_idle_expiry_is_refreshed_by_reads_and_absolute_expiry_is_not(self) -> None:
        now = [0.0]
        store = CursorStore(
            idle_ttl=10,
            absolute_ttl=25,
            clock=lambda: now[0],
            token_factory=iter(("idle", "absolute")).__next__,
        )
        idle_token = store.put("s", {"n": 1})
        absolute_token = store.put("s", {"n": 2})

        now[0] = 8
        self.assertEqual(store.get(idle_token, "s"), {"n": 1})
        now[0] = 17
        self.assertEqual(store.get(idle_token, "s"), {"n": 1})
        now[0] = 26
        with self.assertRaises(CursorError):
            store.get(idle_token, "s")
        with self.assertRaises(CursorError):
            store.get(absolute_token, "s")

    def test_lru_and_expired_entries_are_evicted(self) -> None:
        now = [0.0]
        tokens = iter(("a", "b", "c", "d"))
        store = CursorStore(max_entries=2, idle_ttl=5, clock=lambda: now[0], token_factory=tokens.__next__)
        first = store.put("s", {"n": 1})
        second = store.put("s", {"n": 2})
        store.get(first, "s")
        third = store.put("s", {"n": 3})

        with self.assertRaises(CursorError):
            store.get(second, "s")
        self.assertEqual(store.get(first, "s"), {"n": 1})
        self.assertEqual(store.get(third, "s"), {"n": 3})

        now[0] = 6
        with self.assertRaises(CursorError):
            store.get(first, "s")
        self.assertEqual(len(store), 0)

    def test_byte_limit_evicts_old_entries_and_rejects_single_oversized_state(self) -> None:
        one = {"value": "1234"}
        size = len(b'{"scope":"s","state":{"value":"1234"}}')
        tokens = iter(("a", "b", "large"))
        store = CursorStore(max_bytes=size, token_factory=tokens.__next__)

        first = store.put("s", one)
        self.assertEqual(store.bytes_used, size)
        second = store.put("s", one)
        self.assertEqual(store.bytes_used, size)
        with self.assertRaises(CursorError):
            store.get(first, "s")
        self.assertEqual(store.get(second, "s"), one)
        with self.assertRaises(CursorCapacityError):
            store.put("s", {"value": "x" * size})
        self.assertEqual(len(store), 1)

    def test_clear_drops_all_state_and_resets_accounting(self) -> None:
        store = CursorStore(token_factory=lambda: "token")
        token = store.put("s", {"safe": [1, 2]})
        self.assertGreater(store.bytes_used, 0)

        store.clear()

        self.assertEqual(len(store), 0)
        self.assertEqual(store.bytes_used, 0)
        with self.assertRaises(CursorError):
            store.get(token, "s")

    def test_state_must_be_a_json_serializable_dictionary(self) -> None:
        store = CursorStore(token_factory=lambda: "token")
        with self.assertRaises(TypeError):
            store.put("s", [])  # type: ignore[arg-type]
        with self.assertRaises((TypeError, ValueError)):
            store.put("s", {"not_json": object()})


if __name__ == "__main__":
    unittest.main()
