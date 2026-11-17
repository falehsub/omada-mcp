"""Black-box contracts for bounded client queries and their MCP envelopes."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

TESTS = Path(__file__).resolve().parent
for path in (TESTS.parent / "src", TESTS):
    sys.path.insert(0, str(path))

from client_fixtures import DEFAULT_SECRET_CANARY, FakeOmadaClient, SyntheticClientSource  # noqa: E402
from fake_controller import make_config  # noqa: E402

from omada_mcp.schema_validation import validate_tool_arguments  # noqa: E402
from omada_mcp.server import Server  # noqa: E402
from omada_mcp.tools import get_tool  # noqa: E402
from omada_mcp.transport import SiteInfo  # noqa: E402

CLIENT_QUERY_TOOLS = (
    "list_clients",
    "list_wifi_clients",
    "list_wired_clients",
    "search_clients",
)


class ClientContractTests(unittest.TestCase):
    def make_server(self, *, count=205, read_only=False):
        client = FakeOmadaClient(SyntheticClientSource(count))
        config = make_config(read_only=read_only)
        client.config = config
        client.authenticate()
        return Server(config, client=client), client

    def invoke(self, server, name="list_clients", **arguments):
        return server.handle({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })

    @staticmethod
    def assert_output_valid(testcase, tool_name, output):
        tool = get_tool(tool_name)
        testcase.assertIsNotNone(tool)
        schema_as_input = SimpleNamespace(
            name=f"{tool_name} output",
            input_schema=tool.output_schema,
            read_only=True,
        )
        validate_tool_arguments(schema_as_input, output)

    def test_input_schema_rejects_bad_paged_arguments_before_collection_io(self):
        server, client = self.make_server()
        before = client.request_count

        for arguments in (
            {"pageSize": 0},
            {"pageSize": 501},
            {"resultFormat": "xml"},
            {"fields": "name"},
        ):
            with self.subTest(arguments=arguments):
                response = self.invoke(server, **arguments)
                self.assertIn("error", response, response)

        self.assertEqual(client.request_count, before)

    def test_sparse_and_full_envelopes_validate_against_output_schema(self):
        server, _ = self.make_server(count=13)
        sparse_result = self.invoke(
            server,
            pageSize=2,
            fields=["name", "ip"],
            resultFormat="envelope",
        )
        sparse = sparse_result["result"]["structuredContent"]
        self.assert_output_valid(self, "list_clients", sparse)
        self.assertEqual(set(sparse["items"][0]), {"mac", "name", "ip"})

        full_result = self.invoke(
            server,
            pageSize=2,
            resultFormat="envelope",
        )
        full = full_result["result"]["structuredContent"]
        self.assert_output_valid(self, "list_clients", full)
        self.assertEqual(len(full["items"][0]), 25)

    def test_all_four_tools_envelope_text_is_single_block_equal_to_structure(self):
        server, _ = self.make_server()
        arguments = {
            "pageSize": 2,
            "fields": ["name", "ip"],
            "resultFormat": "envelope",
        }
        for tool_name in CLIENT_QUERY_TOOLS:
            with self.subTest(tool=tool_name):
                response = self.invoke(server, tool_name, **arguments)
                result = response["result"]
                self.assertFalse(result.get("isError"), result)
                self.assertEqual(len(result["content"]), 1)
                self.assertEqual(
                    json.loads(result["content"][0]["text"]),
                    result["structuredContent"],
                )

    def test_unknown_secret_is_neither_returned_nor_saved_in_cursor(self):
        server, client = self.make_server()
        result = self.invoke(
            server,
            pageSize=1,
            fields=["name"],
            resultFormat="envelope",
        )["result"]
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertNotIn(DEFAULT_SECRET_CANARY, encoded)

        entries = list(client.client_cursors._entries.values())
        self.assertTrue(entries, "page should retain a continuation checkpoint")
        checkpoint_text = json.dumps([entry.state for entry in entries], ensure_ascii=False)
        self.assertNotIn(DEFAULT_SECRET_CANARY, checkpoint_text)

    def test_read_only_mode_allows_new_read_arguments_and_still_blocks_writes(self):
        server, client = self.make_server(read_only=True)
        read = self.invoke(
            server,
            pageSize=2,
            fields=["name"],
            resultFormat="envelope",
        )
        self.assertNotIn("error", read, read)
        self.assertFalse(read["result"].get("isError"), read)

        before_write = client.request_count
        denied = self.invoke(server, "set_client_fixed_ip", mac="02:00:00:00:00:01")
        self.assertEqual(denied["error"]["code"], -32003)
        self.assertEqual(client.request_count, before_write)

    def test_cursor_rejected_for_wrong_tool_or_site_without_collection_io(self):
        server, client = self.make_server()
        first = self.invoke(server, pageSize=1)["result"]["structuredContent"]
        cursor = first["nextCursor"]
        self.assertTrue(cursor)
        before = client.request_count

        wrong_tool = self.invoke(server, "list_wifi_clients", cursor=cursor)
        self.assertTrue(wrong_tool["result"].get("isError"), wrong_tool)
        self.assertEqual(client.request_count, before)

        client._site = SiteInfo("another-site", "Another Site")
        wrong_site = self.invoke(server, "list_clients", cursor=cursor)
        self.assertTrue(wrong_site["result"].get("isError"), wrong_site)
        self.assertEqual(client.request_count, before)


if __name__ == "__main__":
    unittest.main()
