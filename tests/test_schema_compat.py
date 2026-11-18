"""Schema compatibility guard: prevents accidental tool/parameter renames or removals."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from omada_mcp.tools import TOOL_MAP, TOOLS  # noqa: E402

BASELINE_PATH = TESTS / "fixtures" / "schema_baseline.json"


class SchemaCompatibilityTests(unittest.TestCase):
    def test_existing_tools_and_parameters_are_backwards_compatible(self):
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(set(TOOL_MAP), set(baseline), "Tool list diverged from tests/fixtures/schema_baseline.json")

        for tool in TOOLS:
            spec = baseline[tool.name]
            self.assertEqual(tool.read_only, spec["readOnly"], f"{tool.name} readOnly changed")
            props = set(((tool.input_schema or {}).get("properties") or {}).keys())
            missing_props = set(spec["properties"]) - props
            self.assertEqual(
                missing_props,
                set(),
                f"{tool.name} removed/renamed parameter(s) without alias: {sorted(missing_props)}",
            )
            required = set((tool.input_schema or {}).get("required") or [])
            added_required = required - set(spec["required"])
            self.assertEqual(
                added_required,
                set(),
                f"{tool.name} made new parameter(s) required: {sorted(added_required)}",
            )
            removed_required = set(spec["required"]) - required
            self.assertEqual(
                removed_required,
                set(),
                f"{tool.name} changed required parameters: {sorted(removed_required)}",
            )


if __name__ == "__main__":
    unittest.main()
