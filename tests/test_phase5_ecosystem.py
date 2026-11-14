"""Phase 5 ecosystem discovery, generated documentation, and release hygiene tests."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SRC = ROOT / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from omada_mcp import __version__  # noqa: E402
from omada_mcp.tools import TOOLS  # noqa: E402


def _load_generate_docs():
    spec = importlib.util.spec_from_file_location("generate_docs", ROOT / "scripts" / "generate_docs.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Phase5EcosystemTests(unittest.TestCase):
    def test_repo_docs_manifests_and_tool_counts_have_zero_drift(self):
        gd = _load_generate_docs()
        errors = gd.verify_repo_sync(ROOT)
        self.assertEqual(errors, [], f"Repo drift detected: {errors}")

    def test_verify_repo_sync_catches_version_and_doc_drift(self):
        gd = _load_generate_docs()
        with tempfile.TemporaryDirectory() as tmp:
            fake_root = Path(tmp)
            for name in ("pyproject.toml", "server.json", "README.md", ".env.example", "SECURITY.md", "CONTRIBUTING.md"):
                (fake_root / name).write_text((ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")
            (fake_root / "docs").mkdir()
            (fake_root / "docs" / "tools-reference.md").write_text("stale\n", encoding="utf-8")

            # Stale docs + version mismatch in server.json must fail cleanly.
            srv = json.loads((fake_root / "server.json").read_text(encoding="utf-8"))
            srv["version"] = "9.9.9"
            (fake_root / "server.json").write_text(json.dumps(srv), encoding="utf-8")

            errors = gd.verify_repo_sync(fake_root)
            joined = "\n".join(errors)
            self.assertIn("docs/tools-reference.md is out of date", joined)
            self.assertIn("server.json version", joined)

    def test_server_json_mcp_registry_contract(self):
        srv = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
        self.assertIn("static.modelcontextprotocol.io/schemas/", srv["$schema"])
        self.assertEqual(srv["name"], "io.github.falehsub/omada-mcp")
        self.assertEqual(srv["version"], __version__)
        self.assertLessEqual(len(srv["description"]), 100)
        self.assertEqual(srv["repository"]["source"], "github")

        pkgs = {p["registryType"]: p for p in srv["packages"]}
        self.assertEqual(pkgs["pypi"]["identifier"], "omada-mcp")
        self.assertEqual(pkgs["pypi"]["version"], __version__)
        self.assertEqual(pkgs["pypi"]["transport"]["type"], "stdio")
        env_names = {e["name"]: e for e in pkgs["pypi"]["environmentVariables"]}
        self.assertTrue(env_names["OMADA_PASSWORD"]["isSecret"])
        self.assertTrue(env_names["OMADA_BASE_URL"]["isRequired"])
        self.assertFalse(env_names["OMADA_BASE_URL"]["isSecret"])

        self.assertEqual(pkgs["oci"]["identifier"], f"ghcr.io/falehsub/omada-mcp:{__version__}")
        self.assertEqual(pkgs["oci"]["transport"]["type"], "stdio")

    def test_generated_tools_reference_contains_every_tool(self):
        ref = (ROOT / "docs" / "tools-reference.md").read_text(encoding="utf-8")
        for tool in TOOLS:
            self.assertIn(f"`{tool.name}`", ref)

    def test_ci_publish_dependabot_and_dockerfile_hygiene(self):
        ci_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/generate_docs.py --check", ci_text)
        self.assertIn("python -m mypy scripts", ci_text)
        self.assertIn("macos-latest", ci_text)
        self.assertIn("docker-smoke", ci_text)
        self.assertIn("uv tool run --from", ci_text)

        pub_text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("pypa/gh-action-pypi-publish", pub_text)
        self.assertIn("actions/attest-build-provenance", pub_text)
        self.assertIn("linux/amd64,linux/arm64", pub_text)
        self.assertIn("SHA256SUMS.txt", pub_text)
        self.assertIn("ghcr.io", pub_text)

        dep_text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        self.assertIn('package-ecosystem: "github-actions"', dep_text)
        self.assertIn('package-ecosystem: "docker"', dep_text)

        df_text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("USER omada", df_text)
        self.assertIn("org.opencontainers.image.source", df_text)


if __name__ == "__main__":
    unittest.main()
