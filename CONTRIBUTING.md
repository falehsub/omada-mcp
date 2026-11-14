# Contributing to `omada-mcp`

Thank you for helping improve `omada-mcp`! This guide covers local setup,
testing rules, zero-drift documentation checks, and pull request expectations.

## Design Rules

- **Zero runtime dependencies**: `pyproject.toml` defines `dependencies = []`.
  Core runtime code under `src/omada_mcp/` must use the Python standard
  library only (Python `>= 3.10`).
- **Fail-closed safety**: Any new read or write tool must belong to an explicit
  category in `src/omada_mcp/domains/_tool_model.py`, declare accurate
  `read_only`/`destructive`/`idempotent`/`site_scoped` metadata, and update
  `config._READ_ONLY_TOOL_NAMES` or `config.WRITE_TOOL_NAMES`.
- **Never commit secrets or real controller captures**: Always scrub real
  captures with `scripts/anonymize_capture.py` before saving fixtures.

## Local Development Setup

```bash
# Run syntax check + full mock/protocol/hardening suite
python -m compileall -q src tests scripts
python -m unittest discover -s tests -v

# Lint and static type checks (same gates as CI)
uvx ruff check src tests scripts
uvx mypy src
uvx mypy scripts

# Verify generated tool reference & metadata are in sync
python scripts/generate_docs.py --check
```

If you modify tool descriptors, parameters, or environment config, regenerate
the reference documentation and verify zero drift:

```bash
python scripts/generate_docs.py
python scripts/generate_docs.py --check
```

## Test Harnesses & Isolated Docker Lab Rules

1. **Offline hermetic unit tests (`tests/`)**: All unit tests run offline
   against `FakeController` (`tests/fake_controller.py`) and stateful
   `MockController` (`tests/mock_controller.py`) with temp snapshot dirs.
2. **Live Docker lab verification (isolated only)**:
   - **Never** run live tests against a production or home controller
     (`%APPDATA%\omada-mcp\.env` or `~/.config/omada-mcp/.env`).
   - Always pass an explicit `--env-file` pointing at an isolated Docker lab
     (for example `%TEMP%\omada-docker-test\viewer.env` or `writer_e2e.env`):
     ```bash
     python scripts/read_selftest.py --env-file /path/to/isolated/viewer.env
     python scripts/write_selftest.py --env-file /path/to/isolated/writer_e2e.env
     ```
   - Notice `.github/workflows/compat.yml` runs automated read/write verification
     against real Omada 5.15 and 6.2 software controller containers in CI.

## Pull Request Workflow

1. Create a feature branch off `main` (do not push directly to `main`).
2. Keep refactors modular across `src/omada_mcp/domains/`.
3. Ensure `ruff`, `mypy`, `unittest`, and `python scripts/generate_docs.py --check`
   all pass cleanly before opening your PR.
4. Releases publish to PyPI automatically via GitHub Actions OIDC Trusted
   Publishing (`.github/workflows/publish.yml`) when a GitHub Release is
   published (or triggered manually via `workflow_dispatch`), with matching
   version numbers across `pyproject.toml`, `src/omada_mcp/__init__.py`, and
   `server.json`.
