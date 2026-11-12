# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-13

First public release. Extracted from a working private bridge and generalised so
that any Omada controller can be driven by an MCP host.

### Added

- Eight read-only MCP tools over the Omada **Web API v2**: `list_devices`,
  `list_clients`, `list_wifi_clients`, `list_wired_clients`, `get_device`,
  `get_client`, `list_wlans`, `get_site_info`.
- Configuration discovery chain: `OMADA_ENV_FILE` -> `./.env` ->
  `~/.config/omada-mcp/.env`, with the process environment always winning.
- Automatic `omadacId` discovery and site resolution via `OMADA_SITE_ID` or
  `OMADA_SITE_NAME`, defaulting to the first visible site.
- `OMADA_VERIFY_SSL`, `OMADA_CA_BUNDLE` and `OMADA_STRICT_X509` for controller
  certificates, including the Python 3.13+ `VERIFY_X509_STRICT` opt-out.
- `OMADA_READ_ONLY` safety mode: anything not declared read-only is refused with
  JSON-RPC error `-32003`, before tool lookup (fails closed).
- `omada-mcp --doctor`: ordered self-test for dotenv, TLS/CA, login, controller
  version, site discovery and one live read call, each failure with an exact fix.
- MCP tool annotations: `readOnlyHint`, `destructiveHint`, `idempotentHint`,
  `openWorldHint`, plus `title`.
- Session recovery: a 200 response containing the web UI shell triggers one
  re-authentication and a replay, never a loop.
- PACING: calls are spaced (`OMADA_MIN_INTERVAL_SECONDS`, default 0.25 s) and a
  burst `-1600` is retried once after 0.8 s.
- WLAN pre-shared keys are redacted; `hasPresharedKey` reports their presence.
- Zero runtime dependencies; 59 stdlib unit tests; CI on Python 3.10-3.14.
- Verified live on software controller v6.2.10.17: `--doctor` passes and all
  eight read tools return live data (4 devices, 15 clients, 1 WLAN, PSK not
  exposed); write refusal confirmed with `OMADA_READ_ONLY=true`.
