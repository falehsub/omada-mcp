# Security Policy

## Supported Versions

Security fixes target the latest minor release on `main`. Upgrade to the newest
tag on PyPI (`omada-mcp`) or GHCR (`ghcr.io/falehsub/omada-mcp`).

## Reporting a Vulnerability

Please **do not** open a public GitHub issue with controller credentials,
session cookies (`TPOMADA_SESSIONID` / `TPEAP_SESSIONID`), bearer/CSRF tokens,
internal controller URLs, MAC addresses, or unredacted diagnostic dumps.

Instead:

1. Use [GitHub Private Vulnerability Reporting](https://github.com/falehsub/omada-mcp/security/advisories/new)
   on `falehsub/omada-mcp` if enabled, or contact the maintainer privately with
   minimal reproduction steps and affected version details.
2. Include only synthetic/anonymized payloads (you can scrub raw captures with
   `python scripts/anonymize_capture.py`).
3. Expect initial acknowledgement within 72 hours and a coordinated fix/release
   plan once reproduced.

## Credential & Controller Safety Model

`omada-mcp` treats fail-closed least privilege as its default posture:

- **Read-only by default**: `OMADA_READ_ONLY=true` refuses every non-read-only
  tool before handler lookup (`-32003`) and hides write tools from `tools/list`.
  Use a dedicated local **Viewer** controller account whenever writes are not
  needed.
- **Explicit write opt-in & dry-run discipline**: Mutating tools require both
  `OMADA_READ_ONLY=false` and an explicit comma-separated `OMADA_WRITE_TOOLS`
  allowlist (wildcards and `all` are rejected). Every write defaults to
  `dryRun=true`, writes a pre-change JSON snapshot under `OMADA_SNAPSHOT_DIR`,
  and requires a per-target confirmation token (`confirm="<tool>:<target>"`) on
  `dryRun=false`.
- **Site & management safeguards**: Cross-site per-call `site` overrides are
  refused when `OMADA_SITE_NAME`/`OMADA_SITE_ID` is pinned unless
  `OMADA_ALLOW_CROSS_SITE=true`. Uplink ports, controller-hosting switch ports,
  primary/management VLANs, and `OMADA_MANAGEMENT_CIDRS` rules are protected
  against accidental lockout.
- **Secret scrubbing**: `OMADA_PASSWORD`, session cookies, CSRF tokens, PSKs,
  and WireGuard/IPsec/OpenVPN private keys are masked or stripped across logs,
  snapshots, error messages, diffs (`diff_config_snapshots`), and `--doctor`
  output (`deep_redact` / `redact_secrets`).
- **TLS & proxy hygiene**: TLS verification defaults to `true`; WinINET /
  system proxy inheritance defaults to `false` (`OMADA_USE_SYSTEM_PROXY=false`)
  so local management traffic is not routed through untrusted proxies.
- **Env file permissions**: Store `.env` files with owner-only permissions
  (`chmod 600` on POSIX) and never commit real `.env` files or un-anonymized
  controller captures.
