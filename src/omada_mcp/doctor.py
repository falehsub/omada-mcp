"""``omada-mcp --doctor``: an ordered self-test with exact fix hints.

Each phase isolates one failure mode so the reported fix is unambiguous::

    1 env      which dotenv file was used, which required keys exist
    2 tls      /api/info reachable and the certificate chain accepted
    3 login    username/password accepted, token + Csrf-Token round-trip works
    4 site     OMADA_SITE_ID / OMADA_SITE_NAME resolved (or first site)
    5 tools    a real read call through the same path the tools use

Nothing secret is printed: the password appears only as "set (N chars)" and the
session token is never echoed. Exit code 0 means "a client can use this".
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, List, Optional

from . import __version__
from .client import OmadaClient, OmadaError
from .config import Config, ConfigError, load_config
from .tools import TOOL_MAP

__all__ = ["run_doctor", "Report", "PhaseResult"]

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"


@dataclass
class PhaseResult:
    name: str
    status: str
    detail: str
    hint: Optional[str] = None


class Report:
    def __init__(self, stream=None):
        self.stream = stream or sys.stdout
        self.results: List[PhaseResult] = []

    def add(self, phase: PhaseResult) -> PhaseResult:
        self.results.append(phase)
        self._print(phase)
        return phase

    def _print(self, phase: PhaseResult) -> None:
        print(f"{phase.status:<4} {phase.name:<8} {phase.detail}",
              file=self.stream, flush=True)
        if phase.hint:
            print(f"     {'':<8} -> fix: {phase.hint}", file=self.stream, flush=True)

    @property
    def failed(self) -> bool:
        return any(r.status == FAIL for r in self.results)

    @property
    def warned(self) -> bool:
        return any(r.status == WARN for r in self.results)

    def finish(self) -> int:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.status == PASS)
        warned = sum(1 for r in self.results if r.status == WARN)
        failed = sum(1 for r in self.results if r.status == FAIL)
        print("-" * 66, file=self.stream, flush=True)
        summary = f"{passed}/{total} checks passed"
        if warned:
            summary += f", {warned} warning(s)"
        if failed:
            summary += f", {failed} failed"
        print(summary, file=self.stream)
        if failed:
            print("Not ready: apply the fix hints above, then re-run `omada-mcp --doctor`.",
                  file=self.stream)
            return 1
        if warned:
            print("Ready, with warnings: `omada-mcp` will start.", file=self.stream)
            return 0
        print("Ready: `omada-mcp` will serve 8 read-only tools on stdio.", file=self.stream)
        return 0


def _phase_env(config: Optional[Config], error: Optional[ConfigError], report: Report) -> None:
    if error is not None:
        report.add(PhaseResult("env", FAIL, error.message, error.hint))
        return
    assert config is not None
    origin = str(config.env_file) if config.env_file else "process environment only"
    report.add(PhaseResult(
        "env", PASS,
        f"{origin} | url={config.base_url} user={config.username} "
        f"password={'set (%d chars)' % len(config.password) if config.password else 'missing'}",
    ))
    if config.env_file:
        mode = oct(config.env_file.stat().st_mode & 0o777)
        if mode not in ("0o600", "0o400"):
            report.add(PhaseResult(
                "env", WARN, f"{config.env_file} has mode {mode}",
                f"chmod 600 {config.env_file} (it holds the controller password)"))


def _phase_tls(client: OmadaClient, config: Config, report: Report) -> bool:
    if not config.verify_ssl:
        report.add(PhaseResult(
            "tls", WARN, "certificate verification DISABLED (OMADA_VERIFY_SSL=false)",
            "set OMADA_VERIFY_SSL=true and OMADA_CA_BUNDLE=<controller-ca.pem> "
            "once the controller has a trusted certificate"))
    try:
        info = client.controller_info()
    except OmadaError as exc:
        report.add(PhaseResult("tls", FAIL, exc.message, exc.hint))
        return False
    detail = f"reachable, omadacId={info['omadacId']}, controllerVer={info['controllerVer'] or 'unknown'}"
    if config.verify_ssl:
        detail = ("verified against " + (str(config.ca_bundle) if config.ca_bundle
                                         else "the system trust store") + " | " + detail)
    report.add(PhaseResult("tls", PASS, detail))
    if not info["controllerVer"]:
        report.add(PhaseResult("tls", WARN,
                               "the controller did not report controllerVer",
                               "the Web API may be a pre-v5 build; tools may still work"))
    return True


def _phase_login(client: OmadaClient, report: Report) -> bool:
    try:
        auth = client.authenticate(resolve_site=False)
    except OmadaError as exc:
        hint = exc.hint
        if exc.code in (-1, -30109):
            hint = ("the controller rejected the credentials; confirm OMADA_USERNAME / "
                    "OMADA_PASSWORD with a browser login at the same URL")
        report.add(PhaseResult("login", FAIL, exc.message, hint))
        return False
    role_bits = []
    if auth.privilege:
        role_bits.append(f"role={auth.privilege}")
    if auth.site_scope:
        role_bits.append(f"scope={auth.site_scope}")
    suffix = f" ({', '.join(role_bits)})" if role_bits else ""
    report.add(PhaseResult(
        "login", PASS,
        f"token accepted for {auth.username}{suffix}, Csrf-Token round-trip OK"))
    return True


def _phase_site(client: OmadaClient, config: Config, report: Report) -> bool:
    try:
        site = client.resolve_site()
    except OmadaError as exc:
        report.add(PhaseResult("site", FAIL, exc.message, exc.hint))
        return False
    client.site = site
    requested = config.site_id or config.site_name
    detail = f"{site.name} ({site.site_id}) site {site.index + 1} of {site.total}"
    if requested:
        detail += f"; matched OMADA_SITE_{'ID' if config.site_id else 'NAME'}={requested}"
    else:
        detail += "; no OMADA_SITE_* set, using the first site"
        if site.total > 1:
            report.add(PhaseResult(
                "site", WARN, f"the account sees {site.total} sites; using the first",
                "set OMADA_SITE_NAME (or OMADA_SITE_ID) to pin the intended site"))
    report.add(PhaseResult("site", PASS, detail))
    return True


def _phase_tools(client: OmadaClient, report: Report) -> bool:
    try:
        devices = TOOL_MAP["list_devices"].handler(client)
    except OmadaError as exc:
        report.add(PhaseResult("tools", FAIL, exc.message, exc.hint))
        return False
    detail = f"list_devices -> {len(devices)} device(s); {len(TOOL_MAP)} read-only tools registered"
    try:
        clients = _client_count(client)
        detail += f", {clients} client(s)"
    except OmadaError as exc:
        report.add(PhaseResult("tools", WARN, f"device listing works, client listing: {exc.message}",
                               exc.hint))
        return True
    report.add(PhaseResult("tools", PASS, detail))
    if isinstance(devices, list) and devices and "error" in devices[0]:
        report.add(PhaseResult("tools", WARN, "device listing returned an error object",
                               str(devices[0])))
    return True


def _client_count(client: OmadaClient) -> int:
    from .tools import _fetch_clients  # noqa: PLC0415 - avoids a public API

    return len(_fetch_clients(client, limit=0))


def run_doctor(
    config_factory: Callable[[], Config] = load_config,
    client_factory: Optional[Callable[[Config], OmadaClient]] = None,
    stream=None,
) -> int:
    """Run every phase and return a process exit code (0 = ready)."""
    report = Report(stream)
    print(f"omada-mcp doctor v{__version__}", file=report.stream, flush=True)
    print("-" * 66, file=report.stream, flush=True)

    config: Optional[Config] = None
    error: Optional[ConfigError] = None
    try:
        config = config_factory()
    except ConfigError as exc:
        error = exc
    except OmadaError as exc:  # defensive: factory should raise ConfigError only
        error = ConfigError(exc.message, exc.hint)

    _phase_env(config, error, report)
    if config is None:
        return report.finish()

    client = (client_factory or (lambda cfg: OmadaClient(cfg)))(config)
    if not _phase_tls(client, config, report):
        return report.finish()
    if not _phase_login(client, report):
        return report.finish()
    if not _phase_site(client, config, report):
        return report.finish()
    _phase_tools(client, report)
    return report.finish()
