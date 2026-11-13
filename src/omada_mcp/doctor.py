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

import json
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .client import OmadaClient, OmadaError, classify_controller_family
from .config import _IS_WINDOWS, Config, ConfigError, load_config
from .tools import TOOL_MAP

__all__ = ["run_doctor", "Report", "PhaseResult"]

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"


def platform_label() -> str:
    """One-line host description, so a pasted doctor report is triageable."""
    import platform
    import sys

    bits = [platform.system() or "unknown"]
    release = platform.release()
    if release:
        bits.append(release)
    return f"{'-'.join(bits)} (Python {sys.version.split()[0]})"


@dataclass
class PhaseResult:
    name: str
    status: str
    detail: str
    hint: Optional[str] = None


class Report:
    def __init__(self, stream=None, json_output: bool = False):
        self.stream = stream or sys.stdout
        self.json_output = json_output
        self.results: List[PhaseResult] = []
        self.controller_meta: Dict[str, Optional[str]] = {
            "omadacId": None,
            "controllerVer": None,
            "family": None,
            "sessionCookie": None,
        }
        self.site_meta: Optional[Dict[str, Any]] = None

    def add(self, phase: PhaseResult) -> PhaseResult:
        self.results.append(phase)
        if not self.json_output:
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

    def as_dict(self) -> Dict[str, Any]:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.status == PASS)
        warned = sum(1 for r in self.results if r.status == WARN)
        failed = sum(1 for r in self.results if r.status == FAIL)
        if failed:
            status = "fail"
            exit_code = 1
        elif warned:
            status = "warn"
            exit_code = 0
        else:
            status = "pass"
            exit_code = 0
        return {
            "version": __version__,
            "platform": platform_label(),
            "status": status,
            "ready": not failed,
            "exitCode": exit_code,
            "controller": dict(self.controller_meta),
            "site": self.site_meta,
            "summary": {
                "total": total,
                "passed": passed,
                "warned": warned,
                "failed": failed,
            },
            "phases": [
                {
                    "name": r.name,
                    "status": r.status,
                    "detail": r.detail,
                    "hint": r.hint,
                }
                for r in self.results
            ],
        }

    def finish(self) -> int:
        if self.json_output:
            payload = self.as_dict()
            print(json.dumps(payload, indent=2, ensure_ascii=False),
                  file=self.stream, flush=True)
            return int(payload["exitCode"])
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
        print(f"Ready: `omada-mcp` will serve {len(TOOL_MAP)} read-only tools on stdio.",
              file=self.stream)
        return 0


def _phase_env(config: Optional[Config], error: Optional[ConfigError], report: Report) -> None:
    if error is not None:
        report.add(PhaseResult("env", FAIL, error.message, error.hint))
        return
    assert config is not None
    if report.json_output:
        origin = config.env_origin or ("OMADA_ENV_FILE" if config.env_file else "environment")
    else:
        origin = str(config.env_file) if config.env_file else "process environment only"
    report.add(PhaseResult(
        "env", PASS,
        f"{origin} | url={config.base_url} user={config.username} "
        f"password={'set (%d chars)' % len(config.password) if config.password else 'missing'}",
    ))
    if config.env_file and not _IS_WINDOWS:
        mode = oct(config.env_file.stat().st_mode & 0o777)
        if mode not in ("0o600", "0o400"):
            if report.json_output:
                report.add(PhaseResult(
                    "env", WARN, f"{config.env_origin} has mode {mode} (group/other-readable)",
                    f"Restrict permissions: chmod 600 <{config.env_origin}>"))
            else:
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
    family = classify_controller_family(info)
    report.controller_meta["omadacId"] = info.get("omadacId")
    report.controller_meta["controllerVer"] = info.get("controllerVer") or None
    report.controller_meta["family"] = family
    detail = (f"reachable, omadacId={info['omadacId']}, "
              f"controllerVer={info['controllerVer'] or 'unknown'}, family={family}")
    if config.verify_ssl:
        ca_label = "OMADA_CA_BUNDLE" if report.json_output else str(config.ca_bundle)
        via = ca_label if config.ca_bundle else "the system trust store"
        if config.tls_server_name:
            via += f" (serverName={config.tls_server_name})"
        detail = f"verified against {via} | {detail}"
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
        if exc.code in (-1, -30104, -30109):
            hint = ("the controller rejected the credentials; confirm OMADA_USERNAME / "
                    "OMADA_PASSWORD with a browser login at the same URL")
        report.add(PhaseResult("login", FAIL, exc.message, hint))
        return False
    report.controller_meta["family"] = auth.controller_family
    report.controller_meta["sessionCookie"] = auth.session_cookie
    role_bits = []
    if auth.privilege:
        role_bits.append(f"role={auth.privilege}")
    if auth.site_scope:
        role_bits.append(f"scope={auth.site_scope}")
    if auth.session_cookie:
        role_bits.append(f"cookie={auth.session_cookie}")
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
    report.site_meta = site.as_dict()
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
    json_output: bool = False,
) -> int:
    """Run every phase and return a process exit code (0 = ready)."""
    report = Report(stream, json_output=json_output)
    if not json_output:
        print(f"omada-mcp doctor v{__version__} on {platform_label()}", file=report.stream,
              flush=True)
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
