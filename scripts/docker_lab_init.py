#!/usr/bin/env python3
"""Initialize an ephemeral Omada Controller lab (v5.x or v6.x) for read-only CI sweeps.

Waits for HTTPS readiness, captures the controller's TLS leaf certificate,
completes root-admin registration and the first-run wizard if needed, creates a
dedicated Viewer account, verifies both logins, and writes isolated dotenv files.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _make_opener(ctx: ssl.SSLContext) -> tuple[urllib.request.OpenerDirector, http.cookiejar.CookieJar]:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(jar),
        _NoRedirect(),
    )
    return opener, jar


def _json_req(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    *,
    token: str | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    raw: bytes | None = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        raw = json.dumps(body).encode("utf-8")
    if token:
        headers["Csrf-Token"] = token
    req = urllib.request.Request(url, data=raw, headers=headers, method=method.upper())
    try:
        with opener.open(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return json.loads(text) if text.strip() else {"errorCode": -1, "msg": "empty"}
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            pass
        return {"errorCode": -exc.code, "msg": f"HTTP {exc.code}: {text[:200]}"}


def wait_for_info(base_url: str, timeout_s: float = 240.0) -> dict[str, Any]:
    """Poll ``/api/info`` until the controller answers with an ``omadacId``."""
    ctx = ssl._create_unverified_context()
    opener, _ = _make_opener(ctx)
    deadline = time.monotonic() + timeout_s
    last_err = ""
    while time.monotonic() < deadline:
        try:
            payload = _json_req(opener, "GET", f"{base_url}/api/info", timeout=5.0)
            res = payload.get("result")
            if payload.get("errorCode") == 0 and isinstance(res, dict) and res.get("omadacId"):
                return res
            last_err = str(payload)
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
        time.sleep(2.0)
    raise RuntimeError(f"controller at {base_url} did not become ready within {timeout_s}s ({last_err})")


def fetch_server_certificate(host: str, port: int) -> tuple[str, str]:
    """Fetch leaf PEM cert and determine recommended ``OMADA_TLS_SERVER_NAME``."""
    pem = ssl.get_server_certificate((host, port))
    server_name = ""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8") as tmp:
        tmp.write(pem)
        tmp_path = tmp.name
    try:
        ssl_mod = getattr(ssl, "_ssl", None)
        decode = getattr(ssl_mod, "_test_decode_cert", None) if ssl_mod is not None else None
        if callable(decode):
            info = decode(tmp_path)
            sans = [val for kind, val in info.get("subjectAltName", ()) if kind in ("DNS", "IP Address")]
            if host not in sans and "127.0.0.1" not in sans and "localhost" not in sans:
                for pair in info.get("subject", ()):
                    for key, val in pair:
                        if key == "commonName" and val:
                            server_name = str(val)
                            break
        if not server_name:
            # Check CN via openssl CLI fallback if _test_decode_cert is absent
            res = subprocess.run(
                ["openssl", "x509", "-in", tmp_path, "-noout", "-subject", "-ext", "subjectAltName"],
                capture_output=True, text=True, check=False,
            )
            if host not in res.stdout and "CN=Omada" in res.stdout:
                server_name = "Omada"
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return pem, server_name


def _api_paths(base_url: str, omadac_id: str, suffix: str) -> list[str]:
    clean = suffix.lstrip("/")
    return [f"{base_url}/{omadac_id}/{clean}", f"{base_url}/{clean}"]


def _post_first_ok(
    opener: urllib.request.OpenerDirector,
    urls: list[str],
    payloads: list[dict[str, Any]],
    *,
    token: str | None = None,
    allow_codes: tuple[int, ...] = (0,),
) -> dict[str, Any]:
    last: dict[str, Any] = {}
    for url in urls:
        for body in payloads:
            resp = _json_req(opener, "POST", url, body, token=token, timeout=30.0)
            if resp.get("errorCode") in allow_codes:
                return resp
            last = {"url": url, "resp": resp}
    raise RuntimeError(f"all setup attempts failed: {last}")


def _find_viewer_role(roles: list[dict[str, Any]]) -> dict[str, Any]:
    for role in roles:
        name = str(role.get("name") or role.get("roleName") or "").lower()
        if "viewer" in name or "observer" in name:
            return role
    return {}


def init_lab(
    *,
    base_url: str,
    admin_user: str,
    admin_password: str,
    viewer_user: str,
    viewer_password: str,
    site_name: str,
    ca_out: Path,
    admin_env_out: Path,
    viewer_env_out: Path,
    timeout_s: float = 240.0,
) -> dict[str, Any]:
    """Bootstrap an unconfigured Omada Docker controller and write CA + dotenv files."""
    info = wait_for_info(base_url, timeout_s=timeout_s)
    omadac_id = str(info["omadacId"])
    controller_ver = str(info.get("controllerVer") or "")
    parsed = urllib.parse.urlsplit(base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8043

    pem, server_name = fetch_server_certificate(host, port)
    ca_out.parent.mkdir(parents=True, exist_ok=True)
    ca_out.write_text(pem, encoding="utf-8")

    ctx = ssl.create_default_context(cafile=str(ca_out))
    if server_name:
        # Use Python HTTPS client with CA verified against our captured leaf
        ctx.check_hostname = False
    opener, jar = _make_opener(ctx)

    # Check if root registration is required (v6 separates anon/register from wizard)
    if not info.get("registeredRoot", True):
        reg_urls = _api_paths(base_url, omadac_id, "api/v2/anon/register")
        _post_first_ok(
            opener,
            reg_urls,
            [{
                "username": admin_user,
                "password": admin_password,
                "email": "lab@example.invalid",
                "allowRemoteBinding": False,
                "language": 1,
            }],
        )

    if not info.get("configured", False):
        wizard_urls = [
            f"{base_url}/{omadac_id}/api/v2/anon/cmd/wizardConfigForLocal",
            f"{base_url}/api/v2/anon/cmd/wizardConfigForLocal",
            f"{base_url}/{omadac_id}/api/v2/anon/cmd/wizardConfig",
            f"{base_url}/api/v2/anon/cmd/wizardConfig",
        ]
        wizard_payloads = [
            {
                "orgName": site_name,
                "region": "United States",
                "timeZone": "UTC",
                "language": 1,
                "expImprove": False,
                "networkConfig": {"enable": True, "name": site_name, "devices": []},
            },
            {
                "controllerName": site_name,
                "region": "United States",
                "timeZone": "UTC",
                "language": 1,
                "expImprove": False,
                "type": 0,
                "username": admin_user,
                "password": admin_password,
                "email": "lab@example.invalid",
                "site": {
                    "siteName": site_name,
                    "scenario": "Home",
                    "timeZone": "UTC",
                    "region": "United States",
                    "type": 0,
                },
                "deviceAccountSetting": {
                    "username": "labdev",
                    "password": admin_password,
                },
            },
        ]
        _post_first_ok(opener, wizard_urls, wizard_payloads, allow_codes=(0, -30106))

    # Authenticate as Admin
    login_res = _json_req(
        opener,
        "POST",
        f"{base_url}/{omadac_id}/api/v2/login",
        {"username": admin_user, "password": admin_password},
    )
    if login_res.get("errorCode") != 0:
        raise RuntimeError(f"admin login failed after setup: {login_res}")
    token = str((login_res.get("result") or {}).get("token") or "")

    # Fetch sites and available roles to create a least-privilege Viewer user
    sites_res = _json_req(opener, "GET", f"{base_url}/{omadac_id}/api/v2/user/sites?token={token}", token=token)
    if sites_res.get("errorCode") != 0:
        sites_res = _json_req(opener, "GET", f"{base_url}/{omadac_id}/api/v2/sites?token={token}", token=token)
    site_rows = ((sites_res.get("result") or {}).get("data") or [])
    resolved_site = str((site_rows[0] if site_rows else {}).get("name") or site_name)
    resolved_site_id = str((site_rows[0] if site_rows else {}).get("id") or "")

    roles_res = _json_req(opener, "GET", f"{base_url}/{omadac_id}/api/v2/roles?token={token}", token=token)
    raw_roles = roles_res.get("result")
    roles_data = raw_roles if isinstance(raw_roles, list) else (
        raw_roles.get("data", []) if isinstance(raw_roles, dict) else []
    )
    if not isinstance(roles_data, list):
        roles_data = []
    viewer_role = _find_viewer_role([r for r in roles_data if isinstance(r, dict)])
    viewer_role_id = str(viewer_role.get("id") or viewer_role.get("roleId") or "")

    user_urls = [
        f"{base_url}/{omadac_id}/api/v2/account/users?token={token}",
        f"{base_url}/{omadac_id}/api/v2/users?token={token}",
    ]
    user_payloads: list[dict[str, Any]] = [
        {
            "type": 0,
            "name": viewer_user,
            "password": viewer_password,
            "roleType": 2,
            "privilege": {"all": True, "sites": []},
            "alert": False,
            "adopt": False,
            "manage": False,
        },
        {
            "type": 0,
            "name": viewer_user,
            "username": viewer_user,
            "password": viewer_password,
            "roleType": 3,
            "all": True,
            "privilege": {"all": True, "sites": []},
            **({"roleId": viewer_role_id} if viewer_role_id else {}),
        },
    ]
    if resolved_site_id:
        user_payloads.append({
            "type": 0,
            "name": viewer_user,
            "password": viewer_password,
            "roleType": 2,
            "privilege": {"all": False, "sites": [{"key": resolved_site_id, "name": resolved_site}]},
            "alert": False,
            "adopt": False,
            "manage": False,
        })
    _post_first_ok(opener, user_urls, user_payloads, token=token, allow_codes=(0, -30107))

    # Verify Viewer login on a clean cookie jar
    v_opener, _ = _make_opener(ctx)
    v_login = _json_req(
        v_opener,
        "POST",
        f"{base_url}/{omadac_id}/api/v2/login",
        {"username": viewer_user, "password": viewer_password},
    )
    if v_login.get("errorCode") != 0:
        raise RuntimeError(f"viewer verification login failed: {v_login}")

    def _write_env(path: Path, user: str, pw: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"OMADA_BASE_URL={base_url}",
            f"OMADA_USERNAME={user}",
            f"OMADA_PASSWORD={pw}",
            f"OMADA_SITE_NAME={resolved_site}",
            "OMADA_VERIFY_SSL=true",
            f"OMADA_CA_FILE={ca_out}",
            "OMADA_READ_ONLY=true",
        ]
        if server_name:
            lines.append(f"OMADA_TLS_SERVER_NAME={server_name}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    _write_env(admin_env_out, admin_user, admin_password)
    _write_env(viewer_env_out, viewer_user, viewer_password)

    return {
        "omadacId": omadac_id,
        "controllerVer": controller_ver,
        "siteName": resolved_site,
        "tlsServerName": server_name or None,
        "adminVerified": True,
        "viewerVerified": True,
        "adminEnv": str(admin_env_out),
        "viewerEnv": str(viewer_env_out),
        "caFile": str(ca_out),
        "cookieNames": [c.name for c in jar],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="https://127.0.0.1:8043")
    parser.add_argument("--site-name", default="DockerLab")
    parser.add_argument("--admin-user", default="omada_lab_admin")
    parser.add_argument("--viewer-user", default="omada_lab_viewer")
    parser.add_argument("--admin-password", default=os.environ.get("LAB_ADMIN_PASSWORD") or f"LabAdm!{secrets.token_hex(6)}")
    parser.add_argument("--viewer-password", default=os.environ.get("LAB_VIEWER_PASSWORD") or f"LabVwr!{secrets.token_hex(6)}")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=240.0)
    args = parser.parse_args(argv)

    summary = init_lab(
        base_url=args.base_url.rstrip("/"),
        admin_user=args.admin_user,
        admin_password=args.admin_password,
        viewer_user=args.viewer_user,
        viewer_password=args.viewer_password,
        site_name=args.site_name,
        ca_out=args.out_dir / "omada-lab-ca.pem",
        admin_env_out=args.out_dir / "admin.env",
        viewer_env_out=args.out_dir / "viewer.env",
        timeout_s=args.timeout,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
