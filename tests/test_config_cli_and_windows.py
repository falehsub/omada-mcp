"""Configuration discovery, Windows TLS/X.509, CLI, and doctor unit tests."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent / "src"
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fake_controller import (  # noqa: E402
    FakeController,
    make_client,
    make_config,
)

from omada_mcp import config as config_module  # noqa: E402
from omada_mcp.client import (  # noqa: E402
    OmadaClient,
    OmadaError,
    build_ssl_context,
)
from omada_mcp.config import (  # noqa: E402
    ConfigError,
    load_config,
    normalize_base_url,
    parse_env_text,
)
from omada_mcp.doctor import run_doctor  # noqa: E402
from omada_mcp.server import Server, configure_streams  # noqa: E402
from omada_mcp.tools import (  # noqa: E402
    normalize_mac,
)


class EnvTests(unittest.TestCase):
    def _write(self, directory, name, body):
        path = Path(directory) / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_parse_env_text_supports_export_quotes_and_comments(self):
        parsed = parse_env_text(
            "# comment\n"
            "export OMADA_BASE_URL=https://c:8043\n"
            'OMADA_PASSWORD="p#ss word"\n'
            "OMADA_USERNAME=admin  # inline comment\n"
            "IGNORED\n"
            "OMADA_SITE_NAME='Lab Site'\n"
        )
        self.assertEqual(parsed["OMADA_BASE_URL"], "https://c:8043")
        self.assertEqual(parsed["OMADA_PASSWORD"], "p#ss word")
        self.assertEqual(parsed["OMADA_USERNAME"], "admin")
        self.assertEqual(parsed["OMADA_SITE_NAME"], "Lab Site")
        self.assertNotIn("IGNORED", parsed)

    def test_omada_env_file_wins_over_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            explicit = self._write(tmp, "explicit.env",
                                   "OMADA_BASE_URL=https://explicit:8043\n"
                                   "OMADA_USERNAME=u1\nOMADA_PASSWORD=p1\n")
            cwd = Path(tmp) / "work"
            cwd.mkdir()
            (cwd / ".env").write_text("OMADA_USERNAME=from-cwd\n", encoding="utf-8")
            config = load_config(environ={"OMADA_ENV_FILE": str(explicit)}, cwd=cwd)
            self.assertEqual(config.username, "u1")
            self.assertEqual(config.env_file, explicit)

    def test_cwd_env_used_when_no_explicit_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp)
            (cwd / ".env").write_text(
                "OMADA_BASE_URL=controller.test\nOMADA_USERNAME=u2\nOMADA_PASSWORD=p2\n",
                encoding="utf-8")
            config = load_config(environ={}, cwd=cwd)
            self.assertEqual(config.username, "u2")
            self.assertEqual(config.base_url, "https://controller.test:8043")

    def test_xdg_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "omada-mcp"
            cfg_dir.mkdir()
            (cfg_dir / ".env").write_text(
                "OMADA_BASE_URL=https://xdg:8043\nOMADA_USERNAME=u3\nOMADA_PASSWORD=p3\n",
                encoding="utf-8")
            empty_cwd = Path(tmp) / "empty"
            empty_cwd.mkdir()
            config = load_config(environ={"XDG_CONFIG_HOME": tmp}, cwd=empty_cwd)
            self.assertEqual(config.username, "u3")

    def test_environment_overrides_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = self._write(tmp, "e.env",
                                   "OMADA_BASE_URL=https://file:8043\n"
                                   "OMADA_USERNAME=fileuser\nOMADA_PASSWORD=filepass\n")
            config = load_config(
                environ={"OMADA_ENV_FILE": str(env_file), "OMADA_USERNAME": "shelluser"},
                cwd=tmp)
            self.assertEqual(config.username, "shelluser")
            self.assertEqual(config.password, "filepass")
            self.assertEqual(config.sources["OMADA_USERNAME"], "environment")

    def test_explicit_missing_env_file_raises_with_hint(self):
        with self.assertRaises(ConfigError) as ctx:
            load_config(environ={"OMADA_ENV_FILE": "/nonexistent/omada.env"}, cwd="/tmp")
        self.assertIn("OMADA_ENV_FILE", str(ctx.exception))
        self.assertIn("fix", str(ctx.exception))

    def test_missing_required_keys_are_all_listed(self):
        with self.assertRaises(ConfigError) as ctx:
            load_config(environ={}, cwd=tempfile.mkdtemp())
        message = str(ctx.exception)
        for key in ("OMADA_BASE_URL", "OMADA_USERNAME", "OMADA_PASSWORD"):
            self.assertIn(key, message)

    def test_invalid_boolean_names_the_variable(self):
        with self.assertRaises(ConfigError) as ctx:
            load_config(environ={"OMADA_BASE_URL": "https://c:8043", "OMADA_USERNAME": "u",
                                 "OMADA_PASSWORD": "p", "OMADA_VERIFY_SSL": "maybe"},
                        cwd=tempfile.mkdtemp())
        self.assertIn("OMADA_VERIFY_SSL", str(ctx.exception))

    def test_missing_ca_bundle_is_a_config_error(self):
        with self.assertRaises(ConfigError) as ctx:
            load_config(environ={"OMADA_BASE_URL": "https://c:8043", "OMADA_USERNAME": "u",
                                 "OMADA_PASSWORD": "p",
                                 "OMADA_CA_BUNDLE": "/nope/ca.pem"},
                        cwd=tempfile.mkdtemp())
        self.assertIn("OMADA_CA_BUNDLE", str(ctx.exception))

    def test_base_url_normalisation(self):
        self.assertEqual(normalize_base_url("controller.test"), "https://controller.test:8043")
        self.assertEqual(normalize_base_url("https://c.test/"), "https://c.test:8043")
        self.assertEqual(normalize_base_url("https://c.test:8443"), "https://c.test:8443")
        self.assertEqual(normalize_base_url("http://c.test"), "http://c.test:8088")
        with self.assertRaises(ConfigError):
            normalize_base_url("ftp://c.test")
        with self.assertRaises(ConfigError):
            normalize_base_url("https://user:pw@c.test:8043")

    def test_masked_config_hides_password(self):
        config = make_config(password="hunter2")
        masked = config.masked()
        self.assertNotIn("hunter2", json.dumps(masked))
        self.assertEqual(masked["password"], "set (7 chars)")


class WindowsTests(unittest.TestCase):
    """Windows-specific behaviour, exercised on any OS.

    The failures these prevent are invisible on Linux: a code-page encoding
    error, a ``\r\n`` frame, a config file nobody can find, and a controller
    call routed through a registry proxy.
    """

    def _windows_stream(self, encoding="cp1252"):
        """A TextIOWrapper that mimics the Windows console: legacy code page + CRLF."""
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding=encoding, newline="\r\n",
                                  write_through=True)
        return raw, stream

    def test_console_stream_is_forced_to_utf8_and_lf(self):
        raw, stream = self._windows_stream()
        configure_streams(None, stream, stream)
        stream.write(json.dumps({"ssid": "\u0634\u0628\u0643\u0629 \u0627\u0644\u0645\u0646\u0632\u0644"},
                                ensure_ascii=False))
        stream.flush()
        data = raw.getvalue()
        self.assertNotIn(b"\r", data, "CRLF leaked into a JSON-RPC frame")
        self.assertEqual(data.decode("utf-8").strip(),
                         '{"ssid": "\u0634\u0628\u0643\u0629 \u0627\u0644\u0645\u0646\u0632\u0644"}')

    def test_unconfigured_cp1252_stream_would_have_failed(self):
        """Proves the guard is load-bearing, not decoration."""
        _raw, stream = self._windows_stream()
        with self.assertRaises(UnicodeEncodeError):
            stream.write("\u0634\u0628\u0643\u0629")
            stream.flush()

    def test_server_emits_lf_only_frames(self):
        client, _, _ = make_client()
        server = Server(client.config, client=client)
        raw, stream = self._windows_stream()
        configure_streams(None, stream, stream)
        server.out = stream
        server.handle({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        server._write({"jsonrpc": "2.0", "id": 1, "result": {}})
        stream.flush()
        self.assertNotIn(b"\r\n", raw.getvalue())
        self.assertEqual(stream.encoding.lower().replace("-", ""), "utf8")

    def test_crlf_input_frames_are_parsed(self):
        payload = ('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\r\n'
                   '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\r\n')
        messages = list(Server._read_messages(io.StringIO(payload)))
        self.assertEqual([m["id"] for m in messages], [1, 2])

    def test_env_file_with_utf8_bom_is_parsed(self):
        """PowerShell 5.1 `Set-Content -Encoding utf8` and old Notepad add a BOM."""
        from omada_mcp.config import parse_env_file
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_bytes(b"\xef\xbb\xbfOMADA_BASE_URL=https://win:8043\r\nOMADA_USERNAME=u\r\n")
            values = parse_env_file(env_file)
        self.assertEqual(values.get("OMADA_BASE_URL"), "https://win:8043")
        self.assertEqual(values.get("OMADA_USERNAME"), "u")

    def test_appdata_env_file_is_discovered_on_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            appdata = Path(tmp) / "Roaming"
            (appdata / "omada-mcp").mkdir(parents=True)
            env_file = appdata / "omada-mcp" / ".env"
            env_file.write_text("OMADA_BASE_URL=https://win:8043\n"
                                "OMADA_USERNAME=winuser\nOMADA_PASSWORD=pw\n",
                                encoding="utf-8")
            empty = Path(tmp) / "work"
            empty.mkdir()
            with mock.patch.object(config_module, "_IS_WINDOWS", True):
                config = config_module.load_config(
                    environ={"APPDATA": str(appdata)}, cwd=empty)
            self.assertEqual(config.username, "winuser")
            self.assertEqual(config.env_file, env_file)

    def test_appdata_precedes_posix_config_dir(self):
        with mock.patch.object(config_module, "_IS_WINDOWS", True):
            origins = [origin for origin, _ in config_module.candidate_env_files(
                cwd="/work", environ={"APPDATA": "/roaming"})]
        self.assertEqual(origins, ["cwd/.env", "%APPDATA%/omada-mcp/.env",
                                   "~/.config/omada-mcp/.env"])

    def test_no_appdata_falls_through_without_error(self):
        with mock.patch.object(config_module, "_IS_WINDOWS", True):
            origins = [origin for origin, _ in config_module.candidate_env_files(
                cwd="/work", environ={})]
        self.assertEqual(origins, ["cwd/.env", "~/.config/omada-mcp/.env"])

    def test_system_proxy_is_disabled_by_default(self):
        from omada_mcp.client import UrllibTransport

        transport = UrllibTransport(build_ssl_context(make_config()))
        self.assertEqual(transport.proxy_mode, "disabled")
        self.assertIsInstance(transport.proxy_handler, urllib.request.ProxyHandler)
        self.assertEqual(transport.proxy_handler.proxies, {})

    def test_system_proxy_can_be_enabled_explicitly(self):
        from omada_mcp.client import UrllibTransport

        transport = UrllibTransport(build_ssl_context(make_config()),
                                    use_system_proxy=True)
        self.assertEqual(transport.proxy_mode, "system")

    def test_use_system_proxy_is_configurable(self):
        with self.assertRaises(ConfigError):
            load_config(environ={"OMADA_BASE_URL": "https://c:8043",
                                 "OMADA_USERNAME": "u", "OMADA_PASSWORD": "p",
                                 "OMADA_USE_SYSTEM_PROXY": "sometimes"},
                        cwd=tempfile.mkdtemp())
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(environ={"OMADA_BASE_URL": "https://c:8043",
                                          "OMADA_USERNAME": "u", "OMADA_PASSWORD": "p",
                                          "OMADA_USE_SYSTEM_PROXY": "true"}, cwd=tmp)
        self.assertTrue(config.use_system_proxy)

    def test_doctor_skips_posix_permissions_on_windows(self):
        from omada_mcp import doctor as doctor_module

        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("OMADA_BASE_URL=https://c:8043\nOMADA_USERNAME=u\n"
                                "OMADA_PASSWORD=p\n", encoding="utf-8")
            env_file.chmod(0o644)
            client, _, _ = make_client()
            stream = io.StringIO()
            with mock.patch.object(doctor_module, "_IS_WINDOWS", True):
                rc = doctor_module.run_doctor(
                    config_factory=lambda: config_module.load_config(
                        environ={"OMADA_ENV_FILE": str(env_file)}, cwd=tmp),
                    client_factory=lambda _cfg: client, stream=stream)
        output = stream.getvalue()
        self.assertEqual(rc, 0, output)
        self.assertNotIn("chmod", output)
        self.assertIn("Python", output)  # platform line in the header

    def test_doctor_warns_about_world_readable_env_on_posix(self):
        from omada_mcp import doctor as doctor_module

        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("OMADA_BASE_URL=https://c:8043\nOMADA_USERNAME=u\n"
                                "OMADA_PASSWORD=p\n", encoding="utf-8")
            env_file.chmod(0o644)
            client, _, _ = make_client()
            stream = io.StringIO()
            with mock.patch.object(doctor_module, "_IS_WINDOWS", False):
                doctor_module.run_doctor(
                    config_factory=lambda: config_module.load_config(
                        environ={"OMADA_ENV_FILE": str(env_file)}, cwd=tmp),
                    client_factory=lambda _cfg: client, stream=stream)
        self.assertIn("chmod 600", stream.getvalue())


class DoctorTests(unittest.TestCase):
    def _run(self, config=None, factory=None, client_factory=None, stream=None):
        stream = stream or io.StringIO()
        rc = run_doctor(
            config_factory=(factory or (lambda: config or make_config())),
            client_factory=client_factory,
            stream=stream,
        )
        return rc, stream.getvalue()

    def test_all_phases_pass(self):
        client, _, _ = make_client()
        rc, output = self._run(client_factory=lambda _cfg: client)
        self.assertEqual(rc, 0, output)
        for phase in ("env", "tls", "login", "site", "tools"):
            self.assertIn(phase, output)
        self.assertIn("Ready", output)
        self.assertIn("password=set (2 chars)", output)

    def test_config_error_is_reported_with_hint(self):
        def factory():
            raise ConfigError("missing required variable(s): OMADA_PASSWORD",
                              hint="add it to ./.env")
        rc, output = self._run(factory=factory)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL", output)
        self.assertIn("fix: add it to ./.env", output)

    def test_bad_credentials_fail_at_login_phase(self):
        client, _, _ = make_client(password="wrong")
        rc, output = self._run(client_factory=lambda _cfg: client)
        self.assertEqual(rc, 1)
        self.assertIn("login", output)
        self.assertIn("FAIL", output)

    def test_unreachable_controller_fails_at_tls_phase(self):
        config = make_config()

        def transport_request(*_args, **_kwargs):
            raise OmadaError("cannot reach https://controller.test:8043: refused",
                             hint="check OMADA_BASE_URL")

        fake = FakeController()
        client = OmadaClient(config, transport=fake, log_fn=lambda _m: None)
        client._transport = type("T", (), {"request": staticmethod(transport_request)})()
        rc, output = self._run(client_factory=lambda _cfg: client)
        self.assertEqual(rc, 1)
        self.assertIn("tls", output)
        self.assertIn("check OMADA_BASE_URL", output)

    def test_read_only_doctor_still_works(self):
        client, _, _ = make_client(read_only=True)
        rc, output = self._run(client_factory=lambda _cfg: client)
        self.assertEqual(rc, 0, output)


class CliTests(unittest.TestCase):
    def test_list_tools_emits_valid_json(self):
        from unittest import mock

        from omada_mcp.cli import main

        with mock.patch.dict(os.environ, {}, clear=True):
            buffer = io.StringIO()
            original = sys.stdout
            sys.stdout = buffer
            try:
                self.assertEqual(main(["--list-tools"]), 0)
            finally:
                sys.stdout = original
            payload = json.loads(buffer.getvalue())
            self.assertEqual(len(payload["tools"]), 33)

            buffer_all = io.StringIO()
            sys.stdout = buffer_all
            try:
                self.assertEqual(main(["--list-tools", "--all"]), 0)
            finally:
                sys.stdout = original
            payload_all = json.loads(buffer_all.getvalue())
            self.assertEqual(len(payload_all["tools"]), 80)

        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "custom.env"
            env_file.write_text(
                "OMADA_READ_ONLY=false\nOMADA_WRITE_TOOLS=set_vlan_isolation,create_ip_group\n",
                encoding="utf-8",
            )
            buf_env = io.StringIO()
            with mock.patch("sys.stdout", buf_env), \
                 mock.patch.dict(os.environ, {"OMADA_ENV_FILE": str(env_file)}, clear=True):
                self.assertEqual(main(["--list-tools"]), 0)
            self.assertEqual(len(json.loads(buf_env.getvalue())["tools"]), 35)

    def test_missing_config_exits_non_zero(self):
        from omada_mcp.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            original_cwd = os.getcwd()
            environ_backup = dict(os.environ)
            for key in list(os.environ):
                if key.startswith("OMADA_"):
                    del os.environ[key]
            # Isolate per-user config dirs and stdin so developer machines with
            # an existing ~/.config/omada-mcp/.env or %APPDATA%\omada-mcp\.env
            # never start the stdio server loop and hang the test suite.
            os.environ["APPDATA"] = tmp
            os.environ["XDG_CONFIG_HOME"] = tmp
            os.environ["HOME"] = tmp
            os.environ["USERPROFILE"] = tmp
            stderr = io.StringIO()
            original_stderr = sys.stderr
            original_stdin = sys.stdin
            sys.stderr = stderr
            sys.stdin = io.StringIO("")
            try:
                os.chdir(tmp)
                code = main([])
            finally:
                os.chdir(original_cwd)
                sys.stderr = original_stderr
                sys.stdin = original_stdin
                os.environ.clear()
                os.environ.update(environ_backup)
            self.assertEqual(code, 2)
            self.assertIn("omada-mcp --doctor", stderr.getvalue())

    def test_normalize_mac_variants(self):
        self.assertEqual(normalize_mac("AABBCCDDEEFF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("aa-bb-cc-dd-ee-ff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("not-a-mac"), "not-a-mac")

