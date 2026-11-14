"""Regression coverage for the local controller review."""
import http.client
import io
import json
import tempfile
import unittest
from unittest import mock

from test_bridge import CLIENTS, FakeController, make_config
from omada_mcp.client import OmadaClient, OmadaError, UrllibTransport, build_ssl_context
from omada_mcp.config import ConfigError, load_config, normalize_base_url
from omada_mcp.server import Server
from omada_mcp.tools import TOOL_MAP


class ReviewRegressionTests(unittest.TestCase):
    def test_disconnect_error_never_exposes_session_token(self):
        transport = UrllibTransport(build_ssl_context(make_config()))
        conn = mock.MagicMock()
        conn.sock = None
        conn.getresponse.side_effect = http.client.RemoteDisconnected('closed')
        with mock.patch.object(transport, '_new_connection', return_value=conn):
            with self.assertRaises(OmadaError) as caught:
                transport.request('POST', 'https://controller.test/api/write?token=private-session-token', data=b'{}')
        rendered = str(caught.exception) + str(caught.exception.endpoint)
        self.assertNotIn('private-session-token', rendered)
        self.assertIn('/api/write', rendered)
        self.assertEqual(conn.request.call_count, 1)
        transport.close()

    def test_client_type_filter_precedes_result_limit(self):
        for name, rows, expected in (
            ('list_wired_clients', CLIENTS, CLIENTS[1]['mac']),
            ('list_wifi_clients', list(reversed(CLIENTS)), CLIENTS[0]['mac']),
        ):
            with self.subTest(tool=name):
                client = OmadaClient(make_config(), transport=FakeController(clients=rows), sleep=lambda _: None, log_fn=lambda _: None)
                result = TOOL_MAP[name].handler(client, limit=1)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]['mac'], expected)

    def test_invalid_numeric_config_is_actionable(self):
        for key, values in (
            ('OMADA_TIMEOUT_SECONDS', ('0', '-1', 'nan', 'inf', '-inf')),
            ('OMADA_MIN_INTERVAL_SECONDS', ('-1', 'nan', 'inf')),
            ('OMADA_WRITE_INTERVAL_SECONDS', ('-1', 'nan', 'inf')),
        ):
            for value in values:
                with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmp:
                    env = dict(OMADA_BASE_URL='https://controller.test', OMADA_USERNAME='test', OMADA_PASSWORD='test', HOME=tmp, USERPROFILE=tmp, APPDATA=tmp, XDG_CONFIG_HOME=tmp)
                    env[key] = value
                    with self.assertRaises(ConfigError) as caught:
                        load_config(environ=env, cwd=tmp)
                    self.assertEqual(caught.exception.key, key)

    def test_malformed_url_is_a_config_error(self):
        for url in ('https://host:bad', 'https://host:65536', 'https://[broken'):
            with self.subTest(url=url), self.assertRaises(ConfigError):
                normalize_base_url(url)

    def test_notifications_never_execute_tools_or_send_replies(self):
        cfg = make_config()
        client = OmadaClient(cfg, transport=FakeController(), log_fn=lambda _: None)
        server = Server(cfg, client=client)
        for method in ('ping', 'unknown', 'tools/call'):
            response = server.handle(dict(jsonrpc='2.0', method=method, params={'name': 'list_devices'}))
            self.assertIsNone(response)
        self.assertEqual(client.request_count, 0)

    def test_invalid_envelopes_are_rejected_before_controller_io(self):
        cfg = make_config()
        server = Server(cfg, client=OmadaClient(cfg, transport=FakeController(), log_fn=lambda _: None))
        for updates, code, expected_id in (
            ({'jsonrpc':'1.0'}, -32600, 1),
            ({'id':True}, -32600, None),
            ({'id':[]}, -32600, None),
            ({'id':None}, -32600, None),
            ({'params':[]}, -32602, 1),
            ({'params':False}, -32602, 1),
        ):
            request = dict(jsonrpc='2.0', id=1, method='ping')
            request.update(updates)
            with self.subTest(updates=updates):
                resp = server.handle(request)
                self.assertEqual(resp['error']['code'], code)
                self.assertEqual(resp['id'], expected_id)

    def test_complete_oversized_frame_is_rejected_and_reader_recovers(self):
        class SmallServer(Server):
            MAX_FRAME_CHARS = 80
        ping = json.dumps(dict(jsonrpc='2.0', id=2, method='ping'))
        stream = io.StringIO(json.dumps({'padding':'x' * 200}) + '\n' + ping + '\n')
        self.assertEqual(list(SmallServer._read_messages(stream)), [None, json.loads(ping)])

    def test_config_snapshot_drops_unknown_controller_fields(self):
        from test_write_support import make_write_env, call_tool, unwrap_ok
        with tempfile.TemporaryDirectory() as tmp:
            server, _, ctrl, _ = make_write_env(tmp, read_only=True)
            # A future firmware can introduce secrets under names we do not know.
            for rows in (ctrl.lan_collection, ctrl.lan_interfaces, ctrl.groups, ctrl.acls):
                for row in rows:
                    row['futureCredential'] = 'future-controller-secret'
            snapshot = unwrap_ok(call_tool(server, 'get_config_snapshot', {}))
            self.assertNotIn('future-controller-secret', json.dumps(snapshot))
            self.assertEqual(ctrl.write_request_count, 0)

    def test_repeated_client_page_does_not_exhaust_page_budget(self):
        client = OmadaClient(make_config(), log_fn=lambda _: None)
        page = {'errorCode':0, 'result':{'data':CLIENTS, 'totalRows':500}}
        from omada_mcp.tools import _paginate_client_rows
        with mock.patch.object(client, 'api', return_value=page) as request:
            rows = _paginate_client_rows(client, mock.Mock(site_id='test-site'), 'clients')
        self.assertEqual(len(rows), 2)
        self.assertLessEqual(request.call_count, 2)

    def test_read_selftest_guards_transport_and_reports_without_payloads(self):
        import importlib.util
        from pathlib import Path
        from test_write_support import make_write_env
        spec = importlib.util.spec_from_file_location('read_selftest', Path(__file__).resolve().parents[1] / 'scripts' / 'read_selftest.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            _, client, ctrl, _ = make_write_env(tmp, read_only=True)
            report = module.run_checks(client)
            self.assertEqual(report['failed'], 0, report)
            self.assertEqual(report['passed'] + report['skipped'], 33)
            self.assertEqual(ctrl.write_request_count, 0)
            rendered = json.dumps(report)
            self.assertNotIn('192.168.', rendered)
            self.assertNotIn('mocksite', rendered)
        transport = module.ReadOnlyTransport(build_ssl_context(make_config()))
        with self.assertRaises(OmadaError):
            transport.request('PATCH', 'https://controller.test/api/write', data=b'{}')
        transport.close()

    def test_redirect_session_expiry_reauthenticates_without_following_redirect(self):
        class RedirectController(FakeController):
            def request(self, method, url, **kwargs):
                if 'token=local-invalid-token' in url:
                    return 302, b''
                return super().request(method, url, **kwargs)
        client = OmadaClient(make_config(), transport=RedirectController(), sleep=lambda _:None, log_fn=lambda _:None)
        client.authenticate()
        client.token = 'local-invalid-token'
        result = TOOL_MAP['list_devices'].handler(client)
        self.assertTrue(result)
        self.assertNotEqual(client.token, 'local-invalid-token')

    def test_services_and_routing_drop_unknown_controller_fields(self):
        from test_write_support import make_write_env, call_tool, unwrap_ok
        with tempfile.TemporaryDirectory() as tmp:
            server, _, ctrl, _ = make_write_env(tmp, read_only=True)
            for obj in (ctrl.upnp, ctrl.dns_proxy, ctrl.ddns):
                obj['futureCredential'] = 'future-controller-secret'
            for rows in (ctrl.mdns_rules, ctrl.mdns_profiles, ctrl.policy_routes, ctrl.lan_dns_rules):
                rows.append({'id':'test', 'name':'test', 'futureCredential':'future-controller-secret'})
            ctrl.lan_dns_rules.append({
                'id': 'dns-fwd-test', 'name': 'fwd-test', 'type': 2,
                'dnsServers': ['1.1.1.1', '9.9.9.9'],
                'futureCredential': 'future-controller-secret',
            })
            for tool in ('get_network_services', 'list_policy_routes', 'list_lan_dns_rules'):
                with self.subTest(tool=tool):
                    result = unwrap_ok(call_tool(server, tool, {}))
                    self.assertNotIn('future-controller-secret', json.dumps(result))
                    if tool == 'list_lan_dns_rules':
                        fwd = next(item for item in result['items'] if item.get('id') == 'dns-fwd-test')
                        self.assertEqual(fwd['dnsServers'], ['1.1.1.1', '9.9.9.9'])

    def test_redirect_recovery_is_bounded_and_never_replays_writes(self):
        from omada_mcp.client import OmadaSessionExpiredError
        for method in ('GET', 'POST'):
            client = OmadaClient(make_config(), log_fn=lambda _:None)
            client.token, client.controller_id = 'test', 'test'
            with mock.patch.object(client, '_raw', return_value=(302, b'')) as request, mock.patch.object(client, 'authenticate') as auth:
                expected = OmadaSessionExpiredError if method == 'POST' else OmadaError
                with self.assertRaises(expected):
                    client.api('test-endpoint', method=method)
                self.assertEqual(request.call_count, 1 if method == 'POST' else 2)
                auth.assert_called_once_with(force=True)

    def test_cli_rejects_nonfinite_poll_interval_before_loading_config(self):
        from omada_mcp.cli import main
        for value in ('nan', 'inf', '-inf'):
            with self.subTest(value=value), mock.patch('omada_mcp.cli.load_config') as load, mock.patch('sys.stderr', new_callable=io.StringIO):
                self.assertEqual(main(['--watch', '--interval='+value]), 2)
                load.assert_not_called()

    def test_snapshot_files_are_unique_across_process_clients(self):
        import datetime
        from pathlib import Path
        stamp = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            first = OmadaClient(make_config(snapshot_dir=Path(tmp)))
            second = OmadaClient(make_config(snapshot_dir=Path(tmp)))
            with mock.patch('omada_mcp.client.datetime.datetime') as clock:
                clock.now.return_value = stamp
                one = first._save_snapshot('test', 'target', {'value':1})
                two = second._save_snapshot('test', 'target', {'value':2})
            self.assertNotEqual(one, two)
            self.assertEqual(json.loads((Path(tmp)/one).read_text())['data']['value'], 1)
            self.assertEqual(json.loads((Path(tmp)/two).read_text())['data']['value'], 2)

    def test_opener_transport_does_not_follow_auth_redirects(self):
        import http.server
        import threading
        hits = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                hits.append(self.path)
                self.send_response(302 if self.path == '/start' else 200)
                if self.path == '/start':
                    self.send_header('Location', '/other-origin')
                self.send_header('Content-Length', '0')
                self.end_headers()
        httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=lambda:httpd.serve_forever(poll_interval=0.01), daemon=True)
        worker.start()
        transport = UrllibTransport(build_ssl_context(make_config()))
        try:
            with mock.patch.object(transport, '_should_use_opener', return_value=True):
                status, _ = transport.request('GET', 'http://127.0.0.1:'+str(httpd.server_port)+'/start', headers={'Csrf-Token':'synthetic-token'})
            self.assertEqual(status, 302)
            self.assertEqual(hits, ['/start'])
        finally:
            transport.close()
            httpd.shutdown()
            httpd.server_close()
            worker.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
