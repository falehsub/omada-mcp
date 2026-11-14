"""Read-only live tool sweep with payload-free JSON results (stdlib only).

Run: python scripts/read_selftest.py --env-file /path/to/isolated/viewer.env
Never uses discovered per-user config. All writes except login are blocked.
Hardware-dependent tools are explicitly skipped when no target is available.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from omada_mcp.client import OmadaClient, OmadaError, UrllibTransport, build_ssl_context
from omada_mcp.config import ConfigError, load_config
from omada_mcp.server import Server, configure_streams
from omada_mcp.tools import TOOLS


class ReadOnlyTransport(UrllibTransport):
    """Enforce the live test's no-mutation rule independently of tool metadata."""

    def request(self, method, url, headers=None, data=None, timeout=None):
        path = urllib.parse.urlsplit(url).path
        if method.upper() != 'GET' and not (
            method.upper() == 'POST' and path.endswith('/api/v2/login')
        ):
            raise OmadaError('live read self-test blocked a mutating request')
        return super().request(method, url, headers, data, timeout)


def run_checks(client):
    """Exercise each read tool once through the MCP dispatcher on one session."""
    config = replace(client.config, read_only=True, write_tools=(), tool_categories=())
    server = Server(config, client=client)
    results = []
    devices, clients = [], []
    for tool in (tool for tool in TOOLS if tool.read_only):
        arguments = {}
        if tool.name == 'explain_error':
            arguments['code'] = -1600
        if 'mac' in tool.input_schema.get('required', []):
            targets = clients if tool.name in ('get_client', 'diagnose_client') else devices
            if tool.name == 'get_switch_ports':
                targets = [d for d in targets if d.get('type') == 'switch']
            elif tool.name in ('get_ap_radios', 'get_rf_scan'):
                targets = [d for d in targets if d.get('type') == 'ap']
            if not targets:
                results.append({'tool': tool.name, 'status': 'skip', 'reason': 'no matching live target'})
                continue
            arguments['mac'] = targets[0]['mac']
        started = time.monotonic()
        before = client.request_count
        response = server.handle({
            'jsonrpc': '2.0', 'id': len(results) + 1, 'method': 'tools/call',
            'params': {'name': tool.name, 'arguments': arguments},
        })
        result = response.get('result', {})
        failed = 'error' in response or result.get('isError', False)
        row = {
            'tool': tool.name, 'status': 'fail' if failed else 'pass',
            'seconds': round(time.monotonic() - started, 3),
            'requests': client.request_count - before,
        }
        if failed:
            # No controller messages, IDs, credentials, or payloads in shareable reports.
            row['reason'] = 'RPC error' if 'error' in response else 'tool execution error'
        results.append(row)
        items = result.get('structuredContent', {}).get('items', [])
        if tool.name == 'list_devices':
            devices = items
        elif tool.name == 'list_clients':
            clients = items
    return {
        'controllerVersion': getattr(client.auth_info, 'controller_version', None),
        'readOnly': True,
        'passed': sum(r['status'] == 'pass' for r in results),
        'failed': sum(r['status'] == 'fail' for r in results),
        'skipped': sum(r['status'] == 'skip' for r in results),
        'results': results,
    }


def main(argv=None):
    configure_streams()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', required=True, help='explicit isolated lab dotenv file')
    args = parser.parse_args(argv)
    try:
        env = dict(os.environ, OMADA_ENV_FILE=args.env_file, OMADA_READ_ONLY='true', OMADA_WRITE_TOOLS='')
        config = load_config(environ=env)
        config = replace(config, min_interval=max(0.25, config.min_interval))
        transport = ReadOnlyTransport(build_ssl_context(config), timeout=config.timeout,
                                      use_system_proxy=config.use_system_proxy)
        client = OmadaClient(config, transport=transport, log_fn=lambda _: None)
        try:
            report = run_checks(client)
        finally:
            client.close()
        print(json.dumps(report, indent=2))
        return 1 if report['failed'] else 0
    except (ConfigError, OmadaError):
        # Keep stdout shareable even on failures; doctor gives detailed local diagnostics.
        print(json.dumps({'readOnly': True, 'error': 'setup failed; run --doctor locally for details'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
