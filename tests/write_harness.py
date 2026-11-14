"""Shared harness helpers for stateful mock-controller write-support tests."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
TESTS = Path(__file__).resolve().parent
for p in (str(SRC), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from mock_controller import MockController  # noqa: E402

from omada_mcp.client import OmadaClient  # noqa: E402
from omada_mcp.config import WRITE_TOOL_NAMES, Config  # noqa: E402
from omada_mcp.server import Server  # noqa: E402


def make_write_config(
    *,
    tmp_dir: str,
    base_url: str = "https://192.168.10.10:8043",
    read_only: bool = False,
    write_tools: tuple[str, ...] = WRITE_TOOL_NAMES,
    management_cidrs: tuple[str, ...] = (),
    write_min_interval: float = 0.0,
) -> Config:
    return Config(
        base_url=base_url,
        username="admin-writer",
        password="pw",
        verify_ssl=False,
        read_only=read_only,
        write_tools=write_tools,
        snapshot_dir=Path(tmp_dir),
        snapshot_origin="OMADA_SNAPSHOT_DIR",
        write_min_interval=write_min_interval,
        management_cidrs=management_cidrs,
        min_interval=0.0,
        timeout=5.0,
    )


def make_write_env(
    tmp_dir: str,
    *,
    role: str = "Administrator",
    read_only: bool = False,
    write_tools: tuple[str, ...] = WRITE_TOOL_NAMES,
    management_cidrs: tuple[str, ...] = (),
    write_min_interval: float = 0.0,
    controller_url: str = "https://192.168.10.10:8043",
):
    ctrl = MockController(role=role)
    cfg = make_write_config(
        tmp_dir=tmp_dir,
        base_url=controller_url,
        read_only=read_only,
        write_tools=write_tools,
        management_cidrs=management_cidrs,
        write_min_interval=write_min_interval,
    )
    now = [100.0]
    sleeps = []

    def fake_clock() -> float:
        return now[0]

    def fake_sleep(sec: float) -> None:
        sleeps.append(sec)
        now[0] += sec

    client = OmadaClient(
        cfg,
        transport=ctrl,
        sleep=fake_sleep,
        clock=fake_clock,
        log_fn=lambda _msg: None,
    )
    server = Server(cfg, client=client)
    return server, client, ctrl, sleeps


def call_tool(server: Server, name: str, arguments: dict | None = None, req_id: int = 1) -> dict:
    return server.handle({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })


def unwrap_ok(resp: dict) -> dict:
    assert "error" not in resp, f"unexpected RPC error: {resp.get('error')}"
    res = resp["result"]
    assert not res.get("isError"), f"unexpected tool error: {res}"
    return res["structuredContent"]

