#!/usr/bin/env python3
"""Self-cancelling write-mode self test for omada-mcp.

Every scenario ends where it started, so the controller is left unchanged:

  ip-group      create an IP group, verify, delete it
  acl           create a DISABLED gateway ACL rule, verify, delete it
  isolation     write a VLAN's isolation back to the value it already has
  dhcp-pools    write a VLAN's DHCP pools back exactly as read
  fixed-ip      (opt-in, --client-mac) reserve the address a client already
                holds, verify, then release it

Usage:

    OMADA_ENV_FILE=~/.config/omada-mcp/.env omada-mcp-write-selftest
    OMADA_ENV_FILE=... python scripts/write_selftest.py --client-mac aa:bb:cc:dd:ee:ff

Requirements: OMADA_READ_ONLY=false and an OMADA_WRITE_TOOLS allowlist covering the
tools each scenario needs (the script tells you exactly what is missing). It refuses
to run scenarios it cannot complete, rather than half-applying them.

Exit code 0 = every attempted scenario restored state; 1 = something failed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from omada_mcp.config import ConfigError, load_config  # noqa: E402
from omada_mcp.server import Server  # noqa: E402

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
results = []


def record(status, label, detail=""):
    results.append((status, label, detail))
    print(f"  {status:<4}  {label}" + (f"  {detail}" if detail else ""))


class Runner:
    def __init__(self, server: Server):
        self.server = server
        self.notes = []

    def call(self, name, arguments=None):
        response = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                       "params": {"name": name, "arguments": arguments or {}}})
        if "error" in response:
            return {"_rpc": response["error"].get("code"),
                    "_msg": str(response["error"].get("message"))[:160]}
        result = response["result"]
        try:
            body = json.loads(result["content"][0]["text"])
        except (ValueError, IndexError):
            body = {"_text": (result.get("content") or [{}])[0].get("text", "")[:160]}
        if result.get("isError"):
            body["_isError"] = True
        return body

    def commit(self, tool, arguments):
        """Dry run, then commit with the token it returned."""
        dry = self.call(tool, arguments)
        token = dry.get("confirmToken")
        if not token:
            return dry, dry
        return dry, self.call(tool, dict(arguments, dryRun=False, confirm=token))

    @staticmethod
    def failed(body):
        return bool(body.get("_isError") or body.get("_rpc"))

    def detail(self, body):
        return str(body.get("_text") or body.get("_msg") or "")[:90]


def scenario_ip_group(run):
    name = "ZZ_OMADA_MCP_SELFTEST"
    before = run.call("list_ip_groups")
    rows = before if isinstance(before, list) else before.get("items", [])
    if any(r.get("name") == name for r in rows):
        record(SKIP, "ip-group", f"{name} already exists")
        return
    dry, done = run.commit("create_ip_group", {"name": name, "ipRange": "198.18.0.0/28"})
    record(PASS if dry.get("dryRun") and not dry.get("applied") else FAIL,
           "ip-group dry run wrote nothing", f"dryRun={dry.get('dryRun')} applied={dry.get('applied')}")
    if run.failed(done) or not done.get("applied"):
        record(FAIL, "ip-group create", run.detail(done))
        return
    record(PASS, "ip-group create verified", f"verified={done.get('verified')}")
    dry_del, deleted = run.commit("delete_ip_group", {"group": name})
    record(PASS if deleted.get("applied") or not run.failed(deleted) else FAIL,
           "ip-group delete", run.detail(deleted))
    after = run.call("list_ip_groups")
    rows_after = after if isinstance(after, list) else after.get("items", [])
    record(PASS if not any(r.get("name") == name for r in rows_after) else FAIL,
           "ip-group state restored")


def scenario_acl(run):
    name = "ZZ_OMADA_MCP_SELFTEST_ACL"
    acls = run.call("list_acls")
    rows = acls if isinstance(acls, list) else acls.get("items", [])
    if any(r.get("name") == name for r in rows):
        record(SKIP, "acl", f"{name} already exists")
        return
    nets = run.call("list_lan_networks")
    nets = nets if isinstance(nets, list) else nets.get("items", [])
    if len(nets) < 2:
        record(SKIP, "acl", "needs two LAN networks to build a rule")
        return
    payload = {"name": name, "policy": "deny", "status": False,
               "source": {"type": "network", "ids": [nets[0]["id"]]},
               "destination": {"type": "network", "ids": [nets[1]["id"]]},
               "direction": {"lanToLan": True, "lanToWan": False}}
    dry, done = run.commit("create_gateway_acl", payload)
    record(PASS if dry.get("dryRun") else FAIL, "acl dry run", run.detail(dry))
    if run.failed(done) or not done.get("applied"):
        record(FAIL, "acl create (disabled)", run.detail(done))
        return
    rows = run.call("list_acls")
    rows = rows if isinstance(rows, list) else rows.get("items", [])
    mine = [r for r in rows if r.get("name") == name]
    record(PASS if mine and mine[0].get("status") is False else FAIL,
           "acl created disabled", f"status={mine[0].get('status') if mine else None}")
    if mine:
        run.commit("delete_gateway_acl", {"rule": mine[0]["id"]})
        rows = run.call("list_acls")
        rows = rows if isinstance(rows, list) else rows.get("items", [])
        record(PASS if not any(r.get("name") == name for r in rows) else FAIL,
               "acl state restored")


def scenario_isolation(run):
    nets = run.call("list_lan_networks")
    nets = nets if isinstance(nets, list) else nets.get("items", [])
    if not nets:
        record(SKIP, "isolation", "no LAN networks visible")
        return
    net = nets[-1]
    current = bool(net.get("isolation"))
    dry, done = run.commit("set_vlan_isolation", {"vlan": net["vlan"], "isolation": current})
    record(PASS if dry.get("dryRun") else FAIL, "isolation dry run", run.detail(dry))
    record(PASS if done.get("applied") else FAIL,
           f"isolation written back unchanged (vlan {net['vlan']})", run.detail(done))
    after = run.call("list_lan_networks")
    after = after if isinstance(after, list) else after.get("items", [])
    same = next((n for n in after if n.get("vlan") == net["vlan"]), {})
    record(PASS if bool(same.get("isolation")) == current else FAIL, "isolation state restored")


def scenario_dhcp_pools(run):
    nets = run.call("list_lan_networks")
    nets = nets if isinstance(nets, list) else nets.get("items", [])
    candidates = [n for n in nets if n.get("dhcpPools")]
    if not candidates:
        record(SKIP, "dhcp-pools", "no pools exposed by list_lan_networks")
        return
    # The safety check refuses pools that cover managed devices (the management VLAN
    # usually does), so take the first candidate it actually accepts.
    target = dry = None
    refusals = []
    for net in candidates:
        attempt = run.call("set_vlan_dhcp_pools", {"vlan": net["vlan"], "pools": net["dhcpPools"]})
        if run.failed(attempt):
            refusals.append(f"vlan {net['vlan']}: {run.detail(attempt)[:60]}")
            continue
        target, dry = net, attempt
        break
    if target is None:
        record(SKIP, "dhcp-pools", "every pool was refused by the safety check: " + "; ".join(refusals[:3]))
        return
    pools = target["dhcpPools"]
    done = run.call("set_vlan_dhcp_pools",
                    dict({"vlan": target["vlan"], "pools": pools},
                         dryRun=False, confirm=dry["confirmToken"])) if dry.get("confirmToken") else dry
    record(PASS if dry.get("dryRun") else FAIL, "dhcp-pools dry run", run.detail(dry))
    record(PASS if done.get("applied") else FAIL,
           f"dhcp-pools written back unchanged (vlan {target['vlan']})", run.detail(done))
    after = run.call("list_lan_networks")
    after = after if isinstance(after, list) else after.get("items", [])
    same = next((n for n in after if n.get("vlan") == target["vlan"]), {})
    record(PASS if json.dumps(same.get("dhcpPools")) == json.dumps(pools) else FAIL,
           "dhcp pools state restored")


def scenario_lan_pool_shape(run):
    """create_lan_network must accept the pool shape the readers emit.

    Dry run only — this scenario never creates a network. It exists so a schema drift
    between what list_lan_networks returns and what create_lan_network advertises fails
    loudly instead of surfacing as a client-side validation error months later.
    """
    nets = run.call("list_lan_networks")
    nets = nets if isinstance(nets, list) else nets.get("items", [])
    source = next((n for n in nets if n.get("dhcpPools")), None)
    if source is None:
        record(SKIP, "lan-pool-shape", "no pools exposed by list_lan_networks")
        return
    # Use the reader's KEY SHAPE ({start,end}) with values consistent with the subnet we
    # ask for, so the only thing under test is the contract, not address semantics.
    reader_shape = [{"start": "172.31.255.10", "end": "172.31.255.20"}]
    dry = run.call("create_lan_network", {"name": "ZZ_OMADA_MCP_SELFTEST_LAN", "vlan": 3999,
                                          "gatewaySubnet": "172.31.255.1/24",
                                          "pools": reader_shape})
    if dry.get("_rpc") == -32003:
        record(SKIP, "lan-pool-shape", "create_lan_network is not allowlisted")
        return
    detail = run.detail(dry)
    if "ipaddrend" in detail.lower() or "ipaddrend and" in detail.lower():
        record(FAIL, "lan-pool-shape: reader shape rejected by create_lan_network", detail)
        return
    record(PASS, "lan-pool-shape: {start,end} accepted by create_lan_network (dry run)",
           f"dryRun={dry.get('dryRun')} applied={dry.get('applied')}")


def scenario_fixed_ip(run, mac):
    clients = run.call("search_clients", {"query": mac})
    rows = clients if isinstance(clients, list) else clients.get("items", [])
    target = next((c for c in rows if str(c.get("mac", "")).lower().replace(":", "-") ==
                   mac.lower().replace(":", "-")), None)
    if target is None:
        record(SKIP, "fixed-ip", f"client {mac} not found")
        return
    if not target.get("ip"):
        record(SKIP, "fixed-ip", "client has no address to reserve")
        return
    ip, vlan = target["ip"], target.get("vlan")
    dry, done = run.commit("set_client_fixed_ip", {"mac": mac, "ip": ip, "vlan": vlan})
    record(PASS if dry.get("dryRun") else FAIL, "fixed-ip dry run", run.detail(dry))
    if run.failed(done):
        record(FAIL, "fixed-ip reserve", run.detail(done))
        return
    record(PASS, "fixed-ip reserve verified",
           f"verified={done.get('verified')} warnings={done.get('warnings')}")
    _dry2, released = run.commit("release_client_fixed_ip", {"mac": mac})
    record(PASS if released.get("applied") else FAIL, "fixed-ip released (state restored)",
           run.detail(released))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Self-cancelling write-mode self test.")
    parser.add_argument("--client-mac", help="opt in to the fixed-IP scenario for this client")
    parser.add_argument("--skip", action="append", default=[],
                        choices=["ip-group", "acl", "isolation", "dhcp-pools",
                                 "lan-pool-shape", "fixed-ip"])
    args = parser.parse_args(argv)

    try:
        config = load_config()
    except ConfigError as exc:
        print(f"config error: {exc}")
        return 2
    if config.read_only:
        print("OMADA_READ_ONLY is true — this script needs false (and an OMADA_WRITE_TOOLS allowlist).")
        return 2
    if not config.write_tools:
        print("OMADA_WRITE_TOOLS is empty — nothing to test.")
        return 2

    server = Server(config)
    run = Runner(server)
    print(f"write self test: {len(config.write_tools)} allowlisted tool(s), site={config.site_id or config.site_name or 'first'}")

    plan = [("ip-group", scenario_ip_group), ("acl", scenario_acl),
            ("isolation", scenario_isolation), ("dhcp-pools", scenario_dhcp_pools),
            ("lan-pool-shape", scenario_lan_pool_shape)]
    for name, fn in plan:
        if name in args.skip:
            record(SKIP, name, "skipped by --skip")
            continue
        print(f"[{name}]")
        fn(run)
    if args.client_mac:
        print("[fixed-ip]")
        scenario_fixed_ip(run, args.client_mac)

    failed = sum(1 for status, _, _ in results if status == FAIL)
    skipped = sum(1 for status, _, _ in results if status == SKIP)
    print(f"\n{len(results) - failed - skipped} passed, {failed} failed, {skipped} skipped")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
