"""Tool descriptor list: tool_specs_write_c."""

from __future__ import annotations

from ._tool_model import _WRITE_CONTROL_PROPS, Tool
from ._write_common import WRITE_ENVELOPE_SCHEMA
from .ops_hotspot_write import (
    create_hotspot_vouchers,
    export_controller_backup,
    revoke_hotspot_voucher,
)
from .vpn_ddns_write import (
    delete_ddns,
    delete_wireguard_peer,
    delete_wireguard_tunnel,
    set_vpn_tunnel_status,
    upsert_ddns,
    upsert_wireguard_peer,
    upsert_wireguard_tunnel,
)

WRITE_TOOLS_C: list[Tool] = [
    Tool(
        name="set_vpn_tunnel_status",
        title="Enable or disable VPN tunnel",
        description=(
            "Toggle status of an IPsec, OpenVPN, L2TP, or PPTP tunnel entry (POST setting/vpns/{id}/status) "
            "with dryRun preview and secret redaction."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "vpn": {"type": "string", "description": "VPN entry ID or exact name"},
                "enabled": {"type": "boolean", "description": "True to enable, False to disable"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["vpn", "enabled"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_vpn_tunnel_status,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="upsert_wireguard_tunnel",
        title="Create or update WireGuard interface",
        description=(
            "Create or update a WireGuard VPN interface (POST/PUT setting/wireguard). "
            "If privateKey is omitted on create, requests an ephemeral controller keypair without returning or logging it."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "WireGuard interface name (1..64 chars)"},
                "localIp": {"type": "string", "description": "Interface local IP address, e.g. '10.66.0.1' ('/prefix' stripped automatically)"},
                "privateKey": {"type": "string", "description": "Optional 44-char base64 WireGuard private key"},
                "mtu": {"type": "integer", "minimum": 576, "maximum": 1440, "default": 1420},
                "listenPort": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 51820},
                "status": {"type": "boolean", "default": True},
                "tunnelId": {"type": "string", "description": "Optional existing interface ID when renaming"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "localIp"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_wireguard_tunnel,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_wireguard_tunnel",
        title="Delete WireGuard interface",
        description=(
            "Delete a WireGuard VPN interface (DELETE setting/wireguard/{id}). "
            "Refuses deletion if peers are still attached."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "tunnel": {"type": "string", "description": "WireGuard interface ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["tunnel"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_wireguard_tunnel,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="upsert_wireguard_peer",
        title="Create or update WireGuard peer",
        description=(
            "Create or update a WireGuard peer bound to an existing interface (POST/PUT setting/wireguard/peer). "
            "Redacts presharedKey from all responses and snapshots."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Peer name (1..64 chars)"},
                "interface": {"type": "string", "description": "Parent WireGuard interface ID or exact name"},
                "publicKey": {"type": "string", "description": "44-char base64 WireGuard peer public key"},
                "allowAddress": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowed IP CIDRs routed to this peer, e.g. ['10.66.0.2/32']",
                },
                "peerId": {"type": "string", "description": "Optional existing peer ID when updating/renaming"},
                "endPoint": {"type": "string", "description": "Optional remote endpoint IP or hostname"},
                "endPointPort": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "Remote endpoint UDP port (paired with endPoint)"},
                "presharedKey": {"type": "string", "description": "Optional 44-char base64 preshared key"},
                "keepAlive": {"type": "integer", "minimum": 0, "maximum": 65535, "default": 25},
                "comment": {"type": "string", "description": "Optional comment (max 128 chars)"},
                "status": {"type": "boolean", "default": True},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "interface", "publicKey", "allowAddress"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_wireguard_peer,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_wireguard_peer",
        title="Delete WireGuard peer",
        description="Delete a WireGuard peer by ID or exact name (DELETE setting/wireguard/peer/{id}).",
        input_schema={
            "type": "object",
            "properties": {
                "peer": {"type": "string", "description": "WireGuard peer ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["peer"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_wireguard_peer,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="upsert_ddns",
        title="Create or update DDNS entry",
        description=(
            "Create or update a dynamic DNS configuration on a WAN port (POST/PUT setting/service/ddns). "
            "Passwords are redacted from responses and rollback snapshots."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "domainName": {"type": "string", "description": "DDNS hostname (e.g. 'home.example.org')"},
                "service": {"type": ["string", "integer"], "default": "dyndns", "description": "'dyndns' (0), 'noip' (1), 'peanuthull' (2), or 'comexe' (3)"},
                "username": {"type": "string", "description": "DDNS account username (required on create)"},
                "password": {"type": "string", "description": "DDNS account password (required on create)"},
                "ddnsId": {"type": "string", "description": "Optional existing DDNS entry ID"},
                "interface": {"type": "string", "description": "WAN port name or UUID (defaults to primary WAN)"},
                "updateInterval": {"type": "integer", "enum": [0, 1, 6, 12, 24, 48, 72], "default": 12, "description": "Update interval hours (0=never, 1, 6, 12, 24, 48, 72)"},
                "status": {"type": "boolean", "default": True},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["domainName"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_ddns,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_ddns",
        title="Delete DDNS entry",
        description="Delete a DDNS configuration by ID or domainName (DELETE setting/service/ddns/{id}).",
        input_schema={
            "type": "object",
            "properties": {
                "ddns": {"type": "string", "description": "DDNS entry ID or exact domainName"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["ddns"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_ddns,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="export_controller_backup",
        title="Export controller backup safely",
        description=(
            "Trigger a controller backup (or download a named auto-backup file) into OMADA_SNAPSHOT_DIR/backups "
            "with byte/path-traversal guards. Never restores."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "retentionDays": {"type": "integer", "enum": [-1, 0, 7, 30, 60, 90, 180, 365], "default": -1, "description": "-1=settings only, 0=all history, or 7/30/60/90/180/365 days"},
                "retainUsers": {"type": "boolean", "default": True},
                "fileName": {"type": "string", "description": "Optional auto-backup filename to download directly"},
                "timeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 300, "default": 60},
                **_WRITE_CONTROL_PROPS,
            },
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=export_controller_backup,
        read_only=False,
        destructive=False,
        idempotent=True,
        site_scoped=False,
    ),
    Tool(
        name="create_hotspot_vouchers",
        title="Create hotspot voucher group",
        description=(
            "Generate a hotspot voucher group (POST hotspot/sites/{id}/voucherGroups, category 'hotspot')."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Voucher group name (1..64 chars)"},
                "amount": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 10},
                "durationMinutes": {"type": "integer", "minimum": 1, "default": 480},
                "codeLength": {"type": "integer", "minimum": 6, "maximum": 10, "default": 6},
                "codeFormat": {"type": "string", "enum": ["numbers", "letters", "numbers_letters"], "default": "numbers_letters"},
                "maxUsers": {"type": "integer", "minimum": 1, "maximum": 999, "default": 1},
                "downLimitKbps": {"type": "integer", "minimum": 1},
                "upLimitKbps": {"type": "integer", "minimum": 1},
                "trafficLimitMb": {"type": "integer", "minimum": 1},
                "description": {"type": "string"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_hotspot_vouchers,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="revoke_hotspot_voucher",
        title="Revoke hotspot voucher or group",
        description=(
            "Revoke/delete a hotspot voucher group or single voucher code (category 'hotspot')."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Voucher group ID/name or voucher ID/code"},
                "targetType": {"type": "string", "enum": ["group", "voucher"], "default": "group"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["target"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=revoke_hotspot_voucher,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
]
