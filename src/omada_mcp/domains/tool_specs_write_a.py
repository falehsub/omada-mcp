"""Tool descriptor list: tool_specs_write_a."""

from __future__ import annotations

from ._tool_model import _WRITE_CONTROL_PROPS, Tool
from ._write_common import WRITE_ENVELOPE_SCHEMA
from .clients_write import release_client_fixed_ip, set_client_fixed_ip
from .networks_write import (
    create_lan_network,
    delete_lan_network,
    set_vlan_dhcp_pools,
    set_vlan_isolation,
    update_lan_network,
)
from .routing_dns_write import (
    delete_port_forward,
    delete_static_route,
    upsert_port_forward,
    upsert_static_route,
)
from .security_acls_write import (
    create_gateway_acl,
    delete_gateway_acl,
    set_acl_rule_status,
    update_gateway_acl,
)
from .security_groups_write import create_ip_group, delete_ip_group, replace_ip_group
from .services_write import (
    delete_dhcp_reservation,
    delete_mdns_rule,
    set_upnp,
    upsert_dhcp_reservation,
    upsert_mdns_rule,
)
from .wireless_write import create_ssid, delete_ssid, update_ssid

WRITE_TOOLS_A: list[Tool] = [
    Tool(
        name="set_client_fixed_ip",
        title="Set client DHCP reservation",
        description=(
            "Assign a DHCP fixed IPv4 reservation on a client (PATCH clients/{MAC}). "
            "Lease-delayed; strips volatile keys and refuses managed device MACs (-41011). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC address"},
                "ip": {"type": "string", "description": "Fixed IPv4 address within target VLAN"},
                "vlan": {"type": "integer", "description": "Optional VLAN ID to resolve netId"},
                "netId": {"type": "string", "description": "Optional LAN network ID"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "ip"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_client_fixed_ip,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="release_client_fixed_ip",
        title="Release client DHCP reservation",
        description=(
            "Clear useFixedAddr on a client (PATCH clients/{MAC}). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC address"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=release_client_fixed_ip,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="set_vlan_dhcp_pools",
        title="Set VLAN DHCP pools",
        description=(
            "Update dhcpSettings.ipRangePool on a LAN/VLAN via full /interface PATCH with "
            "two-endpoint verification and controller/device overlap guards. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "pools": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ipaddrStart": {"type": "string"},
                            "ipaddrEnd": {"type": "string"},
                            "start": {"type": "string"},
                            "end": {"type": "string"},
                        },
                        "anyOf": [
                            {"required": ["ipaddrStart", "ipaddrEnd"]},
                            {"required": ["start", "end"]},
                        ],
                    },
                    "description": (
                        "Non-empty list of DHCP pools. Either the controller field names "
                        "{ipaddrStart, ipaddrEnd} or the shorthand {start, end} that "
                        "list_lan_networks returns is accepted (issue #4)."
                    ),
                },
                "vlan": {"type": "integer", "description": "Target VLAN ID (or provide netId)"},
                "netId": {"type": "string", "description": "Target LAN network ID (or provide vlan)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["pools"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_vlan_dhcp_pools,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="set_vlan_isolation",
        title="Set VLAN isolation",
        description=(
            "Toggle client/network isolation on a LAN/VLAN via the /interface endpoint and "
            "verify across both setting/lan/networks and setting/lan/networks/interface. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "isolation": {
                    "type": "boolean",
                    "description": "True to enable VLAN isolation, false to disable",
                },
                "vlan": {"type": "integer", "description": "Target VLAN ID (or provide netId)"},
                "netId": {"type": "string", "description": "Target LAN network ID (or provide vlan)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["isolation"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_vlan_isolation,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="create_ip_group",
        title="Create IPv4 IP group",
        description=(
            "Create an IPv4 IP profile group (type=0), packing ranges into <=16 aligned CIDRs "
            "(-33726)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique IPv4 IP group name"},
                "cidrs": {
                    "type": "array",
                    "description": "List of IPv4 CIDRs, IPs, ranges, or {ip, mask} objects",
                },
                "ipRange": {
                    "type": "string",
                    "description": "Optional comma-separated IPv4 ranges/CIDRs (e.g. '192.168.20.180-199')",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_ip_group,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="replace_ip_group",
        title="Replace IPv4 IP group",
        description=(
            "Replace an IPv4 IP group via delete+recreate, automatically running the 6-step "
            "temporary-group swap when ACL rules reference the group (-33717). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "group": {"type": "string", "description": "IP group ID or exact name"},
                "cidrs": {
                    "type": "array",
                    "description": "Replacement IPv4 CIDRs, IPs, ranges, or {ip, mask} objects",
                },
                "ipRange": {
                    "type": "string",
                    "description": "Replacement comma-separated IPv4 ranges/CIDRs",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["group"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=replace_ip_group,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="create_gateway_acl",
        title="Create gateway ACL rule",
        description=(
            "Create a gateway ACL rule (POST setting/firewall/acls?type=0) with anti-stranding "
            "checks for management hosts."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique gateway ACL rule name"},
                "policy": {
                    "type": ["string", "integer"],
                    "description": "Rule policy: 'deny' (0) or 'permit' (1)",
                },
                "source": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": ["string", "integer"],
                            "description": "0=network, 1=ip_group, 2=port_group",
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "Source selector: {'type': 'network'|'ip_group'|'port_group'|0|1|2, 'ids': [...]}",
                },
                "destination": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": ["string", "integer"],
                            "description": "0=network, 1=ip_group, 2=port_group",
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "Destination selector: {'type': 'network'|'ip_group'|'port_group'|0|1|2, 'ids': [...]}",
                },
                "direction": {
                    "type": "object",
                    "properties": {
                        "lanToWan": {"type": "boolean"},
                        "lanToLan": {"type": "boolean"},
                        "wanInIds": {"type": "array", "items": {"type": "string"}},
                        "vpnInIds": {"type": "array", "items": {"type": "string"}},
                    },
                    "description": "Direction flags (at least one enabled, e.g. {'lanToWan': true, 'lanToLan': false})",
                },
                "status": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable rule immediately (default true)",
                },
                "protocols": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Protocol codes (default [256] for any)",
                },
                "biDirectional": {
                    "type": "boolean",
                    "default": False,
                    "description": "Apply rule in both directions (default false)",
                },
                "syslog": {
                    "type": "boolean",
                    "default": False,
                    "description": "Log matching packets to syslog (default false)",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "policy", "source", "destination", "direction"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_gateway_acl,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="set_acl_rule_status",
        title="Enable or disable ACL rule (gateway, switch, or EAP)",
        description=(
            "Enable or disable a gateway, switch, or EAP ACL rule status without changing aclDisable."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "ACL rule ID or exact name"},
                "status": {"type": "boolean", "description": "True to enable, false to disable"},
                "aclType": {
                    "type": "string",
                    "enum": ["gateway", "switch", "eap"],
                    "description": "ACL scope (auto-detected if omitted)",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule", "status"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_acl_rule_status,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_dhcp_reservation",
        title="Create or update static DHCP reservation",
        description=(
            "Create or update a static DHCP reservation in setting/service/dhcp "
            "(works for offline MACs too; verifies pool/subnet bounds and checks silent no-op). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC address (any standard format)"},
                "ip": {"type": "string", "description": "Static IPv4 address within the target LAN subnet"},
                "vlan": {"type": ["string", "integer"], "description": "Target LAN VLAN ID or name"},
                "netId": {"type": "string", "description": "Target LAN network ID (optional when vlan is set)"},
                "description": {"type": "string", "description": "Optional reservation description"},
                "status": {"type": "boolean", "default": True, "description": "Enable reservation (default true)"},
                "exportToIpMacBinding": {"type": "boolean", "description": "Sync entry to IP-MAC binding table"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "ip"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_dhcp_reservation,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_dhcp_reservation",
        title="Delete static DHCP reservation",
        description=(
            "Delete a static DHCP reservation by MAC (DELETE setting/service/dhcp/{MAC}). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Reserved client MAC address"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_dhcp_reservation,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="create_lan_network",
        title="Create LAN or VLAN network",
        description=(
            "Create a routed LAN interface (purpose='interface', requires gatewaySubnet) or pure "
            "switch/AP VLAN (purpose='vlan') via POST setting/lan/networks. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique LAN/VLAN network name"},
                "vlan": {"type": "integer", "minimum": 1, "maximum": 4094, "description": "IEEE 802.1Q VLAN ID (1-4094)"},
                "purpose": {
                    "type": "string",
                    "enum": ["interface", "vlan"],
                    "default": "interface",
                    "description": "'interface' (routed gateway VLAN, default) or 'vlan' (L2 VLAN only)",
                },
                "gatewaySubnet": {"type": "string", "description": "Gateway IP/prefix CIDR (e.g. '10.30.0.1/24') for purpose='interface'"},
                "dhcpEnable": {"type": "boolean", "default": True, "description": "Enable DHCP server on interface"},
                "pools": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ipaddrStart": {"type": "string"},
                            "ipaddrEnd": {"type": "string"},
                            "start": {"type": "string"},
                            "end": {"type": "string"},
                        },
                        "anyOf": [
                            {"required": ["ipaddrStart", "ipaddrEnd"]},
                            {"required": ["start", "end"]},
                        ],
                    },
                    "description": (
                        "Optional DHCP pools. Either the controller field names "
                        "{ipaddrStart, ipaddrEnd} or the shorthand {start, end} that "
                        "list_lan_networks returns is accepted, so a reader's output can be "
                        "fed straight into a create."
                    ),
                },
                "leaseTime": {"type": "integer", "minimum": 1, "default": 120, "description": "DHCP lease time in minutes (default 120)"},
                "domain": {"type": "string", "description": "Optional local DNS domain suffix"},
                "isolation": {"type": "boolean", "default": False, "description": "Enable guest/network isolation"},
                "igmpSnoopEnable": {"type": "boolean", "default": False, "description": "Enable IGMP snooping"},
                "icmpPingEnable": {"type": "boolean", "default": True, "description": "Respond to ICMP ping on gateway"},
                "interfaceIds": {"type": "array", "items": {"type": "string"}, "description": "Optional LAN interface port UUIDs"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "vlan"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_lan_network,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="update_lan_network",
        title="Update LAN/VLAN settings",
        description=(
            "Update LAN/VLAN name, DHCP server, lease time, DNS servers, domain, IGMP snooping, "
            "or ICMP ping on /interface using full-object read-modify-write. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "vlan": {"type": ["string", "integer"], "description": "Target VLAN ID or network name"},
                "netId": {"type": "string", "description": "Target LAN network ID"},
                "name": {"type": "string", "description": "New network name"},
                "dhcpEnable": {"type": "boolean", "description": "Enable or disable DHCP server"},
                "leaseTime": {"type": "integer", "minimum": 1, "description": "DHCP lease time in minutes"},
                "dnsMode": {"type": "string", "enum": ["auto", "manual"], "description": "DHCP DNS mode: 'auto' or 'manual'"},
                "dnsServers": {"type": "array", "items": {"type": "string"}, "description": "1 or 2 manual IPv4 DNS server addresses"},
                "domain": {"type": "string", "description": "Local DNS domain suffix"},
                "igmpSnoopEnable": {"type": "boolean", "description": "Enable or disable IGMP snooping"},
                "icmpPingEnable": {"type": "boolean", "description": "Enable or disable gateway ICMP ping"},
                **_WRITE_CONTROL_PROPS,
            },
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_lan_network,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_lan_network",
        title="Delete LAN/VLAN network",
        description=(
            "Delete a non-primary LAN/VLAN network (refuses Default VLAN and the network holding "
            "the MCP host/management IP)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "vlan": {"type": ["string", "integer"], "description": "VLAN ID or network name"},
                "netId": {"type": "string", "description": "LAN network ID"},
                **_WRITE_CONTROL_PROPS,
            },
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_lan_network,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="update_gateway_acl",
        title="Update ACL rule (gateway, switch, or EAP)",
        description=(
            "Modify name, status, policy, endpoints, protocols, or syslog on an existing gateway, switch, or EAP ACL."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "ACL rule ID or exact name"},
                "aclType": {
                    "type": "string",
                    "enum": ["gateway", "switch", "eap"],
                    "description": "ACL scope (auto-detected if omitted)",
                },
                "name": {"type": "string", "description": "New ACL rule name"},
                "status": {"type": "boolean", "description": "Enable or disable rule"},
                "policy": {"type": ["string", "integer"], "description": "'deny' (0) or 'permit' (1)"},
                "source": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": ["string", "integer"],
                            "description": "0=net,1=ip_grp,2=port_grp,3=mac_grp,4=ssid",
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "Updated source selector",
                },
                "destination": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": ["string", "integer"],
                            "description": "0=net,1=ip_grp,2=port_grp,3=mac_grp,4=ssid",
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "Updated destination selector",
                },
                "direction": {
                    "type": "object",
                    "properties": {
                        "lanToWan": {"type": "boolean"},
                        "lanToLan": {"type": "boolean"},
                        "wanInIds": {"type": "array", "items": {"type": "string"}},
                        "vpnInIds": {"type": "array", "items": {"type": "string"}},
                    },
                    "description": "Updated direction flags",
                },
                "protocols": {"type": "array", "items": {"type": "integer"}, "description": "Protocol codes"},
                "biDirectional": {"type": "boolean", "description": "Apply rule in both directions"},
                "syslog": {"type": "boolean", "description": "Log matching traffic to syslog"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_gateway_acl,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_gateway_acl",
        title="Delete ACL rule (gateway, switch, or EAP)",
        description=(
            "Delete a gateway, switch, or EAP ACL rule by ID or exact name (DELETE setting/firewall/acls/{id}?type=0|1|2)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "ACL rule ID or exact name"},
                "aclType": {
                    "type": "string",
                    "enum": ["gateway", "switch", "eap"],
                    "description": "ACL scope (auto-detected if omitted)",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_gateway_acl,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_ip_group",
        title="Delete IPv4 IP group",
        description=(
            "Delete an unreferenced IPv4 IP group (DELETE setting/profiles/groups/0/{id}); "
            "pre-checks gateway ACL references before deletion. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "group": {"type": "string", "description": "IP group ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["group"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_ip_group,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="create_ssid",
        title="Create Wi-Fi SSID",
        description=(
            "Create a Wi-Fi SSID in a WLAN group with band selection, security mode (open or "
            "WPA2/WPA3 PSK), optional VLAN binding, PMF, and 802.11r. PSKs are never returned "
            "in diffs, snapshots, or outputs."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Broadcast SSID name"},
                "wlanGroup": {"type": "string", "description": "WLAN group name or ID (defaults to site default group)"},
                "bands": {
                    "type": ["array", "integer", "string"],
                    "description": "Bands: ['2g', '5g'] (or '6g'), comma string, or Omada bitmask (default ['2g', '5g'])",
                },
                "security": {
                    "type": "string",
                    "enum": ["open", "wpa-psk", "wpa2-psk", "wpa-wpa2-psk", "wpa3-sae"],
                    "default": "wpa2-psk",
                    "description": "Security mode: 'open', 'wpa-psk', 'wpa2-psk', 'wpa-wpa2-psk', or 'wpa3-sae'",
                },
                "psk": {"type": "string", "description": "Passphrase (8-63 chars, required unless security='open'; never echoed)"},
                "vlanId": {"type": "integer", "minimum": 1, "maximum": 4094, "description": "Optional custom VLAN tag for this SSID"},
                "guest": {"type": "boolean", "default": False, "description": "Enable guest network mode"},
                "broadcast": {"type": "boolean", "default": True, "description": "Enable/broadcast SSID (default true)"},
                "pmfMode": {"type": ["string", "integer"], "default": "disable", "description": "'disable' (3), 'capable' (2), or 'mandatory' (1)"},
                "enable11r": {"type": "boolean", "default": False, "description": "Enable 802.11r fast roaming"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_ssid,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="update_ssid",
        title="Update Wi-Fi SSID",
        description=(
            "Update an SSID via full-object PATCH (setting/wlans/{wlanId}/ssids/{ssidId}) with "
            "PSK redaction in snapshots/outputs."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "ssid": {"type": "string", "description": "Existing SSID ID or exact name"},
                "wlanGroup": {"type": "string", "description": "Optional WLAN group ID or name"},
                "name": {"type": "string", "description": "New SSID broadcast name"},
                "bands": {"type": ["array", "integer", "string"], "description": "Updated bands (['2g', '5g', '6g'] or bitmask)"},
                "psk": {"type": "string", "description": "New Wi-Fi passphrase (8-63 chars; never echoed)"},
                "vlanId": {"type": "integer", "minimum": 1, "maximum": 4094, "description": "Bind SSID to VLAN ID"},
                "clearVlan": {"type": "boolean", "default": False, "description": "Reset SSID VLAN binding to default"},
                "guest": {"type": "boolean", "description": "Toggle guest network mode"},
                "broadcast": {"type": "boolean", "description": "Enable/disable SSID broadcast"},
                "pmfMode": {"type": ["string", "integer"], "description": "'disable', 'capable', or 'mandatory'"},
                "enable11r": {"type": "boolean", "description": "Toggle 802.11r fast roaming"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["ssid"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_ssid,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_ssid",
        title="Delete Wi-Fi SSID",
        description=(
            "Delete a Wi-Fi SSID from its WLAN group (redacts PSKs in snapshots). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "ssid": {"type": "string", "description": "SSID ID or exact name"},
                "wlanGroup": {"type": "string", "description": "Optional WLAN group ID or name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["ssid"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_ssid,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_port_forward",
        title="Create or update port forwarding rule",
        description=(
            "Create or update a NAT port forwarding rule (setting/transmission/portForwardings). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Existing rule ID when updating (omit to create or match by name)"},
                "name": {"type": "string", "description": "Rule name"},
                "externalPort": {"type": "string", "description": "External port or range (e.g. '443' or '8000-8010')"},
                "forwardIp": {"type": "string", "description": "Internal LAN target IPv4 address"},
                "forwardPort": {"type": "string", "description": "Internal target port or range"},
                "protocol": {"type": ["string", "integer"], "default": "all", "description": "'all', 'tcp', 'udp', or Omada protocol integer"},
                "status": {"type": "boolean", "default": True, "description": "Enable rule (default true)"},
                "fromIp": {"type": "string", "description": "Optional source IP/CIDR restriction (empty = any)"},
                "interfaceWanPortIds": {"type": "array", "items": {"type": "string"}, "description": "Optional WAN port UUIDs"},
                "dmz": {"type": "boolean", "default": False, "description": "Enable DMZ-style forwarding (default false)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "externalPort", "forwardIp", "forwardPort"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_port_forward,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_port_forward",
        title="Delete port forwarding rule",
        description=(
            "Delete a port forwarding rule by ID or exact name. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "Port forward rule ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_port_forward,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_static_route",
        title="Create or update static route",
        description=(
            "Create or update a gateway static route (setting/transmission/staticRoutings). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Existing route ID when updating"},
                "name": {"type": "string", "description": "Route name"},
                "destination": {"type": "string", "description": "Destination IPv4 CIDR (e.g. '192.168.50.0/24')"},
                "nextHop": {"type": "string", "description": "Next-hop IPv4 address"},
                "interfaceId": {"type": "string", "description": "Optional LAN/WAN interface UUID"},
                "routeType": {"type": "integer", "default": 0, "description": "Route type (default 0 = Next Hop)"},
                "metric": {"type": "integer", "minimum": 1, "default": 1, "description": "Route metric/distance (default 1)"},
                "status": {"type": "boolean", "default": True, "description": "Enable route (default true)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "destination", "nextHop"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_static_route,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_static_route",
        title="Delete static route",
        description=(
            "Delete a gateway static route by ID or exact name. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "Static route ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_static_route,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_mdns_rule",
        title="Create or update mDNS reflector rule",
        description=(
            "Create or update an mDNS reflector rule across VLANs (AirPlay, Chromecast, printers, etc.). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Existing rule ID when updating"},
                "name": {"type": "string", "description": "mDNS rule name"},
                "profiles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Built-in or custom mDNS profile names or IDs (e.g. ['AirPlay', 'Printers'])",
                },
                "serviceNetworks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Service-hosting VLAN IDs, network names, or IDs",
                },
                "clientNetworks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Client VLAN IDs, network names, or IDs allowed to discover services",
                },
                "ruleType": {"type": "string", "enum": ["gateway", "ap"], "default": "gateway", "description": "'gateway' (default) or 'ap'"},
                "status": {"type": "boolean", "default": True, "description": "Enable rule (default true)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "profiles", "serviceNetworks", "clientNetworks"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_mdns_rule,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_mdns_rule",
        title="Delete mDNS reflector rule",
        description=(
            "Delete an mDNS reflector rule by ID or exact name. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "mDNS rule ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["rule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_mdns_rule,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="set_upnp",
        title="Enable or disable UPnP",
        description=(
            "Enable or disable UPnP on the site gateway (PUT setting/upnp; auto-selects WAN port and LANs when enabled)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "enable": {"type": "boolean", "description": "True to enable UPnP, false to disable"},
                "wanPortIds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional WAN port UUIDs when enabling UPnP",
                },
                "networkIds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional LAN IDs, VLANs, or names when enabling UPnP",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["enable"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_upnp,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
]
