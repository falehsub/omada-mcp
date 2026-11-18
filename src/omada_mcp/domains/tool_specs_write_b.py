"""Tool descriptor list: tool_specs_write_b."""

from __future__ import annotations

from ._tool_model import _WRITE_CONTROL_PROPS, Tool
from ._write_common import WRITE_ENVELOPE_SCHEMA
from .clients_write import (
    reconnect_client,
    set_client_blocked,
    set_client_lock_to_ap,
    set_client_rate_limit,
    update_client,
)
from .devices_write import (
    reboot_device,
    run_ping,
    run_traceroute,
    start_rf_scan,
    start_wan_speedtest,
    update_ap_radio,
    update_device,
)
from .rollback import rollback_from_snapshot
from .routing_dns_write import (
    delete_lan_dns_rule,
    delete_policy_route,
    upsert_lan_dns_rule,
    upsert_policy_route,
)
from .schedules_write import (
    bind_poe_schedule,
    delete_poe_schedule,
    delete_schedule,
    upsert_poe_schedule,
    upsert_schedule,
)
from .security_acls_write import create_eap_acl, create_switch_acl
from .security_groups_write import (
    delete_mac_group,
    delete_port_group,
    upsert_mac_group,
    upsert_port_group,
)
from .switch_l2_write import (
    delete_switch_lag,
    set_switch_port_mirror,
    update_switch_global_features,
    upsert_switch_lag,
)
from .switch_write import (
    cycle_poe_port,
    delete_port_profile,
    start_cable_test,
    update_switch_port,
    upsert_port_profile,
)
from .wireless_write import (
    assign_ap_wlan_group,
    delete_rate_limit_profile,
    run_wlan_optimization,
    set_ap_ssid_overrides,
    set_wifi_radio_features,
    upsert_rate_limit_profile,
)

WRITE_TOOLS_B: list[Tool] = [
    Tool(
        name="set_client_blocked",
        title="Block or unblock client",
        description=(
            "Block or unblock a client MAC on the site (refuses the MCP management host and "
            "managed devices)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC address"},
                "blocked": {"type": "boolean", "description": "True to block client, false to unblock"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "blocked"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_client_blocked,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="reconnect_client",
        title="Reconnect wireless client",
        description=(
            "Force an active wireless client to reassociate/reconnect to an AP "
            "(POST cmd/clients/{MAC}/reconnect)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Active wireless client MAC address"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=reconnect_client,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="update_client",
        title="Rename client",
        description=(
            "Rename a client alias using volatile-key-stripped PATCH clients/{MAC}. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC address"},
                "name": {"type": "string", "description": "New client alias/name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_client,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="update_device",
        title="Update Omada device settings",
        description=(
            "Rename an adopted AP/switch/gateway, set LED mode ('on'/'off'/'site'), or toggle "
            "device locator blink (POST cmd/devices/{MAC}/locate). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Managed Omada device MAC address or exact name"},
                "name": {"type": "string", "description": "New device name"},
                "ledSetting": {"type": ["string", "integer"], "description": "LED setting: 'off' (0), 'on' (1), or 'site' (2)"},
                "locate": {"type": "boolean", "description": "Toggle device locator LED blinking"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_device,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="reboot_device",
        title="Reboot Omada device",
        description=(
            "Reboot an adopted Omada AP, switch, or gateway (POST cmd/devices/{MAC}/reboot). "
            "Disruptive action; requires confirmation."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Managed Omada device MAC address or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=reboot_device,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="rollback_from_snapshot",
        title="Rollback change from pre-mutation snapshot",
        description=(
            "Replay or revert a prior write operation from a snapshot JSON inside OMADA_SNAPSHOT_DIR. "
            "dryRun=true diffs stored pre-mutation state against current live controller state; "
            "dryRun=false applies the restore/delete and verifies read-back."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "snapshotId": {"type": "string", "description": "Snapshot filename (.json) inside OMADA_SNAPSHOT_DIR"},
                "force": {"type": "boolean", "default": False, "description": "Allow rolling back even if newer snapshots touched this target"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["snapshotId"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=rollback_from_snapshot,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="update_switch_port",
        title="Update switch port configuration",
        description=(
            "Configure switch port status, name, port profile, PoE, speed/duplex, VLAN overrides, or isolation. "
            "Refuses mutating uplink, LAG member, or controller-hosting ports unless allowUplinkMutation=true. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Managed switch MAC address or exact name"},
                "port": {"type": "integer", "minimum": 1, "description": "1-based switch port number"},
                "enabled": {"type": "boolean", "description": "Enable/disable port link (disabling switches to Disable profile)"},
                "name": {"type": "string", "description": "Port label/description"},
                "profileId": {"type": "string", "description": "Port profile UUID to assign"},
                "profileName": {"type": "string", "description": "Port profile name to assign"},
                "profileOverrideEnable": {"type": "boolean", "description": "Enable per-port profile override"},
                "poeEnabled": {"type": "boolean", "description": "Enable/disable PoE on this port (sets override mode)"},
                "linkSpeed": {"type": ["string", "integer"], "description": "'auto', '10m', '100m', '1000m', '2500m', '10g' or code"},
                "duplex": {"type": ["string", "integer"], "description": "'auto', 'half', 'full' or code"},
                "nativeNetworkId": {"type": "string", "description": "Override native/untagged network ID"},
                "taggedNetworkIds": {"type": "array", "items": {"type": "string"}, "description": "Override tagged network IDs"},
                "untaggedNetworkIds": {"type": "array", "items": {"type": "string"}, "description": "Override additional untagged network IDs"},
                "portIsolationEnable": {"type": "boolean", "description": "Enable/disable L2 port isolation"},
                "lldpMedEnable": {"type": "boolean", "description": "Enable/disable LLDP-MED"},
                "spanningTreeEnable": {"type": "boolean", "description": "Enable/disable STP on port"},
                "allowUplinkMutation": {"type": "boolean", "default": False, "description": "Explicitly allow mutating detected uplink/LAG/controller port"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "port"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_switch_port,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="cycle_poe_port",
        title="Power-cycle PoE switch port",
        description=(
            "Momentarily power-cycle PoE output on a switch port (POST cmd/switches/{MAC}/ports/{port}/restart). "
            "Warns when downstream adopted AP/switch is powered, and guards uplink/controller-host ports unless allowUplinkMutation=true."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Managed switch MAC address or exact name"},
                "port": {"type": "integer", "minimum": 1, "description": "1-based switch port number"},
                "allowUplinkMutation": {"type": "boolean", "default": False, "description": "Override uplink/LAG/controller-port guard"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "port"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=cycle_poe_port,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="upsert_port_profile",
        title="Create or update switch port profile",
        description=(
            "Create or update a wired LAN switch port profile (setting/lan/profiles). "
            "Refuses modifying protected built-in profiles (prohibitModify=true). "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Port profile name"},
                "profileId": {"type": "string", "description": "Existing profile UUID when updating/renaming"},
                "poeMode": {"type": ["string", "integer"], "description": "'off' (0), 'on'/'poe' (1), 'poe+'/'keep' (2)"},
                "nativeNetworkId": {"type": "string", "description": "Native LAN/VLAN network ID"},
                "nativeNetworkName": {"type": "string", "description": "Native LAN/VLAN network name"},
                "taggedNetworkIds": {"type": "array", "items": {"type": "string"}, "description": "Tagged VLAN network IDs"},
                "untaggedNetworkIds": {"type": "array", "items": {"type": "string"}, "description": "Untagged VLAN network IDs"},
                "portIsolationEnable": {"type": "boolean"},
                "lldpMedEnable": {"type": "boolean"},
                "spanningTreeEnable": {"type": "boolean"},
                "loopbackDetectEnable": {"type": "boolean"},
                "flowControlEnable": {"type": "boolean"},
                "eeeEnable": {"type": "boolean"},
                "dot1x": {"type": "integer"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_port_profile,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_port_profile",
        title="Delete switch port profile",
        description=(
            "Delete a custom wired LAN switch port profile by ID or exact name "
            "(DELETE setting/lan/profiles/{id}). Refuses built-in protected profiles."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "profile": {"type": "string", "description": "Port profile ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["profile"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_port_profile,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="update_ap_radio",
        title="Update AP radio channel, width, or TX power",
        description=(
            "Update one band ('2g', '5g', '5g2', '6g') of an adopted AP while preserving sibling band blocks "
            "(PUT eaps/{MAC}/config/radios). Validates channel/channelWidth against AP channelInfo first."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Adopted AP MAC address or exact name"},
                "band": {"type": "string", "enum": ["2g", "5g", "5g1", "5g2", "6g"], "description": "Target radio band"},
                "enabled": {"type": "boolean", "description": "Enable/disable this radio band"},
                "channel": {"type": ["string", "integer"], "description": "Channel number or 'auto'"},
                "channelWidth": {"type": "string", "description": "Width: 'auto', '20', '40', '80', '160', '320' (or 20MHz..320MHz)"},
                "txPowerLevel": {"type": ["string", "integer"], "description": "'low' (0), 'medium' (1), 'high' (2), 'custom' (3), 'auto' (4)"},
                "txPower": {"type": "integer", "description": "Custom dBm TX power when txPowerLevel='custom'"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "band"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_ap_radio,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="start_rf_scan",
        title="Start AP RF environment scan",
        description=(
            "Trigger an RF spectrum scan on an adopted AP (POST cmd/eaps/{MAC}/tools/rfScan). "
            "Briefly interrupts client service while scanning."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Adopted AP MAC address or exact name"},
                "bands": {"type": "array", "items": {"type": "string"}, "description": "Optional list of bands e.g. ['2g','5g']"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=start_rf_scan,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="assign_ap_wlan_group",
        title="Assign WLAN group to AP",
        description=(
            "Assign a WLAN group by ID or exact name to an adopted AP (PUT eaps/{MAC}/config/wlans) "
            "while preserving existing ssidOverrides."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Adopted AP MAC address or exact name"},
                "wlanGroup": {"type": "string", "description": "Target WLAN group ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "wlanGroup"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=assign_ap_wlan_group,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="set_wifi_radio_features",
        title="Update site Wi-Fi radio and roaming features",
        description=(
            "Update site-wide Wi-Fi roaming (802.11r/11k, AI/non-stick/non-ping-pong roaming, "
            "force disassociation), band steering thresholds, airtime fairness, and mesh flags."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "fastRoaming80211r": {"type": "boolean", "description": "802.11r fast roaming"},
                "aiRoamingEnable": {"type": "boolean", "description": "AI roaming"},
                "dualBand11kReportEnable": {"type": "boolean", "description": "802.11k neighbor reports"},
                "forceDisassociationEnable": {"type": "boolean", "description": "Force disassociation"},
                "nonStickRoamingEnable": {"type": "boolean", "description": "Non-stick roaming"},
                "nonPingPongRoamingEnable": {"type": "boolean", "description": "Non-ping-pong roaming"},
                "bandSteeringEnable": {"type": "boolean", "description": "Site band steering"},
                "connectionThreshold": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Steering connection threshold"},
                "differenceThreshold": {"type": "integer", "minimum": 0, "maximum": 100, "description": "Steering signal difference threshold"},
                "maxFailures": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Steering max failures"},
                "multiBandMode": {
                    "type": ["string", "integer"],
                    "description": "Multi-band mode: 'disable' (0), 'prefer_5g' (1), 'balanced' (2), or 'site' (3)",
                },
                "atf2g": {"type": "boolean", "description": "2.4 GHz airtime fairness"},
                "atf5g": {"type": "boolean", "description": "5 GHz airtime fairness"},
                "atf6g": {"type": "boolean", "description": "6 GHz airtime fairness"},
                "meshEnable": {"type": "boolean", "description": "Site wireless mesh"},
                "autoFailoverEnable": {"type": "boolean", "description": "Mesh auto failover"},
                "lldpEnable": {"type": "boolean", "description": "AP LLDP"},
                "advancedFeatureEnable": {"type": "boolean", "description": "Advanced wireless features"},
                **_WRITE_CONTROL_PROPS,
            },
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_wifi_radio_features,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="upsert_policy_route",
        title="Create or update gateway policy route",
        description=(
            "Create or update a gateway PBR / policy routing rule (setting/transmission/policyRoutings). "
            "Requires an adopted gateway."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Policy route name"},
                "routeId": {"type": "string", "description": "Existing policy route ID when updating"},
                "status": {"type": "boolean", "default": True},
                "protocols": {"type": "array", "items": {"type": "integer"}, "description": "IP protocol numbers e.g. [6, 17]"},
                "sourceType": {"type": "integer", "default": 0, "description": "0=Network, 1=IP Group"},
                "sourceIds": {"type": "array", "items": {"type": "string"}},
                "destinationType": {"type": "integer", "default": 1, "description": "0=Network, 1=IP Group, 2=IP-Port Group"},
                "destinationIds": {"type": "array", "items": {"type": "string"}},
                "interfaceIds": {"type": "array", "items": {"type": "string"}, "description": "WAN/interface IDs for egress"},
                "backupInterface": {"type": "boolean", "default": True},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_policy_route,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_policy_route",
        title="Delete gateway policy route",
        description=(
            "Delete a gateway policy route by ID or exact name (DELETE setting/transmission/policyRoutings/{id})."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "routeId": {"type": "string", "description": "Policy route ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["routeId"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_policy_route,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_lan_dns_rule",
        title="Create or update local LAN DNS rule",
        description=(
            "Create or update a local LAN DNS record/CNAME/forward rule (setting/lan/dns; Omada v5.14+/v6.x gateway)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "DNS rule name"},
                "domain": {"type": "string", "description": "Hostname or domain name"},
                "ruleType": {"type": ["string", "integer"], "default": "ip", "description": "'ip' (0), 'cname' (1), 'forward' (2)"},
                "ruleId": {"type": "string", "description": "Existing rule ID when updating"},
                "enable": {"type": "boolean", "default": True},
                "ipAddresses": {"type": "array", "items": {"type": "string"}, "description": "IPv4 A record addresses for ruleType='ip'"},
                "ipv6Addresses": {"type": "array", "items": {"type": "string"}, "description": "IPv6 AAAA addresses for ruleType='ip'"},
                "cname": {"type": "string", "description": "Canonical target hostname for ruleType='cname'"},
                "dnsServers": {"type": "array", "items": {"type": "string"}, "description": "Upstream forward DNS servers for ruleType='forward'"},
                "lanNetworkIds": {"type": "array", "items": {"type": "string"}, "description": "LAN network IDs (type 0/1)"},
                "aliases": {"type": "array", "items": {"type": "string"}},
                "customTtl": {"type": "boolean", "default": False},
                "ttl": {"type": "integer", "minimum": 1, "maximum": 86400, "default": 3600},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "domain"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_lan_dns_rule,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_lan_dns_rule",
        title="Delete local LAN DNS rule",
        description=(
            "Delete a local LAN DNS rule by ID or exact name (DELETE setting/lan/dns/{id})."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "ruleId": {"type": "string", "description": "LAN DNS rule ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["ruleId"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_lan_dns_rule,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="create_switch_acl",
        title="Create switch ACL rule",
        description=(
            "Create a switch ACL rule (POST setting/firewall/acls?type=1) with anti-stranding checks. "
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique switch ACL rule name"},
                "policy": {"type": ["string", "integer"], "description": "'deny' (0) or 'permit' (1)"},
                "source": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["network", "ip_group", "port_group", "mac_group"],
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "{'type': 'network'|'ip_group'|'port_group'|'mac_group', 'ids': [...]}",
                },
                "destination": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["network", "ip_group", "port_group", "mac_group"],
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "{'type': 'network'|'ip_group'|'port_group'|'mac_group', 'ids': [...]}",
                },
                "bindingType": {"type": ["string", "integer"], "default": "all_ports", "description": "'all_ports' (0), 'custom_ports' (1), 'all_switches' (2), 'vlan' (3)"},
                "customAclPorts": {"type": "array", "items": {"type": ["object", "string"]}},
                "networkId": {"type": "string", "description": "VLAN/network ID when bindingType='vlan' (3)"},
                "status": {"type": "boolean", "default": True},
                "protocols": {"type": "array", "items": {"type": "integer"}},
                "biDirectional": {"type": "boolean", "default": False},
                "etherType": {"type": "string", "description": "Optional EtherType hex e.g. '0x0800'"},
                "syslog": {"type": "boolean", "default": False},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "policy", "source", "destination"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_switch_acl,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="create_eap_acl",
        title="Create EAP wireless ACL rule",
        description=(
            "Create an EAP ACL rule (POST setting/firewall/acls?type=2) with anti-stranding checks. "
            "Supports source/destination type 'ssid' in addition to network/group selectors."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique EAP ACL rule name"},
                "policy": {"type": ["string", "integer"], "description": "'deny' (0) or 'permit' (1)"},
                "source": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["network", "ip_group", "port_group", "mac_group", "ssid"],
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "{'type': 'network'|'ip_group'|'port_group'|'mac_group'|'ssid', 'ids': [...]}",
                },
                "destination": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["network", "ip_group", "port_group", "mac_group", "ssid"],
                        },
                        "ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["type", "ids"],
                    "description": "{'type': 'network'|'ip_group'|'port_group'|'mac_group'|'ssid', 'ids': [...]}",
                },
                "status": {"type": "boolean", "default": True},
                "protocols": {"type": "array", "items": {"type": "integer"}},
                "syslog": {"type": "boolean", "default": False},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "policy", "source", "destination"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=create_eap_acl,
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    Tool(
        name="set_client_lock_to_ap",
        title="Lock or unlock wireless client to AP(s)",
        description=(
            "Configure clientLockToApSetting on a wireless client (PATCH clients/{MAC}) using volatile-stripped RMW "
            "and wire AP MAC string normalization."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "clientMac": {"type": "string", "description": "Client MAC address"},
                "enabled": {"type": "boolean", "description": "Enable or disable lock-to-AP"},
                "apMacs": {"type": "array", "items": {"type": "string"}, "description": "Allowed AP MAC addresses or exact names (required when enabled=true)"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["clientMac", "enabled"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_client_lock_to_ap,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="set_client_rate_limit",
        title="Configure client bandwidth rate limit",
        description=(
            "Apply or disable a client rate-limit profile or custom Kbps upload/download limits via PATCH clients/{MAC}."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "clientMac": {"type": "string", "description": "Client MAC address"},
                "enabled": {"type": "boolean", "description": "Enable or disable rate limit"},
                "rateLimitProfileId": {"type": "string", "description": "Rate limit profile UUID"},
                "rateLimitProfileName": {"type": "string", "description": "Rate limit profile exact name"},
                "downLimitKbps": {"type": "integer", "minimum": 1, "description": "Custom download cap in Kbps"},
                "upLimitKbps": {"type": "integer", "minimum": 1, "description": "Custom upload cap in Kbps"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["clientMac", "enabled"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_client_rate_limit,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="upsert_port_group",
        title="Create or update IP-Port group",
        description=(
            "Create or update a TCP/UDP port group (type=1 on setting/profiles/groups) for gateway/switch/EAP ACLs."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Port group name (1-64 chars)"},
                "ports": {
                    "type": "array",
                    "items": {"type": ["string", "integer"]},
                    "description": "Port numbers or ranges e.g. ['80', '443', '8000-8080']",
                },
                "ips": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional associated IPv4 CIDRs or ranges (defaults to empty)",
                },
                "groupId": {"type": "string", "description": "Existing port group ID when updating/renaming"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "ports"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_port_group,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_port_group",
        title="Delete IP-Port group",
        description="Delete an unreferenced IP-Port group (DELETE setting/profiles/groups/1/{id}).",
        input_schema={
            "type": "object",
            "properties": {
                "group": {"type": "string", "description": "Port group ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["group"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_port_group,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_mac_group",
        title="Create or update MAC group",
        description=(
            "Create or update a MAC address group (type=2 on setting/profiles/groups) for ACLs and filtering."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "MAC group name (1-64 chars)"},
                "entries": {
                    "type": "array",
                    "items": {"type": ["string", "object"]},
                    "description": "List of MAC strings or {'name': '...', 'mac': '...'} objects",
                },
                "groupId": {"type": "string", "description": "Existing MAC group ID when updating/renaming"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "entries"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_mac_group,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_mac_group",
        title="Delete MAC group",
        description="Delete an unreferenced MAC address group (DELETE setting/profiles/groups/2/{id}).",
        input_schema={
            "type": "object",
            "properties": {
                "group": {"type": "string", "description": "MAC group ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["group"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_mac_group,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_schedule",
        title="Create or update time-range schedule",
        description="Create or update a reusable schedule/time-range profile (setting/profiles/timeranges).",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Schedule profile name (1-64 chars)"},
                "windows": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Time windows e.g. [{'start': '08:00', 'end': '17:30'}]",
                },
                "dayMode": {
                    "type": ["string", "integer"],
                    "default": "everyday",
                    "description": "'everyday' (0), 'weekday' (1), 'weekend' (2), or 'custom' (3)",
                },
                "days": {
                    "type": "array",
                    "items": {"type": ["string", "integer"]},
                    "description": "Days of week when dayMode='custom' e.g. ['mon', 'wed', 'fri']",
                },
                "scheduleId": {"type": "string", "description": "Existing schedule ID when updating/renaming"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name", "windows"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_schedule,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_schedule",
        title="Delete time-range schedule",
        description="Delete an unreferenced schedule/time-range profile (DELETE setting/profiles/timeranges/{id}).",
        input_schema={
            "type": "object",
            "properties": {
                "schedule": {"type": "string", "description": "Schedule ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["schedule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_schedule,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="run_ping",
        title="Run active ICMP ping from device",
        description="Execute an active ICMP ping test from an online adopted device (POST tools/network-check/0).",
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Source AP, switch, or gateway MAC or exact name"},
                "target": {"type": "string", "description": "Destination IPv4/IPv6 address or hostname"},
                "count": {"type": "integer", "minimum": 1, "maximum": 20, "default": 4},
                "packetSize": {"type": "integer", "minimum": 4, "maximum": 1472, "default": 56},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "target"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=run_ping,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="run_traceroute",
        title="Run active traceroute from device",
        description="Execute an active traceroute from an online adopted device (POST tools/network-check/1).",
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Source AP, switch, or gateway MAC or exact name"},
                "target": {"type": "string", "description": "Destination IPv4/IPv6 address or hostname"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "target"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=run_traceroute,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="start_wan_speedtest",
        title="Trigger WAN gateway speed test",
        description="Start a gateway WAN bandwidth speed test (POST cmd/speedTest or cmd/speedTestPure).",
        input_schema={
            "type": "object",
            "properties": {
                "pure": {"type": "boolean", "default": False, "description": "Use speedTestPure endpoint when true"},
                "pollSeconds": {"type": "integer", "minimum": 0, "maximum": 15, "default": 0},
                **_WRITE_CONTROL_PROPS,
            },
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=start_wan_speedtest,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="start_cable_test",
        title="Run TDR switch cable test",
        description=(
            "Start a switch TDR cable diagnostic test on port(s) (POST cable-test/switches/{MAC}/start; "
            "refuses uplink/controller-carrying ports unless allowUplinkMutation=true)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "deviceMac": {"type": "string", "description": "Switch MAC address or exact name"},
                "ports": {
                    "type": ["array", "integer"],
                    "items": {"type": "integer", "minimum": 1},
                    "description": "Port number or list of port numbers to test",
                },
                "allowUplinkMutation": {"type": "boolean", "default": False},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["deviceMac", "ports"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=start_cable_test,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="upsert_rate_limit_profile",
        title="Create or update rate-limit profile",
        description=(
            "Create or update a client bandwidth rate-limit profile (setting/profiles/rateLimits) "
            "with download/upload Kbps caps."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Rate-limit profile name"},
                "profileId": {"type": "string", "description": "Optional existing profile ID to update"},
                "downLimitEnable": {"type": "boolean"},
                "downLimitKbps": {"type": "integer", "minimum": 1, "description": "Download limit in Kbps"},
                "upLimitEnable": {"type": "boolean"},
                "upLimitKbps": {"type": "integer", "minimum": 1, "description": "Upload limit in Kbps"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_rate_limit_profile,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="delete_rate_limit_profile",
        title="Delete rate-limit profile",
        description=(
            "Delete a rate-limit profile (refuses the built-in Default profile or profiles referenced by SSIDs/clients)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "profile": {"type": "string", "description": "Rate-limit profile ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["profile"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_rate_limit_profile,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="set_ap_ssid_overrides",
        title="Set per-AP SSID overrides",
        description=(
            "Configure per-AP SSID overrides (custom SSID name, enable/disable, VLAN, or PSK) via "
            "PUT eaps/{MAC}/config/wlans; never logs or returns PSK secrets."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "AP MAC address or exact name"},
                "wlanGroup": {"type": "string", "description": "Optional WLAN group ID or exact name"},
                "overrides": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of override patch objects matching by index, globalSsid, or ssid",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "overrides"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_ap_ssid_overrides,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="run_wlan_optimization",
        title="Configure or trigger AI RF optimization",
        description=(
            "Configure AI RF Planning band/power/schedule settings and/or trigger or cancel WLAN optimization "
            "(rfPlanning/config, rfPlanning/schedule, cmd/rfPlanning/optimization)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["trigger", "configure", "cancel"],
                    "default": "trigger",
                    "description": "Action to perform: trigger scan, configure settings only, or cancel running scan",
                },
                "mode": {"type": ["string", "integer"], "description": "'auto' (0) or 'custom' (1)"},
                "channelDeployEnable2g": {"type": "boolean"},
                "channelDeployEnable5g": {"type": "boolean"},
                "channelDeployEnable6g": {"type": "boolean"},
                "powerAdjustEnable2g": {"type": "boolean"},
                "powerAdjustEnable5g": {"type": "boolean"},
                "powerAdjustEnable6g": {"type": "boolean"},
                "chanWidth2g": {"type": "integer"},
                "chanWidth5g": {"type": "integer"},
                "chanWidth6g": {"type": "integer"},
                "scheduleEnable": {"type": "boolean"},
                "timingType": {"type": "integer", "description": "1=daily, 2=weekly, 3=monthly"},
                "hour": {"type": "integer", "minimum": 0, "maximum": 23},
                "minute": {"type": "integer", "minimum": 0, "maximum": 59},
                "dayOfWeek": {"type": "integer", "minimum": 0, "maximum": 6},
                "dayOfMonth": {"type": "integer", "minimum": 1, "maximum": 31},
                **_WRITE_CONTROL_PROPS,
            },
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=run_wlan_optimization,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    Tool(
        name="upsert_switch_lag",
        title="Create or update switch LAG / LACP group",
        description=(
            "Create or update a switch LAG/LACP port-channel group (switches/{MAC}/lags or aggregating ports) "
            "with anti-stranding uplink/controller-port safety checks."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Switch MAC address or exact name"},
                "lagId": {"type": "integer", "minimum": 1, "maximum": 64, "description": "LAG ID (1..64)"},
                "ports": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 1},
                    "description": "Two or more switch port numbers in this LAG",
                },
                "lagType": {
                    "type": ["string", "integer"],
                    "default": "static",
                    "description": "'static' (1), 'lacp' (2), 'lacp_active' (3), or 'lacp_passive' (4)",
                },
                "name": {"type": "string", "description": "Optional LAG interface label"},
                "profileId": {"type": "string"},
                "profileName": {"type": "string"},
                "allowUplinkMutation": {"type": "boolean", "default": False},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "lagId", "ports"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_switch_lag,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_switch_lag",
        title="Delete switch LAG group",
        description=(
            "Remove a switch LAG/LACP port-channel group (DELETE switches/{MAC}/lags/{lagId}; "
            "blocks removing an active uplink/controller-carrying LAG unless allowUplinkMutation=true)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Switch MAC address or exact name"},
                "lagId": {"type": "integer", "minimum": 1, "maximum": 64},
                "allowUplinkMutation": {"type": "boolean", "default": False},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "lagId"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_switch_lag,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="update_switch_global_features",
        title="Update switch global L2 features",
        description=(
            "Update switch-level STP/RSTP/MSTP mode and timers, loopback detection, and jumbo frame MTU "
            "(switches/{MAC}/config/general and switches/{MAC}/config/services)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Switch MAC address or exact name"},
                "stpMode": {"type": ["string", "integer"], "description": "'off' (0), 'stp' (1), 'rstp' (2), or 'mstp' (3)"},
                "stpPriority": {"type": "integer", "minimum": 0, "maximum": 61440},
                "helloTime": {"type": "integer", "minimum": 1, "maximum": 10},
                "maxAge": {"type": "integer", "minimum": 6, "maximum": 40},
                "forwardDelay": {"type": "integer", "minimum": 4, "maximum": 30},
                "txHoldCount": {"type": "integer", "minimum": 1, "maximum": 20},
                "maxHops": {"type": "integer", "minimum": 1, "maximum": 40},
                "loopbackDetectEnable": {"type": "boolean"},
                "jumboEnable": {"type": "boolean"},
                "jumbo": {"type": "integer", "minimum": 1518, "maximum": 9216},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=update_switch_global_features,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="set_switch_port_mirror",
        title="Configure or clear switch port mirroring",
        description=(
            "Configure a switch port as a SPAN mirror destination monitoring mirroredPorts/mirroredLags, "
            "or pass mirroredPorts=[] to restore normal switching (refuses mirroring destination on active uplink)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Switch MAC address or exact name"},
                "mirroringPort": {"type": "integer", "minimum": 1, "description": "Destination analyzer port number"},
                "mirroredPorts": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 1},
                    "description": "Source port numbers to mirror (empty list [] clears mirroring)",
                },
                "mirroredLags": {"type": "array", "items": {"type": "integer", "minimum": 1}},
                "allowUplinkMutation": {"type": "boolean", "default": False},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["mac", "mirroringPort", "mirroredPorts"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=set_switch_port_mirror,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="upsert_poe_schedule",
        title="Create or update PoE power schedule",
        description=(
            "Create or update a site PoE power schedule referencing a time-range profile and optional switch port bindings."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "PoE schedule name"},
                "poeScheduleId": {"type": "string", "description": "Optional existing PoE schedule ID to update"},
                "schedule": {"type": "string", "description": "Time-range profile ID or exact name (turnOnTime)"},
                "enabled": {"type": "boolean", "default": True},
                "portBindings": {
                    "type": "object",
                    "description": "Optional map of switch MAC/name -> list of PoE port numbers",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["name"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=upsert_poe_schedule,
        read_only=False,
        destructive=False,
        idempotent=True,
    ),
    Tool(
        name="bind_poe_schedule",
        title="Bind switch ports to PoE schedule",
        description=(
            "Attach or replace a switch's PoE ports on an existing PoE schedule (setting/service/poeSchedules)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "poeSchedule": {"type": "string", "description": "PoE schedule ID or exact name"},
                "mac": {"type": "string", "description": "Switch MAC address or exact name"},
                "ports": {"type": "array", "items": {"type": "integer", "minimum": 1}},
                "replace": {
                    "type": "boolean",
                    "default": False,
                    "description": "Replace existing bindings for this switch (pass ports=[] + replace=true to unbind)",
                },
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["poeSchedule", "mac", "ports"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=bind_poe_schedule,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    Tool(
        name="delete_poe_schedule",
        title="Delete PoE power schedule",
        description="Delete a PoE power schedule by ID or exact name.",
        input_schema={
            "type": "object",
            "properties": {
                "poeSchedule": {"type": "string", "description": "PoE schedule ID or exact name"},
                **_WRITE_CONTROL_PROPS,
            },
            "required": ["poeSchedule"],
        },
        output_schema=WRITE_ENVELOPE_SCHEMA,
        handler=delete_poe_schedule,
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
]
