"""Tool descriptor list: tool_specs_read."""

from __future__ import annotations

from ._tool_model import _EMPTY, _LIMIT_PROP, _SUPPORTED_ITEMS_SCHEMA, Tool, _list_output_schema
from .audit_snapshot import (
    _NETWORK_AUDIT_SCHEMA,
    _SNAPSHOT_ALL_OBJECTS,
    _SNAPSHOT_SCHEMA,
    _get_config_snapshot,
    _network_audit_enriched,
)
from .clients_read import (
    _CLIENT_SCHEMA,
    _SEARCH_CLIENT_SCHEMA,
    _get_client,
    _list_clients,
    _list_wifi_clients,
    _list_wired_clients,
    _search_clients,
)
from .devices_read import (
    _AP_RADIOS_SCHEMA,
    _DEVICE_SCHEMA,
    _PORT_PROFILE_SCHEMA,
    _RF_SCAN_SCHEMA,
    _SWITCH_PORTS_SCHEMA,
    _WLAN_GROUP_SCHEMA,
    _WLAN_SCHEMA,
    _get_ap_radios,
    _get_device,
    _get_rf_scan,
    _get_switch_ports,
    _list_devices,
    _list_port_profiles,
    _list_wlan_groups,
    _list_wlans,
)
from .diagnostics_read import (
    _DIAGNOSE_CLIENT_SCHEMA,
    _DIAGNOSE_WAN_SCHEMA,
    _EXPLAIN_ERROR_SCHEMA,
    _LOG_SCHEMA,
    _diagnose_client,
    _diagnose_wan,
    _explain_error,
    _list_logs,
)
from .networks_read import (
    _DHCP_RES_SCHEMA,
    _LAN_NETWORK_SCHEMA,
    _SERVICES_SCHEMA,
    _SITE_INFO_SCHEMA,
    _TOPOLOGY_SCHEMA,
    _VPN_TUNNELS_SCHEMA,
    _WAN_STATUS_SCHEMA,
    _get_network_services_enriched,
    _get_site_info,
    _get_topology,
    _get_wan_status,
    _list_dhcp_reservations,
    _list_lan_networks,
    _list_vpn_tunnels,
)
from .routing_dns_read import (
    _PORT_FORWARD_SCHEMA,
    _STATIC_ROUTE_SCHEMA,
    _list_lan_dns_rules,
    _list_policy_routes,
    _list_port_forwards,
    _list_static_routes,
)
from .security_read import (
    _ACL_SCHEMA,
    _IP_GROUP_SCHEMA,
    _SECURITY_STATUS_SCHEMA,
    _get_security_status,
    _list_acls,
    _list_ip_groups,
)

READ_TOOLS: list[Tool] = [
    Tool(
        name="list_devices",
        title="List Omada devices",
        description=("List all managed network devices (APs, switches, gateways) on the site "
                    "with MAC, model, firmware, IP, uptime and client count."),
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_DEVICE_SCHEMA),
        handler=_list_devices,
    ),
    Tool(
        name="list_clients",
        title="List clients",
        description=("List connected clients (WiFi and wired) with MAC, IP, SSID, AP, VLAN, "
                    "traffic counters, session duration and last-seen time."),
        input_schema={"type": "object", "properties": {"limit": _LIMIT_PROP}},
        output_schema=_list_output_schema(_CLIENT_SCHEMA),
        handler=_list_clients,
    ),
    Tool(
        name="list_wifi_clients",
        title="List WiFi clients",
        description="List only wireless clients, same fields as list_clients.",
        input_schema={"type": "object", "properties": {"limit": _LIMIT_PROP}},
        output_schema=_list_output_schema(_CLIENT_SCHEMA),
        handler=_list_wifi_clients,
    ),
    Tool(
        name="list_wired_clients",
        title="List wired clients",
        description="List only wired clients, same fields as list_clients.",
        input_schema={"type": "object", "properties": {"limit": _LIMIT_PROP}},
        output_schema=_list_output_schema(_CLIENT_SCHEMA),
        handler=_list_wired_clients,
    ),
    Tool(
        name="get_device",
        title="Get device",
        description="Get one device by MAC address or device name.",
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string",
                        "description": "Device MAC (any format) or device name"},
            },
            "required": ["mac"],
        },
        output_schema=_DEVICE_SCHEMA,
        handler=_get_device,
    ),
    Tool(
        name="get_client",
        title="Get client",
        description="Get one client by MAC address, hostname or IP address.",
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string",
                        "description": "Client MAC (any format), hostname or IP address"},
            },
            "required": ["mac"],
        },
        output_schema=_CLIENT_SCHEMA,
        handler=_get_client,
    ),
    Tool(
        name="list_wlans",
        title="List WLANs",
        description=("List configured WLANs/SSIDs with band, VLAN, security type and guest "
                    "flag. Pre-shared keys are never returned; a boolean "
                    "hasPresharedKey reports whether one is set."),
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_WLAN_SCHEMA),
        handler=_list_wlans,
    ),
    Tool(
        name="get_site_info",
        title="Get site summary",
        description=("Site summary: name, id, WAN/LAN/WLAN state, device and client counts, "
                    "controller version."),
        input_schema=_EMPTY,
        output_schema=_SITE_INFO_SCHEMA,
        handler=_get_site_info,
    ),
    Tool(
        name="network_audit",
        title="Audit site network health",
        description=("One-call read-only health audit checking WAN state/packet loss, offline "
                    "devices, pending firmware upgrades, switch PoE budget and downgraded "
                    "uplinks, AP retry/interference spikes, 0-client APs, guest/unexpected "
                    "VLAN clients, unisolated VLANs, and DHCP pool utilization."),
        input_schema=_EMPTY,
        output_schema=_NETWORK_AUDIT_SCHEMA,
        handler=_network_audit_enriched,
    ),
    Tool(
        name="explain_error",
        title="Explain Omada errorCode",
        description=("Decode an Omada Web API errorCode (e.g. -1600, -33717, -33726, -1505, -1001, "
                    "-30109, -41011, -44116) into its meaning, ambiguity notes, and fix."),
        input_schema={
            "type": "object",
            "properties": {
                "code": {"type": "integer",
                         "description": "Numeric Omada errorCode to explain (e.g. -1600, -33726)"},
                "endpoint": {"type": "string",
                             "description": "Optional API endpoint where the error occurred"},
            },
            "required": ["code"],
        },
        output_schema=_EXPLAIN_ERROR_SCHEMA,
        handler=_explain_error,
        open_world=False,
        requires_auth=False,
    ),
    Tool(
        name="get_config_snapshot",
        title="Get site configuration snapshot",
        description=(
            "Read-only snapshot of LAN networks (both collection and /interface endpoints), "
            "gateway ACLs, IP/port groups, PSK-redacted WLANs, devices, and optional "
            "clients, dhcpReservations, portForwards, staticRoutes, mdnsRules, and services."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "objects": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(_SNAPSHOT_ALL_OBJECTS)},
                    "description": (
                        "Optional subset of sections to fetch: networks, acls, groups, wlans, "
                        "devices, clients, dhcpReservations, portForwards, staticRoutes, "
                        "mdnsRules, services (defaults to networks, acls, groups, wlans, devices)"
                    ),
                },
            },
        },
        output_schema=_SNAPSHOT_SCHEMA,
        handler=_get_config_snapshot,
    ),
    Tool(
        name="search_clients",
        title="Search clients",
        description=(
            "Search online and offline/historical clients by MAC, name, hostname, IP, SSID, or "
            "VLAN/network, with active/wireless/guest filters plus exact vlan and ssid "
            "filters. Prefers the rich clients endpoint (ssid, ip, apName, signal) and falls "
            "back to insight/clients for Viewer accounts."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Substring or MAC query matched against MAC, name, hostname, IP, SSID, or network",
                },
                "active": {
                    "type": "boolean",
                    "description": "Filter by online (true) or offline/historical (false) state; omit for all",
                },
                "wireless": {
                    "type": "boolean",
                    "description": "Filter by wireless (true) or wired (false) clients",
                },
                "guest": {
                    "type": "boolean",
                    "description": "Filter by guest flag",
                },
                "vlan": {
                    "type": "integer",
                    "description": "Filter by VLAN id (exact), e.g. 20",
                },
                "ssid": {
                    "type": "string",
                    "description": "Filter by SSID name (case-insensitive; exact match preferred)",
                },
                "limit": _LIMIT_PROP,
            },
        },
        output_schema=_list_output_schema(_SEARCH_CLIENT_SCHEMA),
        handler=_search_clients,
    ),
    Tool(
        name="list_lan_networks",
        title="List LAN and VLAN networks",
        description=(
            "List configured LAN/VLAN networks merging setting/lan/networks and /interface "
            "(subnet, VLAN ID, isolation flags, DHCP pools, lease time, domain, IGMP snooping)."
        ),
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_LAN_NETWORK_SCHEMA),
        handler=_list_lan_networks,
    ),
    Tool(
        name="list_dhcp_reservations",
        title="List static DHCP reservations",
        description="List static DHCP reservations configured on the site (works for offline clients too).",
        input_schema={
            "type": "object",
            "properties": {
                "vlan": {
                    "type": ["string", "integer"],
                    "description": "Optional VLAN ID, netId, or network name filter",
                },
            },
        },
        output_schema=_list_output_schema(_DHCP_RES_SCHEMA),
        handler=_list_dhcp_reservations,
    ),
    Tool(
        name="list_acls",
        title="List firewall ACL rules",
        description=(
            "List gateway, switch, or EAP ACL rules (setting/firewall/acls?type=0|1|2) with "
            "policy, source/destination IDs, direction, protocols, and per-rule status. "
            "Defaults to gateway ACLs for backward compatibility; pass aclType='all' for all scopes. "
            "Note: use get_config_snapshot(objects=['acls']) to inspect the advisory aclDisable flag."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "aclType": {
                    "type": "string",
                    "enum": ["gateway", "switch", "eap", "all"],
                    "default": "gateway",
                    "description": "ACL scope: 'gateway' (default), 'switch', 'eap', or 'all'",
                },
            },
        },
        output_schema=_list_output_schema(_ACL_SCHEMA),
        handler=_list_acls,
    ),
    Tool(
        name="list_ip_groups",
        title="List IP/port/MAC profile groups",
        description=(
            "List profile groups (IP groups type=0, port groups type=1, MAC groups type=2) "
            "with entry counts and ACL references."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "groupType": {
                    "type": ["string", "integer"],
                    "description": "Optional filter: 'ip' (0), 'port' (1), 'mac' (2), or 'all'",
                },
            },
        },
        output_schema=_list_output_schema(_IP_GROUP_SCHEMA),
        handler=_list_ip_groups,
    ),
    Tool(
        name="list_port_forwards",
        title="List port forwarding rules",
        description="List gateway NAT port forwarding and DMZ-mapped rules.",
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_PORT_FORWARD_SCHEMA),
        handler=_list_port_forwards,
    ),
    Tool(
        name="list_static_routes",
        title="List static routes",
        description="List configured gateway static routes (destinations, next hop, interface, metric).",
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_STATIC_ROUTE_SCHEMA),
        handler=_list_static_routes,
    ),
    Tool(
        name="get_network_services",
        title="Get network services",
        description=(
            "Summarize UPnP, DNS proxy, mDNS reflector rules and profiles, secret-redacted DDNS "
            "configuration, and sanitized WAN port status (enriched with live WAN link/latency metrics)."
        ),
        input_schema=_EMPTY,
        output_schema=_SERVICES_SCHEMA,
        handler=_get_network_services_enriched,
    ),
    Tool(
        name="list_logs",
        title="List controller alerts, events, or audit logs",
        description=(
            "Query controller site logs ('alerts', 'events', or 'audit') with time window, "
            "optional level filter, and row cap."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["alerts", "events", "audit"],
                    "default": "alerts",
                    "description": "Log stream: 'alerts' (default), 'events', or 'audit'",
                },
                "hours": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 24,
                    "description": "Lookback window in hours (default 24; 0 for all available history)",
                },
                "level": {
                    "type": ["string", "integer"],
                    "description": "Optional severity/level filter",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 100,
                    "description": "Maximum log entries to return (default 100, max 1000)",
                },
            },
        },
        output_schema=_list_output_schema(_LOG_SCHEMA),
        handler=_list_logs,
    ),
    Tool(
        name="get_switch_ports",
        title="Get switch ports, PoE & diagnostics",
        description=(
            "Inspect per-port link status, speed/duplex, PoE delivery & switch budget, active "
            "port profile/VLANs, error/drop counters, cable test results, LAGs, uplinks, and controller port."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Managed switch MAC address or exact name"},
                "includeCounters": {
                    "type": "boolean", "default": True,
                    "description": "Fetch RX/TX byte, frame, and error counters (default true)",
                },
                "includeCableTest": {
                    "type": "boolean", "default": True,
                    "description": "Include cached cable-test results if supported and previously triggered on the switch (default true)",
                },
                "includeDownPorts": {
                    "type": "boolean", "default": True,
                    "description": "Include down/unlinked ports in output (default true)",
                },
                "compact": {
                    "type": "boolean", "default": False,
                    "description": "Trim zero counters and empty cableTest/VLAN fields (default false)",
                },
            },
            "required": ["mac"],
        },
        output_schema=_SWITCH_PORTS_SCHEMA,
        handler=_get_switch_ports,
    ),
    Tool(
        name="get_ap_radios",
        title="Get AP radio & channel state",
        description=(
            "Inspect an AP's 2.4G/5G/5G2/6G radios: channel, width, TX power, channel utilization, "
            "interference, retry/drop counters, supported channels, and latest RF scan."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Managed access point MAC address or exact name"},
                "includeRfScan": {"type": "boolean", "default": True},
                "includeAvailableChannels": {"type": "boolean", "default": True},
            },
            "required": ["mac"],
        },
        output_schema=_AP_RADIOS_SCHEMA,
        handler=_get_ap_radios,
    ),
    Tool(
        name="get_rf_scan",
        title="Get AP RF scan results",
        description="Read the latest cached RF scan status/neighbor results (empty channels list if no scan was triggered) and per-radio utilization for an AP.",
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Managed access point MAC address or exact name"},
            },
            "required": ["mac"],
        },
        output_schema=_RF_SCAN_SCHEMA,
        handler=_get_rf_scan,
    ),
    Tool(
        name="get_wan_status",
        title="Get live WAN link & health status",
        description=(
            "Inspect gateway WAN link state, gateway/DNS/WAN IP, failover/load-balance mode, "
            "latency/packet loss health metrics, and latest speedtest results."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "includeSpeedtest": {"type": "boolean", "default": True},
                "maskWanIp": {
                    "type": "boolean", "default": False,
                    "description": "Mask public WAN host octets when sharing diagnostics (default false)",
                },
            },
        },
        output_schema=_WAN_STATUS_SCHEMA,
        handler=_get_wan_status,
    ),
    Tool(
        name="list_vpn_tunnels",
        title="List VPN tunnels & secret-redacted configs",
        description=(
            "List WireGuard, OpenVPN, IPsec, and SSL/L2TP VPN tunnel state and configured profiles "
            "(all private keys, PSKs, and passwords redacted)."
        ),
        input_schema=_EMPTY,
        output_schema=_VPN_TUNNELS_SCHEMA,
        handler=_list_vpn_tunnels,
    ),
    Tool(
        name="get_topology",
        title="Get site uplink topology tree",
        description="Build the site's Gateway -> Switch(port) -> AP/Switch uplink tree with device counts.",
        input_schema={
            "type": "object",
            "properties": {
                "includeClients": {
                    "type": "boolean", "default": False,
                    "description": "Include leaf client nodes in the tree (default false)",
                },
            },
        },
        output_schema=_TOPOLOGY_SCHEMA,
        handler=_get_topology,
    ),
    Tool(
        name="get_security_status",
        title="Get IPS/IDS, WIDS & rogue AP status",
        description=(
            "Summarize IPS/IDS enablement, recent threat events, attack defense limits, WIDS/WIPS, "
            "and rogue AP detections (gracefully warns when hardware/feature is unavailable)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 0, "default": 24},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
            },
        },
        output_schema=_SECURITY_STATUS_SCHEMA,
        handler=_get_security_status,
    ),
    Tool(
        name="diagnose_client",
        title="Diagnose a WiFi or wired client",
        description=(
            "Correlate client signal/link state, connection history, parent AP radio or switch port "
            "telemetry, and recent logs into actionable diagnostic findings."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Client MAC (any format), hostname, or IP"},
                "hours": {"type": "integer", "minimum": 0, "default": 24},
            },
            "required": ["mac"],
        },
        output_schema=_DIAGNOSE_CLIENT_SCHEMA,
        handler=_diagnose_client,
    ),
    Tool(
        name="diagnose_wan",
        title="Diagnose gateway WAN & VPN health",
        description=(
            "Correlate live WAN link state, latency/packet loss, speedtest, VPN tunnel health, "
            "and gateway alerts/events into deterministic findings."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "includeSpeedtest": {"type": "boolean", "default": True},
                "hours": {"type": "integer", "minimum": 0, "default": 24},
            },
        },
        output_schema=_DIAGNOSE_WAN_SCHEMA,
        handler=_diagnose_wan,
    ),
    Tool(
        name="list_port_profiles",
        title="List switch LAN port profiles",
        description="List switch port profiles (All, Disable, custom VLAN/PoE profiles).",
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_PORT_PROFILE_SCHEMA),
        handler=_list_port_profiles,
    ),
    Tool(
        name="list_wlan_groups",
        title="List WLAN groups & SSID bindings",
        description="List configured WLAN groups and their SSIDs for assigning APs cleanly.",
        input_schema=_EMPTY,
        output_schema=_list_output_schema(_WLAN_GROUP_SCHEMA),
        handler=_list_wlan_groups,
    ),
    Tool(
        name="list_policy_routes",
        title="List gateway policy routing rules",
        description="List policy routing rules (gracefully reports unavailability if no gateway exists).",
        input_schema=_EMPTY,
        output_schema=_SUPPORTED_ITEMS_SCHEMA,
        handler=_list_policy_routes,
    ),
    Tool(
        name="list_lan_dns_rules",
        title="List local LAN DNS rules",
        description="List local LAN DNS records (gracefully warns on controller versions without LAN DNS).",
        input_schema=_EMPTY,
        output_schema=_SUPPORTED_ITEMS_SCHEMA,
        handler=_list_lan_dns_rules,
    ),
]
