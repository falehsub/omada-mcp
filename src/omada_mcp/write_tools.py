"""Backward-compatible facade re-exporting all write-support handlers and helpers."""

from __future__ import annotations

from .domains._write_common import (
    _ACL_DISPATCH_NOTES as _ACL_DISPATCH_NOTES,
)
from .domains._write_common import (
    _BAND_TO_RADIO_ID as _BAND_TO_RADIO_ID,
)
from .domains._write_common import (
    _DEV_ENDPOINT_PREFIX as _DEV_ENDPOINT_PREFIX,
)
from .domains._write_common import (
    _LED_MODES as _LED_MODES,
)
from .domains._write_common import (
    _SOURCE_DEST_TYPES as _SOURCE_DEST_TYPES,
)
from .domains._write_common import (
    CLIENT_VOLATILE_KEYS,
    WRITE_ENVELOPE_SCHEMA,
)
from .domains._write_common import (
    _normalize_mac as _normalize_mac,
)
from .domains._write_common import (
    _site as _site,
)
from .domains._write_common import (
    _unwrap_rows as _unwrap_rows,
)
from .domains._write_fetchers import (
    _fetch_acls as _fetch_acls,
)
from .domains._write_fetchers import (
    _fetch_clients_filtered as _fetch_clients_filtered,
)
from .domains._write_fetchers import (
    _fetch_devices as _fetch_devices,
)
from .domains._write_fetchers import (
    _fetch_dhcp_reservations as _fetch_dhcp_reservations,
)
from .domains._write_fetchers import (
    _fetch_groups as _fetch_groups,
)
from .domains._write_fetchers import (
    _fetch_insight_clients as _fetch_insight_clients,
)
from .domains._write_fetchers import (
    _fetch_lan_collection as _fetch_lan_collection,
)
from .domains._write_fetchers import (
    _fetch_lan_dns_rules as _fetch_lan_dns_rules,
)
from .domains._write_fetchers import (
    _fetch_lan_interfaces as _fetch_lan_interfaces,
)
from .domains._write_fetchers import (
    _fetch_lan_profiles as _fetch_lan_profiles,
)
from .domains._write_fetchers import (
    _fetch_mdns_profiles as _fetch_mdns_profiles,
)
from .domains._write_fetchers import (
    _fetch_mdns_rules as _fetch_mdns_rules,
)
from .domains._write_fetchers import (
    _fetch_policy_routes as _fetch_policy_routes,
)
from .domains._write_fetchers import (
    _fetch_port_forwards as _fetch_port_forwards,
)
from .domains._write_fetchers import (
    _fetch_ssids as _fetch_ssids,
)
from .domains._write_fetchers import (
    _fetch_static_routes as _fetch_static_routes,
)
from .domains._write_fetchers import (
    _fetch_typed_acls as _fetch_typed_acls,
)
from .domains._write_fetchers import (
    _fetch_wan_networks as _fetch_wan_networks,
)
from .domains._write_fetchers import (
    _fetch_wlan_groups as _fetch_wlan_groups,
)
from .domains._write_fetchers import (
    _omada_mac as _omada_mac,
)
from .domains._write_safety import (
    _check_dhcp_pools_safety as _check_dhcp_pools_safety,
)
from .domains._write_safety import (
    pack_ip_entries,
)
from .domains.clients_write import (
    reconnect_client,
    release_client_fixed_ip,
    set_client_blocked,
    set_client_fixed_ip,
    set_client_lock_to_ap,
    set_client_rate_limit,
    update_client,
)
from .domains.devices_write import reboot_device, start_rf_scan, update_ap_radio, update_device
from .domains.networks_write import (
    create_lan_network,
    delete_lan_network,
    set_vlan_dhcp_pools,
    set_vlan_isolation,
    update_lan_network,
)
from .domains.rollback import rollback_from_snapshot
from .domains.routing_dns_write import (
    delete_lan_dns_rule,
    delete_policy_route,
    delete_port_forward,
    delete_static_route,
    upsert_lan_dns_rule,
    upsert_policy_route,
    upsert_port_forward,
    upsert_static_route,
)
from .domains.security_acls_write import (
    create_eap_acl,
    create_gateway_acl,
    create_switch_acl,
    delete_gateway_acl,
    set_acl_rule_status,
    update_gateway_acl,
)
from .domains.security_groups_write import create_ip_group, delete_ip_group, replace_ip_group
from .domains.services_write import (
    delete_dhcp_reservation,
    delete_mdns_rule,
    set_upnp,
    upsert_dhcp_reservation,
    upsert_mdns_rule,
)
from .domains.switch_write import (
    _build_switch_port_patch as _build_switch_port_patch,
)
from .domains.switch_write import (
    _switch_port_summary as _switch_port_summary,
)
from .domains.switch_write import (
    cycle_poe_port,
    update_switch_port,
    upsert_port_profile,
)
from .domains.switch_write import (
    delete_port_profile as delete_port_profile,
)
from .domains.wireless_write import (
    _parse_ssid_security as _parse_ssid_security,
)
from .domains.wireless_write import (
    assign_ap_wlan_group,
    create_ssid,
    delete_ssid,
    update_ssid,
)

__all__ = [
    "CLIENT_VOLATILE_KEYS",
    "WRITE_ENVELOPE_SCHEMA",
    "assign_ap_wlan_group",
    "create_eap_acl",
    "create_gateway_acl",
    "create_ip_group",
    "create_lan_network",
    "create_ssid",
    "create_switch_acl",
    "cycle_poe_port",
    "delete_dhcp_reservation",
    "delete_gateway_acl",
    "delete_ip_group",
    "delete_lan_dns_rule",
    "delete_lan_network",
    "delete_mdns_rule",
    "delete_policy_route",
    "delete_port_forward",
    "delete_ssid",
    "delete_static_route",
    "pack_ip_entries",
    "reboot_device",
    "reconnect_client",
    "release_client_fixed_ip",
    "replace_ip_group",
    "rollback_from_snapshot",
    "set_acl_rule_status",
    "set_client_blocked",
    "set_client_fixed_ip",
    "set_client_lock_to_ap",
    "set_client_rate_limit",
    "set_upnp",
    "set_vlan_dhcp_pools",
    "set_vlan_isolation",
    "start_rf_scan",
    "update_ap_radio",
    "update_client",
    "update_device",
    "update_gateway_acl",
    "update_lan_network",
    "update_ssid",
    "update_switch_port",
    "upsert_dhcp_reservation",
    "upsert_lan_dns_rule",
    "upsert_mdns_rule",
    "upsert_policy_route",
    "upsert_port_forward",
    "upsert_port_profile",
    "upsert_static_route",
]
