"""Allowlisted controller fields for configuration, service, and routing reads.

Unknown firmware fields are deliberately omitted, including inside nested objects.
These exports are diagnostic snapshots, not controller backup/restore payloads.
"""
from __future__ import annotations

from typing import Any, Mapping


def _fields(*names: str) -> dict:
    return dict.fromkeys(names)


_DHCP = {
    **_fields('enable', 'ipaddrStart', 'ipaddrEnd', 'ipRangeStart', 'ipRangeEnd',
              'leaseTime', 'leasetime', 'dnsEnable', 'priDns', 'sndDns', 'gateway', 'domain'),
    'ipRangePool': [_fields('ipaddrStart', 'ipaddrEnd', 'start', 'end')],
}
_NETWORK = {
    **_fields('id', 'name', 'vlan', 'purpose', 'gatewaySubnet', 'isolation',
              'interfaceIsolation', 'existNetworkIsolation', 'accessControlRule',
              'igmpSnoop', 'igmpSnoopEnable', 'domain'),
    'dhcpSettings': _DHCP,
    'lanNetworkIpv6Config': _fields('proto', 'enable', 'address', 'prefix', 'prefixLength'),
}
_GROUP = {
    **_fields('id', 'groupId', 'name', 'type', 'resource', 'description'),
    'ipList': [_fields('ip', 'mask', 'description')],
    'portList': [_fields('portStart', 'portEnd', 'protocol', 'description')],
    'macList': [None],
}
_ACL = {
    **_fields('id', 'index', 'name', 'status', 'policy', 'sourceType',
              'destinationType', 'biDirectional', 'syslog', 'bindingType', 'networkId'),
    'sourceIds': [None], 'destinationIds': [None], 'protocols': [None],
    'direction': {**_fields('lanToWan', 'lanToLan'), 'wanInIds': [None], 'vpnInIds': [None]},
    'customAclPorts': [_fields('portStart', 'portEnd', 'protocol')],
}
_MDNS = {
    **_fields('id', 'name', 'status', 'type'),
    'osg': {'profileIds': [None], 'serviceNetworks': [None], 'clientNetworks': [None]},
    'ap': {**_fields('serviceVlan'), 'profileIds': [None], 'clientVlan': [None]},
}
_DDNS = _fields('id', 'name', 'domain', 'provider', 'service', 'status', 'enable', 'updateTime')
_SHAPES = {
    'networks': {**_NETWORK, 'collection': _NETWORK, 'interface': _NETWORK},
    'groups': _GROUP,
    'acls': _ACL,
    'mdnsRules': _MDNS,
    'mdnsProfiles': {**_fields('id', 'name', 'defaultProfile'), 'serviceId': [None]},
    'upnp': {**_fields('enable', 'resource'), 'wanPortIds': [None], 'networkIds': [None]},
    'dnsProxy': _fields('enable', 'supportDnsOverride', 'dnsOverride', 'dnssec', 'cacheEnable'),
    'ddns': {**_DDNS, 'totalRows': None, 'data': [_DDNS]},
    'policyRoutes': {
        **_fields('id', 'name', 'status', 'sourceType', 'destinationType',
                  'backupInterface', 'interfaceType', 'interfaceId'),
        'sourceIds': [None], 'destinationIds': [None], 'protocols': [None], 'wanPortIds': [None],
    },
    'lanDnsRules': {
        **_fields('id', 'name', 'enable', 'domain', 'type', 'customTtl', 'ttl', 'cname', 'server'),
        'aliases': [None], 'ipAddresses': [None], 'ipv6Addresses': [None],
        'dnsServers': [None], 'lanNetworkIds': [None],
    },
}


def _project(value: Any, shape: Any) -> Any:
    if isinstance(shape, dict):
        if not isinstance(value, Mapping):
            return None
        return {key: _project(value[key], child) for key, child in shape.items() if key in value}
    if isinstance(shape, list):
        if not isinstance(value, list):
            return []
        return [_project(item, shape[0]) for item in value]
    return value if value is None or isinstance(value, (str, int, float, bool)) else None


def project_controller_row(section: str, row: Mapping[str, Any]) -> dict:
    """Project a known section without exposing new controller fields."""
    return _project(row, _SHAPES[section])
