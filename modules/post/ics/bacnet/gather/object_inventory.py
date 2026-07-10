#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.bacnet_client import object_inventory, who_is
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Post, Ics_scanner_client):
    __info__ = {
        "name": "BACnet object inventory",
        "description": "Discovers BACnet devices and requests object inventory via ReadProperty",
        "author": "KittySploit Team",
        "tags": ["ics", "bacnet", "bms", "gather"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 4,
        'reversible': True,
        'approval_required': False,
        'produces': ['endpoints', 'tech_hints'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["bacnet"], "BACnet/IP UDP port", True)
    device_id = OptInteger(0, "BACnet device instance (0 = auto from Who-Is)", False)

    def check(self):
        return bool(self._host())

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        device_id = int(self.device_id or 0)
        if device_id <= 0:
            devices = who_is(host, self._port(), self._timeout())
            if not devices:
                print_warning("No BACnet I-Am responses")
                return False
            device_id = int(devices[0].device_id or 0)
            print_info(f"Using discovered device_id={device_id}")
        inventory = object_inventory(host, device_id, self._port(), self._timeout())
        if not inventory:
            print_warning("Object inventory request returned no parsed data")
            return False
        for item in inventory:
            print_success(
                f"Device {item.get('device_id')} on {item.get('host')} — "
                f"raw response {len(item.get('raw_hex', '')) // 2} bytes"
            )
        return True
