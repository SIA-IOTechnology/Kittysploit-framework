#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.bacnet_client import who_is
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "BACnet Who-Is discovery",
        "description": (
            "Sends BACnet/IP Who-Is requests (UDP/47808) and collects I-Am responses "
            "for BMS / building controller discovery."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "bacnet", "bms", "building", "enumeration"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['endpoints', 'tech_hints', 'risk_signals'],
        'cost': 1.0,
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
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["bacnet"], "BACnet/IP UDP port", True)
    broadcast = OptBool(False, "Send Who-Is as broadcast", False)

    def check(self):
        if not self._host() and not bool(self.broadcast):
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        return {"vulnerable": True, "reason": "ready to probe BACnet", "confidence": "low"}

    def run(self):
        host = self._host() or "255.255.255.255"
        broadcast = bool(self.broadcast)
        label = "broadcast" if broadcast else f"{host}:{self._port()}"

        print_status(f"Sending BACnet Who-Is to {label}...")
        devices = who_is(host, self._port(), self._timeout(), broadcast=broadcast)

        if not devices:
            print_warning("No BACnet I-Am responses received")
            return False

        print_success(f"Discovered {len(devices)} BACnet device(s)")
        for device in devices:
            print_info(
                f"  {device.host}:{device.port} | device_id={device.device_id} | "
                f"vendor_id={device.vendor_id} | max_apdu={device.max_apdu}"
            )
        return True
