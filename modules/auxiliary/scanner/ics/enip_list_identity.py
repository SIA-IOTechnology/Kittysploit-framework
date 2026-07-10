#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.enip_client import list_identity
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "EtherNet/IP List Identity",
        "description": (
            "Sends an EtherNet/IP List Identity request (UDP/44818) to discover "
            "Rockwell, Siemens, and other CIP devices."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "enip", "cip", "rockwell", "siemens", "enumeration"],
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
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["enip"], "EtherNet/IP UDP port", True)
    broadcast = OptBool(False, "Send List Identity as broadcast", False)

    def check(self):
        host = self._host()
        if not host and not bool(self.broadcast):
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        return {"vulnerable": True, "reason": "ready to probe ENIP", "confidence": "low"}

    def run(self):
        host = self._host() or "255.255.255.255"
        broadcast = bool(self.broadcast)
        label = "broadcast" if broadcast else f"{host}:{self._port()}"

        print_status(f"Sending EtherNet/IP List Identity to {label}...")
        devices = list_identity(
            host,
            self._port(),
            self._timeout(),
            broadcast=broadcast,
        )

        if not devices:
            print_warning("No EtherNet/IP List Identity responses received")
            return False

        print_success(f"Discovered {len(devices)} EtherNet/IP device(s)")
        for device in devices:
            print_info(
                f"  {device.host}:{device.port} | {device.vendor_name} | "
                f"{device.product_name or 'unknown product'} | rev {device.revision} | "
                f"serial 0x{device.serial_number:08X}"
            )
        return True
