#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.s7_client import enumerate_s7_modules, snap7_available


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "S7 module enumeration",
        "description": (
            "Enumerates rack/slot modules on a Siemens S7 PLC using SZL 0x0013 reads "
            "(CPU, IO, CP modules)."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "siemens", "s7comm", "enumeration", "rack"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 8,
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
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["s7comm"], "S7comm port", True)
    rack = OptInteger(0, "PLC rack number", False)
    slot = OptInteger(1, "PLC slot number", False)
    password = OptString("", "Optional S7 session password", False)
    max_index = OptInteger(32, "Maximum SZL index to probe", False, advanced=True)

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        if snap7_available():
            print_info("Using python-snap7 for SZL reads when available")
        print_status(f"Enumerating S7 modules on {host}:{self._port()}...")
        modules = enumerate_s7_modules(
            host,
            self._port(),
            self._timeout(),
            int(self.rack or 0),
            int(self.slot or 1),
            str(self.password or ""),
            int(self.max_index or 32),
        )

        if not modules:
            print_warning("No modules returned — verify rack/slot or install python-snap7")
            return False

        print_success(f"Discovered {len(modules)} module record(s)")
        for item in modules:
            print_info(f"  [{item.index:02d}] {item.name or 'unknown module'}")
        return True
