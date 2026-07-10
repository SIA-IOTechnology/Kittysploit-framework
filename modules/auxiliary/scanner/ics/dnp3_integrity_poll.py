#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import integrity_poll_dnp3
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "DNP3 integrity poll",
        "description": (
            "Performs read-only DNP3 integrity-style polls: device attributes, binary inputs, "
            "binary output status, and analog inputs."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "dnp3", "utilities", "integrity", "poll"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 5,
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

    port = OptPort(ICS_PROTOCOL_PORTS["dnp3"], "DNP3 TCP port", True)
    binary_count = OptInteger(10, "Number of binary inputs to read", False)
    analog_count = OptInteger(5, "Number of analog inputs to read", False)
    src_address = OptInteger(1024, "DNP3 master source link address", False, advanced=True)
    dest_address = OptInteger(1, "DNP3 outstation destination link address", False, advanced=True)

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        print_status(f"Running DNP3 integrity poll against {host}:{self._port()}...")
        result = integrity_poll_dnp3(
            host,
            self._port(),
            self._timeout(),
            int(self.src_address or 1024),
            int(self.dest_address or 1),
            int(self.binary_count or 10),
            int(self.analog_count or 5),
        )

        if not result.connected:
            print_error(result.error or "Connection failed")
            return False

        if not result.link_alive:
            print_warning("DNP3 link status check failed — address or port may be wrong")
            return False

        ok_count = 0
        for label, ok in sorted(result.class_results.items()):
            status = "ok" if ok else "no response"
            points = result.points.get(label, 0)
            print_info(f"  {label}: {status} ({points} bytes)")
            if ok:
                ok_count += 1

        self.sync_workspace_ics(
            port=self._port(),
            protocol="dnp3",
            device_type="RTU/IED",
            purdue_level=1,
            source="auxiliary/scanner/ics/dnp3_integrity_poll",
        )

        if ok_count == 0:
            print_warning("No DNP3 integrity poll responses verified")
            return False

        print_success(f"DNP3 integrity poll completed — {ok_count} object read(s) succeeded")
        return True
