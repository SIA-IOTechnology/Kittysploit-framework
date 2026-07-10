#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.iec104_client import dump_iec104_interrogation


class Module(Post, Ics_scanner_client):
    __info__ = {
        "name": "IEC104 interrogation dump",
        "description": "Collects IEC 60870-5-104 responses after a general interrogation command",
        "author": "KittySploit Team",
        "tags": ["ics", "iec104", "utilities", "gather"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 5,
        'reversible': True,
        'approval_required': True,
        'produces': ['tech_hints', 'risk_signals'],
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

    port = OptPort(ICS_PROTOCOL_PORTS["iec104"], "IEC104 TCP port", True)
    common_address = OptInteger(1, "Common address (CA)", False)
    max_frames = OptInteger(16, "Maximum APDU frames to collect", False)

    def check(self):
        return bool(self._host())

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        result = dump_iec104_interrogation(
            host,
            self._port(),
            self._timeout(),
            int(self.common_address or 1),
            int(self.max_frames or 16),
        )
        if not result.connected or not result.startdt_confirmed:
            print_error(result.error or "Interrogation failed")
            return False
        print_success(f"Collected {len(result.responses)} IEC104 response frame(s)")
        for index, frame in enumerate(result.responses[:8], start=1):
            print_info(f"  [{index}] {frame[:120]}...")
        if not result.responses:
            print_warning("Interrogation completed — no response frames captured")
        return True
