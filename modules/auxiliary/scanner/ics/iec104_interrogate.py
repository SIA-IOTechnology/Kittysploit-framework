#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.iec104_client import interrogate_iec104


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "IEC 104 interrogation",
        "description": (
            "Connects to an IEC 60870-5-104 server (TCP/2404), performs STARTDT, and "
            "sends a general interrogation command (read-only activation)."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "iec104", "utilities", "scada", "enumeration"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': True,
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
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["iec104"], "IEC 104 TCP port", True)
    common_address = OptInteger(1, "Common address (CA) for interrogation ASDU", False)

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not self.is_tcp_open():
            return {"vulnerable": False, "reason": "TCP 2404 closed", "confidence": "high"}
        return {"vulnerable": True, "reason": "IEC 104 port open", "confidence": "low"}

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        print_status(
            f"Interrogating IEC 104 server {host}:{self._port()} (CA={self.common_address})..."
        )
        print_warning("Only run against authorized utility/OT lab systems")

        result = interrogate_iec104(
            host,
            self._port(),
            self._timeout(),
            int(self.common_address or 1),
        )

        if not result.connected:
            print_error(result.error or "Connection failed")
            return False

        if not result.startdt_confirmed:
            print_error(result.error or "STARTDT not confirmed by remote server")
            return False

        print_success(f"IEC 104 STARTDT confirmed on {host}:{self._port()}")
        if result.interrogation_sent:
            print_info("General interrogation command sent")
        if result.responses:
            print_info(f"  Response sample: {result.responses[0][:120]}...")
        return True
