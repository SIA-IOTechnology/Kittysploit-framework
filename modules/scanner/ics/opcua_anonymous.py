#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.opcua_client import opcua_available, probe_opcua_anonymous


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "OPC UA anonymous access",
        "description": "Checks whether an OPC UA server allows anonymous browsing on port 4840",
        "author": "KittySploit Team",
        "severity": "high",
        "tags": ["ics", "opcua", "scada", "gateway", "anonymous"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals'],
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
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["opcua"], "OPC UA TCP port", True)
    ssl = OptBool(False, "Use opc.tcp with TLS endpoint", False)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        if not opcua_available():
            print_error("asyncua not installed — pip install asyncua")
            return False
        result = probe_opcua_anonymous(host, self._port(), bool(self.ssl))
        if result.anonymous:
            self.set_info(severity="high", reason="OPC UA anonymous access enabled")
            print_success(f"Anonymous OPC UA access on {result.url}")
            return True
        self.set_info(severity="info", reason=result.error or "anonymous access denied")
        print_info(result.error or "Anonymous OPC UA access not available")
        return False
