#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.enip_client import scan_enip_cip
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "EtherNet/IP CIP scan",
        "description": "Combines List Identity with TCP CIP Register Session probing",
        "author": "KittySploit Team",
        "severity": "medium",
        "tags": ["ics", "enip", "cip", "rockwell", "siemens"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
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

    port = OptPort(ICS_PROTOCOL_PORTS["enip"], "EtherNet/IP port", True)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        result = scan_enip_cip(host, self._port(), self._timeout())
        if result.identity:
            ident = result.identity
            print_success(
                f"ENIP identity {ident.vendor_name} / {ident.product_name} "
                f"rev {ident.revision} on {host}:{self._port()}"
            )
        if result.session_registered:
            self.set_info(severity="medium", reason="CIP session registration accepted")
            print_success("CIP Register Session accepted")
            return True
        self.set_info(severity="info", reason=result.error or "CIP session not verified")
        print_info(result.error or "CIP session registration not verified")
        return bool(result.identity)
