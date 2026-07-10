#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.enip_client import enumerate_enip_tags
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Post, Ics_scanner_client):
    __info__ = {
        "name": "ENIP tag enumeration",
        "description": "Best-effort EtherNet/IP tag/service hints for Rockwell/Siemens CIP targets",
        "author": "KittySploit Team",
        "tags": ["ics", "enip", "cip", "gather", "tags"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints'],
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

    port = OptPort(ICS_PROTOCOL_PORTS["enip"], "EtherNet/IP port", True)

    def check(self):
        return bool(self._host())

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        tags = enumerate_enip_tags(host, self._port(), self._timeout())
        if not tags:
            print_warning("No ENIP/CIP tag hints returned")
            return False
        print_success(f"Collected {len(tags)} ENIP/CIP hint(s)")
        for tag in tags:
            print_info(f"  {tag}")
        return True
