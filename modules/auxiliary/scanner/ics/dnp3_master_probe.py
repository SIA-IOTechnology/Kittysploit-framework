#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import probe_dnp3_master
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "DNP3 master probe",
        "description": "Active DNP3 master-style probe against an outstation on TCP/20000",
        "author": "KittySploit Team",
        "tags": ["ics", "dnp3", "utilities", "master"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['endpoints', 'tech_hints'],
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
        'chain':         {'produces_capabilities': [{'capability': 'dnp3_access', 'from_detail': ''},
                                   {'capability': 'dnp3_dest', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['post/ics/dnp3/gather/read_points']},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["dnp3"], "DNP3 TCP port", True)

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False
        print_status(f"Probing DNP3 outstation {host}:{self._port()}...")
        result = probe_dnp3_master(host, self._port(), self._timeout())
        if not result.connected:
            print_error(result.error or "Connection failed")
            return False
        print_success(f"DNP3 reachable on {host}:{self._port()}")
        print_info(f"  Link alive: {result.link_alive}")
        print_info(f"  Master read accepted: {result.master_accepted}")
        self.sync_workspace_ics(
            port=self._port(),
            protocol="dnp3",
            device_type="RTU/IED",
            purdue_level=1,
            source="auxiliary/scanner/ics/dnp3_master_probe",
        )
        return bool(result.link_alive or result.master_accepted)
