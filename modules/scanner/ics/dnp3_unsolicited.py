#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import probe_dnp3_unsolicited
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "DNP3 unsolicited enabled",
        "description": "Checks whether a DNP3 outstation accepts unsolicited response configuration",
        "author": "KittySploit Team",
        "severity": "medium",
        "tags": ["ics", "dnp3", "utilities", "unsolicited"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': True,
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
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["dnp3"], "DNP3 TCP port", True)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        print_status(f"Probing DNP3 unsolicited on {host}:{self._port()}...")
        result = probe_dnp3_unsolicited(host, self._port(), self._timeout())
        if not result.connected:
            self.set_info(severity="info", reason="connection failed")
            print_error(result.error or "Connection failed")
            return False
        if result.unsolicited_enabled:
            self.set_info(severity="medium", reason="DNP3 unsolicited configuration accepted")
            print_success("DNP3 unsolicited responses appear enabled")
            self.sync_workspace_ics(
                port=self._port(),
                protocol="dnp3",
                device_type="RTU/IED",
                purdue_level=1,
                source="scanner/ics/dnp3_unsolicited",
            )
            return True
        self.set_info(severity="info", reason="unsolicited not verified")
        print_info("DNP3 unsolicited configuration not verified")
        return False
