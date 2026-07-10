#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import probe_dnp3_operate
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "DNP3 operate enabled",
        "description": (
            "Tests whether a DNP3 outstation accepts SELECT or Direct Operate CROB commands "
            "without authentication (group 12). Uses control code 0x00 (NULL)."
        ),
        "author": "KittySploit Team",
        "severity": "high",
        "tags": ["ics", "dnp3", "utilities", "misconfiguration", "operate", "write"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['network_probe', 'active_exploitation'],
        'expected_requests': 4,
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
    point_index = OptInteger(0, "Binary output point index for CROB probe", False)
    confirm = OptBool(False, "Confirm intentional DNP3 operate probe", True)
    src_address = OptInteger(1024, "DNP3 master source link address", False, advanced=True)
    dest_address = OptInteger(1, "DNP3 outstation destination link address", False, advanced=True)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        if not bool(self.confirm):
            print_error("Refusing to probe DNP3 operate without confirm=true")
            return False

        print_warning("Authorized lab use only — sends SELECT/Direct Operate CROB probes")
        print_status(
            f"Testing DNP3 operate on {host}:{self._port()} (index={self.point_index})..."
        )

        result = probe_dnp3_operate(
            host,
            self._port(),
            self._timeout(),
            int(self.src_address or 1024),
            int(self.dest_address or 1),
            int(self.point_index or 0),
        )

        if not result.connected:
            self.set_info(severity="info", reason=result.error or "connection failed")
            print_error(result.error or "Connection failed")
            return False

        if result.select_accepted or result.direct_operate_accepted:
            self.set_info(
                severity="high",
                reason="DNP3 operate commands accepted",
                select=result.select_accepted,
                direct_operate=result.direct_operate_accepted,
            )
            print_success("DNP3 operate path appears open")
            print_info(f"  SELECT accepted: {result.select_accepted}")
            print_info(f"  Direct Operate accepted: {result.direct_operate_accepted}")
            return True

        self.set_info(severity="info", reason="operate commands not verified")
        print_info("DNP3 operate commands not verified")
        return False
