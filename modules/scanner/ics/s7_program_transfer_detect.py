#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.s7_client import probe_s7_program_transfer


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "S7 program transfer detect",
        "description": (
            "Actively probes whether Siemens S7 program-transfer jobs appear reachable "
            "(upload/download channel). Complements passive sniffer detections."
        ),
        "author": "KittySploit Team",
        "severity": "high",
        "tags": ["ics", "siemens", "s7comm", "program", "upload", "download"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['network_probe', 'active_exploitation'],
        'expected_requests': 6,
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
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["s7comm"], "S7comm port", True)
    rack = OptInteger(0, "PLC rack number", False)
    slot = OptInteger(1, "PLC slot number", False)
    password = OptString("", "Optional S7 session password", False)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False

        print_status(f"Probing S7 program-transfer jobs on {host}:{self._port()}...")
        print_warning("Only run against authorized OT lab systems")

        probes = probe_s7_program_transfer(
            host,
            self._port(),
            self._timeout(),
            int(self.rack or 0),
            int(self.slot or 1),
            str(self.password or ""),
        )
        if not probes:
            self.set_info(severity="info", reason="S7comm connection failed")
            print_error("Could not connect to S7comm service")
            return False

        accepted = [item for item in probes if item.accepted]
        for item in probes:
            status = "OPEN" if item.accepted else "denied"
            print_info(f"  job 0x{item.job_type:02X}: {status} — {item.detail}")

        if accepted:
            self.set_info(
                severity="high",
                reason="S7 program-transfer channel appears reachable",
                jobs=[hex(item.job_type) for item in accepted],
            )
            print_success(
                f"Finding: {len(accepted)} program-transfer job(s) appear reachable"
            )
            return True

        self.set_info(severity="info", reason="Program-transfer jobs denied or filtered")
        print_info("Program-transfer jobs appear blocked")
        return False
