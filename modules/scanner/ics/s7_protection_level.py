#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.s7_client import identify_s7_device


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "S7 protection level check",
        "description": (
            "Detects Siemens S7 PLCs with weak or missing access protection "
            "(protection level 1 / no password)."
        ),
        "author": "KittySploit Team",
        "severity": "critical",
        "tags": ["ics", "siemens", "s7comm", "misconfiguration", "plc"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
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
                                   {'capability': 's7comm', 'from_detail': ''},
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

        print_status(f"Checking S7 protection level on {host}:{self._port()}...")
        identity = identify_s7_device(
            host,
            self._port(),
            self._timeout(),
            int(self.rack or 0),
            int(self.slot or 1),
            str(self.password or ""),
        )

        if not identity.connected:
            self.set_info(severity="info", reason=identity.error or "connection failed")
            print_error(f"S7comm connection failed: {identity.error or 'unknown'}")
            return False

        print_info(f"  Module: {identity.module_type_name or 'unknown'}")
        print_info(f"  Protection: {identity.protection_label}")

        if identity.protection_level == 1:
            self.set_info(
                severity="critical",
                reason="S7 protection level 1 — no password protection",
                protection_level=identity.protection_level,
                module_type=identity.module_type_name,
            )
            print_success("Finding: PLC has no password protection (level 1)")
            return True

        if identity.protection_level in (0, 2, 3):
            self.set_info(
                severity="info",
                reason=f"S7 protection level {identity.protection_level} detected",
                protection_level=identity.protection_level,
            )
            print_info("PLC reports password protection enabled")
            return False

        self.set_info(severity="medium", reason="S7 reachable but protection level unknown")
        print_warning("S7comm reachable but protection level could not be parsed reliably")
        return False
