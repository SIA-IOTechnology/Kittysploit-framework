#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enumerate domain/local SAM accounts via native SAMR/NetAPI (port 445, no LDAP bind).
"""

from kittysploit import *
from lib.protocols.samr import SamEnumerationError, SamEnumerator
from lib.protocols.samr.samr_scanner_client import SamrScannerClient


class Module(Auxiliary, SamrScannerClient):
    __info__ = {
        "name": "SAMR user enumeration",
        "description": (
            "Enumerate SAM accounts through MS-SAMR / NetUserEnum on port 445 without LDAP or Impacket."
        ),
        "author": "KittySploit Team",
        "tags": ["ad", "samr", "smb", "enumeration", "users"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
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
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    include_users = OptBool(True, "Include user accounts", False)
    include_computers = OptBool(True, "Include computer accounts ($)", False)
    max_accounts = OptInteger(500, "Maximum accounts to display", False)
    prefer_samr = OptBool(False, "Force SAMR RPC even on Windows (skip NetUserEnum)", False)
    show_details = OptBool(False, "Show logonCount / lastLogon metadata", False)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target host is required")
            return False

        user, password, dom = self._parse_credentials()
        max_accounts = max(1, int(getattr(self.max_accounts, "value", 500) or 500))

        print_info(f"SAMR user enumeration on {host}:{self._port()}")
        try:
            rows = SamEnumerator(
                host=host,
                port=self._port(),
                username=user,
                password=password,
                domain=dom,
                remote_name=host,
                timeout=self._timeout(),
                prefer_samr=bool(getattr(self.prefer_samr, "value", False)),
            ).enumerate(
                include_users=bool(getattr(self.include_users, "value", True)),
                include_computers=bool(getattr(self.include_computers, "value", True)),
                max_accounts=max_accounts,
            )
        except SamEnumerationError as exc:
            print_error(str(exc))
            return False

        if not rows:
            print_warning("No SAM accounts returned")
            return False

        print_info("=" * 80)
        for record in rows[:max_accounts]:
            line = f"  {record.name}"
            if bool(getattr(self.show_details, "value", False)):
                line += f" (logons={record.logon_count}, lastLogon={record.last_logon}, source={record.source})"
            print_info(line)
        if len(rows) > max_accounts:
            print_info(f"  ... and {len(rows) - max_accounts} more")

        print_success(f"Enumerated {len(rows)} SAM account(s)")
        return True
