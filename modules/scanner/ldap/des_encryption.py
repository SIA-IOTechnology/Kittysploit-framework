#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect accounts using DES-only Kerberos encryption."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD DES Kerberos encryption",
        "description": "Detects accounts restricted to DES Kerberos encryption (weak).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "kerberos", "des", "encryption"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
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

    def run(self):
        # userAccountControl 2097152 = USE_DES_KEY_ONLY
        des = self.search(
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"],
        )
        if not des:
            return False
        names = [self.attr_str(u, "sAMAccountName") for u in des[:15]]
        self.set_info(severity="medium", reason=f"{len(des)} account(s): {', '.join(names)}")
        return True
