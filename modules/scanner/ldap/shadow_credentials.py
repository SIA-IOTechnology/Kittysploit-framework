#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect shadow credentials (msDS-KeyCredentialLink) on accounts."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD shadow credentials",
        "description": "Detects accounts with msDS-KeyCredentialLink set (PKINIT takeover possible).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "shadow credentials", "keycredential", "pkinit"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
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
        users = self.search(
            "(&(objectClass=user)(!(objectClass=computer))(msDS-KeyCredentialLink=*))",
            ["sAMAccountName", "adminCount"],
        )
        computers = self.search(
            "(&(objectClass=computer)(msDS-KeyCredentialLink=*))",
            ["sAMAccountName"],
        )
        if not users and not computers:
            return False
        admin_hits = [self.attr_str(u, "sAMAccountName") for u in users if self.attr_int(u, "adminCount") == 1]
        other = [self.attr_str(u, "sAMAccountName") for u in users if self.attr_int(u, "adminCount") != 1]
        comp_names = [self.attr_str(c, "sAMAccountName") for c in computers]
        parts = []
        if admin_hits:
            parts.append(f"admin(s): {', '.join(admin_hits[:8])}")
        if other or comp_names:
            parts.append(f"others: {', '.join((other + comp_names)[:8])}")
        self.set_info(severity="high", reason="; ".join(parts))
        return True
