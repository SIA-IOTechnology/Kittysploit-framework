#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Pre-Windows 2000 Compatible Access group (Everyone/Anonymous)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client

# Well-known SIDs
_EVERYONE = "S-1-1-0"
_ANON = "S-1-5-7"
_AUTH_USERS = "S-1-5-11"

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD Pre-Windows 2000 access",
        "description": "Detects Pre-Windows 2000 group with Everyone/Anonymous (unauthenticated enumeration).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "pre-windows 2000", "enumeration"],
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
        base = self.base_dn
        if not base:
            return False
        pre2k_dn = f"CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{base}"
        grp = self.search(f"(distinguishedName={pre2k_dn})", ["member"], base=base, size_limit=1)
        if not grp:
            return False
        members = self.attr_list(grp[0], "member")
        if not members:
            return False
        # Check for Everyone or Anonymous in member DNs (often as sid ref)
        members_str = " ".join(str(m).upper() for m in members)
        everyone = "S-1-1-0" in members_str or "EVERYONE" in members_str
        anon = "S-1-5-7" in members_str or "ANONYMOUS" in members_str
        auth = "S-1-5-11" in members_str or "AUTHENTICATED" in members_str
        if everyone or anon:
            who = []
            if everyone:
                who.append("Everyone")
            if anon:
                who.append("Anonymous")
            self.set_info(severity="high", reason=f"Pre-Win2k group contains {', '.join(who)} (unauthenticated enumeration)")
            return True
        if auth:
            self.set_info(severity="medium", reason="Pre-Win2k group contains Authenticated Users")
            return True
        return False
