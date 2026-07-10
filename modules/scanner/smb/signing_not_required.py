#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection SMB signing désactivé ou non requis (relais NTLM)."""

from kittysploit import *
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "SMB signing not required",
        "description": "Detects SMB signing disabled or not required (NTLM relay possible).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["smb", "scanner", "signing", "relay", "ntlm"],
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
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        if not self._host():
            return False
        status, ver = self.smb_signing_status()
        if status == "unreachable" or status == "error":
            return False
        if status == "disabled":
            ver_str = ver or "SMB2/3"
            self.set_info(severity="high", reason=f"Signing disabled ({ver_str})")
            return True
        if status == "enabled_not_required":
            ver_str = ver or "SMB2/3"
            self.set_info(severity="medium", reason=f"Signing enabled but not required ({ver_str})")
            return True
        if status == "smb2_disabled" and self.smb1_enabled():
            self.set_info(severity="high", reason="SMBv1 only — SMB2/3 signing not applicable")
            return True
        return False
