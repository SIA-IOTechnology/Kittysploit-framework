#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aggregate SMB signing, null session, and SMBv1 signals for NTLM relay surface."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.smb.relay_audit import audit_smb_relay_surface
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Auxiliary, Smb_scanner_client):
    __info__ = {
        "name": "SMB Relay Surface Audit",
        "description": (
            "Aggregate SMB signing posture, null session acceptance, and SMBv1 "
            "availability into a relay-risk report."
        ),
        "author": ["KittySploit Team"],
        "tags": ["auxiliary", "scanner", "smb", "ntlm", "relay", "misconfig"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['risk_signals', 'tech_hints'],
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
        'chain':         {'produces_capabilities': [{'capability': 'smb_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    output_file = OptString("", "Optional JSON output file", required=False)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return {"error": "missing_target"}

        data = audit_smb_relay_surface(host, self._port(), timeout=self._timeout())
        print_info(
            f"SMB relay audit: signing={data.get('signing_status')} "
            f"null_session={data.get('null_session')} smbv1={data.get('smbv1_enabled')}"
        )
        for finding in data.get("findings", []):
            print_warning(f"[{finding.get('severity', '').upper()}] {finding.get('description')}")

        print_success(f"Risk={data.get('risk_level')} score={data.get('risk_score')}")
        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data
