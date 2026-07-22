#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate WinRM authentication methods on ports 5985/5986."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.winrm.detectors import probe_winrm


class Module(Auxiliary, Tcp_scanner_client):
    __info__ = {
        "name": "WinRM Authentication Enumeration",
        "description": "Probe WinRM /wsman and enumerate advertised authentication methods.",
        "author": ["KittySploit Team"],
        "tags": ["auxiliary", "scanner", "tcp", "winrm", "windows", "auth"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
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
        'chain':         {'produces_capabilities': [{'capability': 'winrm_access', 'from_detail': ''},
                                   {'capability': 'network_service', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(5985, "WinRM port (5985 HTTP, 5986 HTTPS)", True)
    ssl = OptBool(False, "Use HTTPS (set port 5986 when enabled)", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def check(self):
        return self.is_tcp_open()

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return {"error": "missing_target"}

        use_ssl = bool(self.ssl) or int(self.port or 5985) == 5986
        result = probe_winrm(host, int(self.port or 5985), use_ssl=use_ssl, timeout=self._timeout())
        data = result.to_dict()

        if not result.reachable:
            print_error(result.error or "WinRM endpoint unreachable")
            return data

        print_success(f"WinRM reachable on {host}:{self.port} status={result.status_code}")
        if result.server_header:
            print_info(f"Server: {result.server_header}")
        if result.auth_methods:
            print_info(f"Auth methods: {', '.join(result.auth_methods)}")
            if any(m.lower() in ("negotiate", "ntlm", "kerberos") for m in result.auth_methods):
                print_warning("NTLM/Kerberos-capable WinRM auth advertised — relay surface may apply")
        else:
            print_info("No WWW-Authenticate header observed")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data
