#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect WinRM /wsman endpoints and advertised auth methods."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.winrm.detectors import probe_winrm


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "WinRM Service Detection",
        "description": "Detects WinRM /wsman endpoints on ports 5985/5986.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["winrm", "windows", "network", "scanner", "discovery"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 1,
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
        'chain':         {'produces_capabilities': [{'capability': 'network_service', 'from_detail': ''},
                                   {'capability': 'remote_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['auxiliary/scanner/tcp/winrm_auth_enum']},
    },
    }

    port = OptPort(5985, "WinRM port (5985 HTTP, 5986 HTTPS)", True)
    ssl = OptBool(False, "Use HTTPS (set port 5986 when enabled)", required=False)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        use_ssl = bool(self.ssl) or int(port) == 5986
        info = probe_winrm(host, int(port), use_ssl=use_ssl, timeout=self._timeout()).to_dict()
        if not info.get("reachable"):
            return False

        methods = info.get("auth_methods") or []
        self.set_info(
            severity="info",
            reason="WinRM service detected",
            auth_methods=methods,
            ssl=use_ssl,
        )
        return True
