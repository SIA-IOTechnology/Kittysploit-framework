#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Microsoft Remote Desktop (RDP) service on TCP 3389."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.rdp.detectors import probe_rdp


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "RDP Service Detection",
        "description": "Detects RDP service via TPKT/X.224 pre-auth handshake.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "metadata": {"max-request": 1, "product": "rdp", "vendor": "microsoft"},
        "tags": ["rdp", "windows", "network", "scanner", "discovery"],
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

    port = OptPort(3389, "Target RDP port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        info = probe_rdp(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False

        self.set_info(severity="info", reason="RDP service detected")
        return True
