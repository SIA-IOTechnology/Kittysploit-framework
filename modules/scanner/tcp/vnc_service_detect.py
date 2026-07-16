#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect VNC/RFB remote desktop services."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.vnc.detectors import probe_vnc


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "VNC Service Detection",
        "description": "Detects VNC servers via RFB protocol version banner.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "metadata": {"max-request": 1, "product": "vnc", "vendor": "realvnc"},
        "tags": ["vnc", "network", "scanner", "remote-desktop", "discovery"],
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
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(5900, "Target VNC port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        info = probe_vnc(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False

        version = str(info.get("version") or "")
        self.set_info(
            severity="info",
            reason=f"VNC service detected (RFB {version})".strip(),
            version=version,
        )
        return True
