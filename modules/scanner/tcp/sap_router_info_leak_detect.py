#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAPRouter contains an information leakage vulnerability."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'SAPRouter - Routing information leak Detection',
        'description': 'SAPRouter contains an information leakage vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['scanner', 'tcp', 'network', 'sap', 'misconfig', 'saprouter', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://securityforeveryone.com/tools/saprouter-routing-information-leakage-vulnerability-scanner',
            'https://support.sap.com/en/tools/connectivity-tools/saprouter.html',
        ],
    }

    port = OptPort(3299, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall(bytes.fromhex('00000022524f555445525f41444d002802000000000000000000000000000000000000000000'))
            data = sock.recv(2048)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if any(m.encode() in data for m in ('Routtab', 'Working directory', 'SAProuter Connection Table')):
            self.set_info(severity='critical', reason='SAPRouter - Routing information leak detected')
            return True
        return False
