#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The remote host is running BGP, a popular routing protocol."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'BGP Detection',
        'description': 'The remote host is running BGP, a popular routing protocol. This indicates that the remote host is probably a network router.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['scanner', 'tcp', 'network', 'bgp', 'detection'],
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
            'https://www.acunetix.com/vulnerabilities/network/vulnerability/bgp-detection/',
            'https://www.tenable.com/plugins/nessus/11907',
        ],
    }

    port = OptPort(179, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall(bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF001D010400FFFF0000B4C0'))
            data = sock.recv(16)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if any(m.encode() in data for m in ('ffffffffffffffffffffffffffffffff',)):
            self.set_info(severity='info', reason='BGP detected')
            return True
        return False
