#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects IBM AIX Web-based System Manager services."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'AIX WebSM - Detect',
        'description': 'Detects IBM AIX Web-based System Manager services.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['scanner', 'tcp', 'network', 'aix', 'detection'],
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
            'https://en.wikipedia.org/wiki/IBM_Web-based_System_Manager',
            'https://www.filibeto.org/unix/aix/lib/rel/5.2/wsmadmn.pdf',
        ],
    }

    port = OptPort(9090, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall('en_US\r\n'.encode())
            data = sock.recv(4096)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if all(m.encode() in data for m in ('/var/websm/', 'startNewWServer')):
            self.set_info(severity='info', reason='AIX WebSM detected')
            return True
        return False
