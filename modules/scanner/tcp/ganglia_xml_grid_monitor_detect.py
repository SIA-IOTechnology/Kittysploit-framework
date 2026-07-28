#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ganglia is a scalable distributed monitoring system for high-performance computing systems such as clusters an."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Ganglia XML Grid Monitor Detection',
        'description': 'Ganglia is a scalable distributed monitoring system for high-performance computing systems such as clusters and Grids.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['scanner', 'tcp', 'network', 'ganglia', 'misconfig'],
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
        'references': ['http://ganglia.info/'],
    }

    port = OptPort(8649, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall('\r\n'.encode())
            data = sock.recv(2048)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if all(m.encode() in data for m in ('<!DOCTYPE GANGLIA_XML', '<!ATTLIST', '<!ELEMENT')):
            self.set_info(severity='low', reason='Ganglia XML Grid Monitor detected')
            return True
        return False
