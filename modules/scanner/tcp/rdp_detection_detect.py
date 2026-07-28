#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windows Remote Desktop Protocol was detected."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Windows Remote Desktop Protocol - Detect',
        'description': 'Windows Remote Desktop Protocol was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['scanner', 'tcp', 'network', 'windows', 'rdp', 'detection'],
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
    }

    port = OptPort(3389, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall(bytes.fromhex('0300002a25e00000000000436f6f6b69653a206d737473686173683d746573740d0a010008000b000000'))
            data = sock.recv(2048)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if any(m.encode() in data for m in ('030000130ed', '0300000b06d00000123400', '030000130ed000001234000300080002000000', '030000130ed000001234000200080002000000', '030000130ed000001234000209080002000000', '030000130ed000001234000201080002000000', '030000130ed00000123400021f080002000000', '030000130ed00000123400020f080002000000', '030000130ed00000123400020f080008000000', '030000130ed00000123400021f080008000000')):
            self.set_info(severity='info', reason='Windows Remote Desktop Protocol detected')
            return True
        return False
