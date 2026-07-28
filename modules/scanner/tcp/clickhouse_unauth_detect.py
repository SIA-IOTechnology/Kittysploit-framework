#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ClickHouse was able to be accessed with no required authentication in place."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'ClickHouse - Unauthorized Access Detection',
        'description': 'ClickHouse was able to be accessed with no required authentication in place.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['scanner', 'tcp', 'network', 'clickhouse', 'unauth', 'misconfig', 'vuln'],
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

    port = OptPort(9000, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall(bytes.fromhex('0011436c69636b486f75736520636c69656e741508b1a903000764656661756c7400'))
            data = sock.recv(100)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if all(m.encode() in data for m in ('ClickHouse', 'UTC')):
            self.set_info(severity='high', reason='ClickHouse - Unauthorized Access detected')
            return True
        return False
