#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Smart Install endpoints were discovered."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Cisco Smart Install Endpoints Exposure Detection',
        'description': 'Cisco Smart Install endpoints were discovered. Exposure of SMI to untrusted networks could allow complete compromise of the switch.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['scanner', 'tcp', 'network', 'cisco', 'smi', 'exposure'],
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
            'https://blog.talosintelligence.com/2017/02/cisco-coverage-for-smart-install-client.html',
            'https://blogs.cisco.com/security/cisco-psirt-mitigating-and-detecting-potential-abuse-of-cisco-smart-install-feature',
            'https://tools.cisco.com/security/center/content/CiscoSecurityResponse/cisco-sr-20170214-smi',
            'https://github.com/Cisco-Talos/smi_check/blob/master/smi_check.py#L52-L53',
            'https://github.com/Sab0tag3d/SIET',
        ],
    }

    port = OptPort(4786, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall(bytes.fromhex('000000010000000100000004000000080000000100000000'))
            data = sock.recv(1024)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if any(m.encode() in data for m in ('000000040000000000000003000000080000000100000000',)):
            self.set_info(severity='medium', reason='Cisco Smart Install Endpoints Exposure detected')
            return True
        return False
