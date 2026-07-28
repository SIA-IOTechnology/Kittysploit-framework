#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects remote MSMQ services."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'MSMQ (Microsoft Message Queuing Service) Remote - Detect',
        'description': 'Detects remote MSMQ services. Public exposure of this service may be a misconfiguration.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['scanner', 'tcp', 'network', 'msmq', 'detection'],
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
            'https://www.shadowserver.org/what-we-do/network-reporting/accessible-msmq-service-report/',
            'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/f9bbe350-d70b-4e90-b9c7-d39328653166',
            'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/50da7ea1-eed7-41f9-ba6a-2aa37f5f1e92',
            'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21554',
        ],
    }

    port = OptPort(1801, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall(bytes.fromhex('10c00b004c494f523c020000ffffffff00000200d1587355509195954997b6e611ea26c60789cd434c39118f44459078909ea0fc4ecade1d100300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'))
            data = sock.recv(2048)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if any(m.encode() in data for m in ('105a0b004c494f523c020000ffffffff',)):
            self.set_info(severity='info', reason='MSMQ (Microsoft Message Queuing Service) Remote detected')
            return True
        return False
