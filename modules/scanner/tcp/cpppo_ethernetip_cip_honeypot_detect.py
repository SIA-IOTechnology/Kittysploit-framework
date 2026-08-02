#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected devices responding with the default configuration signature of the CPPPO (Python-based) Ethernet/IP C."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'CPPPO Ethernet/IP CIP Honeypot Default Configuration - Detect',
        'description': 'Detected devices responding with the default configuration signature of the CPPPO (Python-based) Ethernet/IP CIP parser honeypot.This indicates systems likely running the default Conpot honeypot configuration for ICS using the Common Industrial Protocol (CIP) over Ethernet/IP.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['scanner', 'tcp', 'network', 'ics', 'cip', 'honeypot'],
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
                    }],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://github.com/claroty/enip-stack-detector'],
    }

    port = OptPort(44818, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall(bytes.fromhex('63000000000000000000000000000000c1debed100000000'))
            data = sock.recv(1024)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if any(m.encode() in data for m in ('63003c00000000000000000000000000c1debed10000000001000c00360001000002af1200000000000000000000000001000e003600140b60311a066c0014313735362d4c36312f42204c4f47495835353631ff',)):
            self.set_info(severity='info', reason='CPPPO Ethernet/IP CIP Honeypot Default Configuration detected')
            return True
        return False
