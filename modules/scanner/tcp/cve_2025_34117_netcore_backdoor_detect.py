#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Netcore/Netis UDP backdoor on port 53413 (CVE-2025-34117 / 2014 disclosure)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Netcore/Netis - UDP Backdoor Detection (CVE-2025-34117)',
        'description': (
            'Detects Netcore/Netis UDP backdoor on port 53413 by sending '
            'XXXXXXXXnetcore and matching Login successed.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'udp', 'netcore', 'netis', 'backdoor', 'iot', 'cve', 'cve2025', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-34117',
        ],
        'cve': 'CVE-2025-34117',
    }

    port = OptPort(53413, 'UDP backdoor port', True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self._timeout())
            sock.sendto(b'', (host, port))
            try:
                data, _ = sock.recvfrom(64)
            except socket.timeout:
                sock.close()
                return False
            if b'Login:' not in data:
                sock.close()
                return False
            sock.sendto(b'XXXXXXXXnetcore', (host, port))
            try:
                data2, _ = sock.recvfrom(128)
            except socket.timeout:
                sock.close()
                return False
            sock.close()
        except Exception:
            return False
        if b'Login successed' in data2:
            self.set_info(
                severity='critical',
                reason='Netcore/Netis UDP backdoor (CVE-2025-34117)',
                path=f'udp/{port}',
            )
            return True
        return False
