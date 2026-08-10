#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open-FTPD unauthenticated LIST (CVE-2010-2620)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Open-FTPD - Unauthenticated LIST Detection (CVE-2010-2620)',
        'description': (
            'Detects CVE-2010-2620 by issuing LIST without auth on Gabriel FTP Server '
            'and matching 226 Transfer Complete.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'scanner', 'tcp', 'ftp', 'open-ftpd', 'cve', 'cve2010', 'auth-bypass', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2010-2620',
        ],
        'cve': 'CVE-2010-2620',
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
            banner = sock.recv(512).decode('latin-1', errors='replace')
            if "Gabriel's FTP Server" not in banner and 'Gabriel' not in banner:
                sock.close()
                return False
            sock.sendall(b'LIST\r\n')
            chunks = []
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            sock.close()
            data = b''.join(chunks).decode('latin-1', errors='replace')
        except Exception:
            return False
        if '226 Transfer Complete' in data:
            self.set_info(
                severity='high',
                reason='Open-FTPD unauthenticated LIST (CVE-2010-2620)',
                path=f'tcp/{port}',
            )
            return True
        return False
