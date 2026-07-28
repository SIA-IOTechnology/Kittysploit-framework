#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IBM DB2 Database Server panel was detected."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'IBM DB2 Database Server - Detect',
        'description': 'IBM DB2 Database Server panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['scanner', 'tcp', 'network', 'ibm', 'database', 'db', 'db2', 'detection'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://nmap.org/nsedoc/scripts/db2-das-info.html'],
    }

    port = OptPort(50000, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall(bytes.fromhex('01c2000000040000b601000053514c4442325241000100000401010005001d008800000001000080000000010900000001000040000000010900000001000040000000010800000004000040000000010400000001000040000000400400000004000040000000010400000004000040000000010400000004000040000000010400000002000040000000010400000004000040000000010000000001000040000000000400000004000080000000010400000004000080000000010400000003000080000000010400000004000080000000010800000001000040000000010400000004000040000000011000000001000080000000011000000001000080000000010400000004000040000000010900000001000040000000010900000001000080000000010400000003000080000000010000000000000000000000000104000001000080000000010000000000000000000000000000000000000000000000000000000001000040000000010000000001000040000000002020202020202020000000000000000000000000000000000100ff000000000000000000000000000000000000000000e404000000000000000000000000000000000000007f'))
            data = sock.recv(1024)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if any(m.encode() in data for m in ('SQLDB2RA', 'DB2', 'SQLJS1D', 'HTTP/1.1')):
            self.set_info(severity='info', reason='IBM DB2 Database Server detected')
            return True
        return False
