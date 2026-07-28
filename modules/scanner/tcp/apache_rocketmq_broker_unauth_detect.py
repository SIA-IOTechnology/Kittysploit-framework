#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Rocketmq Unauthenticated Access were detected."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Apache Rocketmq Broker - Unauthenticated Access Detection',
        'description': 'Apache Rocketmq Unauthenticated Access were detected.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['scanner', 'tcp', 'network', 'rocketmq', 'broker', 'apache', 'unauth', 'misconfig', 'vuln'],
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
        'references': ['https://rocketmq.apache.org/docs/bestPractice/03access'],
    }

    port = OptPort(10911, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall(bytes.fromhex('000000820000007e7b22636f6465223a3130352c22666c6167223a302c226c616e6775616765223a224a415641222c226f7061717565223a312c2273657269616c697a655479706543757272656e74525043223a224a534f4e222c2276657273696f6e223a3434312c226578744669656c6473223a7b22746f706963223a2254455354227d7d'))
            data = sock.recv(2048)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if (any(m.encode() in data for m in ('HTTP', 'FTP', 'html'))) and (all(m.encode() in data for m in ('serializeTypeCurrentRPC', 'JAVA', 'opaque', 'version'))):
            self.set_info(severity='high', reason='Apache Rocketmq Broker - Unauthenticated Access detected')
            return True
        return False
