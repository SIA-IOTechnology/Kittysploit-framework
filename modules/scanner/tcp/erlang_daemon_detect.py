#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The erlang port mapper daemon is used to coordinate distributed erlang instances."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Erlang Port Mapper Daemon Detection',
        'description': 'The erlang port mapper daemon is used to coordinate distributed erlang instances. His job is to keep track of which node name listens on which address. Hence, epmd map symbolic node names to machine addresses.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['scanner', 'tcp', 'network', 'demon', 'enum', 'erlang', 'epmd', 'misconfig'],
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
        'references': [
            'https://nmap.org/nsedoc/scripts/epmd-info.html',
            'https://book.hacktricks.xyz/network-services-pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd',
            'https://medium.com/@_sadshade/couchdb-erlang-and-cookies-rce-on-default-settings-b1e9173a4bcd',
        ],
    }

    port = OptPort(4369, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall('\x00\x01n'.encode())
            data = sock.recv(1024)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if (any(m.encode() in data for m in ('HTTP/1.1',))) and (all(m.encode() in data for m in ('name', 'at port'))):
            self.set_info(severity='low', reason='Erlang Port Mapper Daemon detected')
            return True
        return False
