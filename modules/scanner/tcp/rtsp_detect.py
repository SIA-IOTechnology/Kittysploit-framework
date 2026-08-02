#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RTSP was detected."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'RTSP - Detect',
        'description': 'RTSP was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['scanner', 'tcp', 'network', 'rtsp', 'detection'],
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
                'suggested_followups': [
                    'listeners/iot/rtsp_client',
                    'post/rtsp/gather/describe_dump',
                ],
            },
        },
        'references': ['https://nmap.org/nsedoc/scripts/rtsp-methods.html'],
    }

    port = OptPort(554, "Target port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            sock.sendall(bytes.fromhex('4f5054494f4e53207369703a6e6d205349502f322e300d0a5669613a205349502f322e302f544350206e6d3b6272616e63683d666f6f0d0a46726f6d3a203c7369703a6e6d406e6d3e3b7461673d726f6f740d0a546f3a203c7369703a6e6d32406e6d323e0d0a43616c6c2d49443a2035303030300d0a435365713a203432204f5054494f4e530d0a4d61782d466f7277617264733a2037300d0a436f6e74656e742d4c656e6774683a20300d0a436f6e746163743a203c7369703a6e6d406e6d3e0d0a4163636570743a206170706c69636174696f6e2f7364700d0a0d0a'))
            data = sock.recv(1024)
            sock.close()
        except Exception:
            return False
        if not data:
            return False
        if any(m.encode() in data for m in ('RTSP/1.0',)):
            self.set_info(severity='info', reason='RTSP detected')
            return True
        return False
