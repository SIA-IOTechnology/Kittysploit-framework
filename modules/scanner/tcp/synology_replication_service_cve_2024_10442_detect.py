#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synology Replication Service synobtrfsreplicad exposure (CVE-2024-10442)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'Synology Replication Service - Exposure Detection (CVE-2024-10442)',
        'description': (
            'Detects Internet-exposed Synology Replication Service (synobtrfsreplicad) '
            'on TCP/5566. CVE-2024-10442 is a pre-auth memory corruption in '
            'libsynobtrfsreplicacore (Pwn2Own Ireland 2024 / SA-24:22).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['scanner', 'tcp', 'synology', 'nas', 'replication', 'cve2024', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.35,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'scanner/http/synology_rackstation_detect',
                    'scanner/http/cve_2024_10441_synology_detect',
                ],
            },
        },
        'references': [
            'https://www.synology.com/en-us/security/advisory/Synology_SA_24_22',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-10442',
            'https://www.zerodayinitiative.com/advisories/ZDI-25-208/',
        ],
        'cve': 'CVE-2024-10442',
    }

    port = OptPort(5566, 'Replication Service port', True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host, port):
            return False
        try:
            sock = socket.create_connection((host, port), timeout=self._timeout())
            sock.settimeout(self._timeout())
            # Minimal 12-byte header probe (length field only); service forks per client.
            sock.send(b'\x00' * 12)
            try:
                sock.recv(64)
            except socket.timeout:
                pass
            sock.close()
        except OSError:
            return False
        self.set_info(
            severity='critical',
            reason='Synology Replication Service reachable on TCP/5566 (CVE-2024-10442 surface)',
            path=f'tcp/{port}',
        )
        return True
