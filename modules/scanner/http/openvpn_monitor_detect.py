#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""openvpn-monitor was discovered."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenVPN Monitor - Detect',
        'description': 'openvpn-monitor was discovered. OpenVPN Monitor is a simple python program to generate html that displays the status of an OpenVPN server, including all its current connections.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'openvpn', 'disclosure'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://openvpn-monitor.openbytes.ie/'],
    }

    def run(self):
        for path in ('/', '/openvpn-monitor/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_markers = (
                'OpenVPN Status Monitor',
                'Username',
                'VPN IP',
                'Remote IP',
            )
            body_hit = any(m in body for m in body_markers)
            if body_hit:
                self.set_info(
                    severity='info',
                    reason="OpenVPN Monitor detected",
                    path=path,
                )
                return True
        return False

