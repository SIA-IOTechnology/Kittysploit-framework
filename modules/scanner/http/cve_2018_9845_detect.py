#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Etherpad Lite before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Etherpad Lite <1.6.4 - Admin Authentication Bypass Detection',
        'description': 'Etherpad Lite before 1.6.4 is exploitable for admin access.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'etherpad', 'auth-bypass', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
        'references': [
            'https://infosecwriteups.com/account-takeovers-believe-the-unbelievable-bb98a0c251a4',
            'https://github.com/ether/etherpad-lite/commit/ffe24c3dd93efc73e0cbf924db9a0cc40be9511b',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-9845',
            'https://github.com/ether/etherpad-lite/blob/develop/CHANGELOG.md',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-9845',
    }

    def run(self):
        r = self.http_request(method="GET", path='/Admin', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Etherpad version', 'Plugin manager', 'Installed parts',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Etherpad Lite <1.6.4 - Admin Authentication Bypass detected",
                path='/Admin',
            )
            return True
        return False

