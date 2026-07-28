#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wireless Multiplex Terminal Playout Server <=20."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wireless Multiplex Terminal Playout Server <=20.2.8 - Default Credential Detection',
        'description': 'Wireless Multiplex Terminal Playout Server <=20.2.8 has a default account with a password of pokon available via its web administrative interface.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wmt', 'default-login', 'mobileviewpoint', 'vuln'],
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
            'https://jeyaseelans.medium.com/cve-2020-35338-9e841f48defa',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-35338',
            'https://www.mobileviewpoint.com/',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-35338',
    }

    def run(self):
        r = self.http_request(method="GET", path='/server/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_any = ('WMT Server',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Wireless Multiplex Terminal Playout Server <=20.2.8 - Default Credential detected",
                path='/server/',
            )
            return True
        return False

