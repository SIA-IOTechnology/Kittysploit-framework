#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zyxel UAG, USG, and ZyWall devices allows a remote attacker to generate guest accounts by directly accessing t."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zyxel ZyWall UAG/USG - Account Creation Access Detection',
        'description': 'Zyxel UAG, USG, and ZyWall devices allows a remote attacker to generate guest accounts by directly accessing the account generator via the "Free Time" component. This can lead to unauthorized network access or DoS attacks.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'zyxel', 'zywall', 'xss', 'vuln'],
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
            'https://www.zyxel.com/support/vulnerabilities-related-to-the-Free-Time-feature.shtml',
            'https://n-thumann.de/blog/zyxel-gateways-missing-access-control-in-account-generator-xss/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-12583',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2019-12583',
    }

    def run(self):
        r = self.http_request(method="GET", path='/free_time.cgi', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('free_time_redirect.cgi?u=', '&smsOnly=0',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Zyxel ZyWall UAG/USG - Account Creation Access detected",
                path='/free_time.cgi',
            )
            return True
        return False

