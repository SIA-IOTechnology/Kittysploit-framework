#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microweber contains a vulnerability that allows exposure of sensitive information to an unauthorized actor in ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microweber Information Disclosure Detection',
        'description': 'Microweber contains a vulnerability that allows exposure of sensitive information to an unauthorized actor in Packagist microweber/microweber prior to 1.2.11.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'microweber', 'disclosure', 'huntr', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0281',
            'https://github.com/microweber/microweber/commit/e680e134a4215c979bfd2eaf58336be34c8fc6e6',
            'https://huntr.dev/bounties/315f5ac6-1b5e-4444-ad8f-802371da3505',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-0281',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/users/search_authors', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"username":', '"email":', '"display_name":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Microweber Information Disclosure detected",
                path='/api/users/search_authors',
            )
            return True
        return False

