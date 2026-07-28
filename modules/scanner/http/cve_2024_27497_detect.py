#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linksys E2000 Ver."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Linksys E2000 1.0.06 position.js Improper Authentication Detection',
        'description': 'Linksys E2000 Ver.1.0.06 build 1 is vulnerable to authentication bypass via the position.js file.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'linksys', 'auth-bypass', 'vkev', 'vuln'],
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
            'https://warp-desk-89d.notion.site/Linksys-E-2000-efcd532d8dcf4710a4af13fca131a5b8',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-27497',
            'https://github.com/Ostorlab/KEV',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
        ],
        'cve': 'CVE-2024-27497',
    }

    def run(self):
        r = self.http_request(method="GET", path='/position.js', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('var session_key', 'close_session', 'HELPPATH',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Linksys E2000 1.0.06 position.js Improper Authentication detected",
                path='/position.js',
            )
            return True
        return False

