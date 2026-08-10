#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link SharePort Web Access unauthenticated exposure (CVE-2018-9032)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link SharePort - Auth Bypass Detection (CVE-2018-9032)',
        'description': (
            'Detects CVE-2018-9032 by requesting SharePort folder_view.php / category_view.php '
            'without auth and matching SharePort Web Access markers.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'dlink', 'shareport', 'auth-bypass', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.2,
            'value': 0.8,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2018-9032',
        ],
        'cve': 'CVE-2018-9032',
    }

    def run(self):
        for path in ('/folder_view.php', '/category_view.php'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if (
                '<title>SharePort Web Access</title>' in body
                and 'href="webfile_css/layout.css"' in body
            ):
                self.set_info(
                    severity='high',
                    reason='D-Link SharePort auth bypass (CVE-2018-9032)',
                    path=path,
                )
                return True
        return False
