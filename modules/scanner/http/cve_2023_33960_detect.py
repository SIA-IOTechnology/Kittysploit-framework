#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenProject versions before 12."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenProject < 12.5.4 - Project Identifiers Exposure Detection',
        'description': "OpenProject versions before 12.5.6 generate a publicly accessible robots.txt file revealing project identifiers, even if the instance is set to 'Login required', letting attackers gather project info, exploit requires no authentication.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'openproject', 'exposure', 'api'],
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
            'https://www.openproject.org/docs/release-notes/12-5-4/',
            'https://github.com/opf/openproject/security/advisories/GHSA-4r3x-x7xf-h2gc',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-33960',
        ],
        'cve': 'CVE-2023-33960',
    }

    def run(self):
        r = self.http_request(method="GET", path='/robots.txt', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Disallow: /projects/', '/work_packages', '/repository', '/activity',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="OpenProject < 12.5.4 - Project Identifiers Exposure detected",
                path='/robots.txt',
            )
            return True
        return False

