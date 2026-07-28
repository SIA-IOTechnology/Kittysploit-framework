#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PrestaShop versions after 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PrestaShop < 1.7.6.6 - Information Exposure via Upload Directory Detection',
        'description': 'PrestaShop versions after 1.5.0.0 and before 1.7.6.6 are vulnerable to information exposure through directory listing in the upload directory due to a missing index.php file.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'prestashop', 'exposure', 'directory-listing'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2020-15081',
            'https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-997j-f42g-x57c',
            'https://github.com/PrestaShop/PrestaShop/commit/bac9ea6936b073f84b1abd9864317af3713f1901',
        ],
        'cve': 'CVE-2020-15081',
    }

    def run(self):
        r = self.http_request(method="GET", path='/upload/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Index of', 'Directory listing for', '[To Parent Directory]', '<title>Index of',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='low',
                reason="PrestaShop < 1.7.6.6 - Information Exposure via Upload Directory detected",
                path='/upload/',
            )
            return True
        return False

