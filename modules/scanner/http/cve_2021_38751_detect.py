#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An HTTP Host header attack exists in ExponentCMS 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ExponentCMS <= 2.6 - Host Header Injection Detection',
        'description': 'An HTTP Host header attack exists in ExponentCMS 2.6 and below in /exponent_constants.php. A modified HTTP header can change links on the webpage to an arbitrary value,leading to a possible attack vector for MITM.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'exponentcms', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-38751',
            'https://github.com/exponentcms/exponent-cms/issues/1544',
            'https://github.com/exponentcms/exponent-cms/blob/a9fa9358c5e8dc2ce7ad61d7d5bea38505b8515c/exponent_constants.php#L56-L64',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-38751',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('{{randstr}}.tld', 'EXPONENT.PATH', 'EXPONENT.URL',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="ExponentCMS <= 2.6 - Host Header Injection detected",
                path='/',
            )
            return True
        return False

