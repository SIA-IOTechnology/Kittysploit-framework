#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposure of the x-amz-meta-s3cmd-attrs header in S3 objects, which can disclose sensitive information."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'x-amz-meta-s3cmd-attrs Header Username Disclosure Detection',
        'description': 'Detected exposure of the x-amz-meta-s3cmd-attrs header in S3 objects, which can disclose sensitive information including the username (uname), user ID (uid), group name (gname), and group ID (gid) of the user who uploaded the file using s3cmd.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 's3', 'aws', 'exposure', 'misconfig', 'header'],
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
            'https://github.com/s3tools/s3cmd/issues/1173',
            'https://hackerone.com/reports/819146',
            'https://medium.com/@jonathanbouman/how-s3cmd-discloses-your-linux-username-to-the-world-b9e4d79cb9e3',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?mi)^x-amz-meta-s3cmd-attrs:\\s*\\S.+$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='low',
                reason="x-amz-meta-s3cmd-attrs Header Username Disclosure detected",
                path='/',
            )
            return True
        return False

