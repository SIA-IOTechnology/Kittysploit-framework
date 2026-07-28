#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Improper access control in Gurock TestRail versions < 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gurock TestRail Application files.md5 Exposure Detection',
        'description': 'Improper access control in Gurock TestRail versions < 7.2.0.3014 resulted in sensitive information exposure. A threat actor can access the /files.md5 file on the client side of a Gurock TestRail application, disclosing a full list of application files and the corresponding file paths which can then be tested, and in some cases result in the disclosure of hardcoded credentials, API keys, or other sensitive data.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'exposure', 'gurock', 'testrail', 'vkev', 'vuln'],
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
            'https://johnjhacking.com/blog/cve-2021-40875/',
            'https://www.gurock.com/testrail/tour/enterprise-edition',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40875',
            'https://github.com/SakuraSamuraii/derailed',
        ],
        'cve': 'CVE-2021-40875',
    }

    def run(self):
        for path in ('/files.md5', '/testrail/files.md5'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('app/arguments/admin',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Gurock TestRail Application files.md5 Exposure detected",
                    path=path,
                )
                return True
        return False

