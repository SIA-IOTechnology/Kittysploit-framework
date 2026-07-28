#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Information disclosure issue in the redirect responses, When accessing any page on the website, Sensitive data."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adlisting Classified Ads 2.14.0 - Information Disclosure Detection',
        'description': 'Information disclosure issue in the redirect responses, When accessing any page on the website, Sensitive data, such as API keys, server keys, and app IDs, is being exposed in the body of these redirects.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'adlisting', 'exposure', 'templatecookie', 'vuln'],
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
            'https://www.exploit-db.com/exploits/51667',
            'https://templatecookie.com/demo/adlisting-classified-ads-script',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4168',
            'https://vuldb.com/?ctiid.236184',
            'https://vuldb.com/?id.236184',
        ],
        'cve': 'CVE-2023-4168',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ad-list-search?keyword=&lat=&long=&long=&lat=&location=&category=&keyword=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('google_map_key', 'api_key', 'auth_domain',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Adlisting Classified Ads 2.14.0 - Information Disclosure detected",
                path='/ad-list-search?keyword=&lat=&long=&long=&lat=&location=&category=&keyword=',
            )
            return True
        return False

