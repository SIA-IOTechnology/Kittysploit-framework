#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Events Calendar WordPress plugin <= 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'The Events Calendar <= 6.15.2 - Information Disclosure Detection',
        'description': 'The Events Calendar WordPress plugin <= 6.15.2 contains an information disclosure vulnerability caused by REST endpoint exposure, letting unauthenticated attackers extract data about password-protected vendors or venues, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'wpscan', 'the-events-calendar', 'unauth', 'vuln'],
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
            'https://www.wiz.io/vulnerability-database/cve/cve-2025-9808',
            'https://wpscan.com/plugin/the-events-calendar/',
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/the-events-calendar',
            'https://wordpress.org/plugins/the-events-calendar/',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-9808',
        ],
        'cve': 'CVE-2025-9808',
    }

    def run(self):
        for path in ('/wp-json/tribe/events/v1/organizers', '/wp-json/tribe/events/v1/venues'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('organizers', 'venues',)
            body_all = ('rest_url', 'total',)
            header_any = ('application/json',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="The Events Calendar <= 6.15.2 - Information Disclosure detected",
                    path=path,
                )
                return True
        return False

