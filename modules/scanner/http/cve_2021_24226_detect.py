#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress AccessAlly plugin before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AccessAlly <3.5.7 - Sensitive Information Leakage Detection',
        'description': 'WordPress AccessAlly plugin before 3.5.7 allows sensitive information leakage because the file \\"resource/frontend/product/product-shortcode.php\\" (which is responsible for the [accessally_order_form] shortcode) dumps serialize($_SERVER), which contains all environment variables. The leakage occurs on all public facing pages containing the [accessally_order_form] shortcode, and no login or administrator role is required.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'wp-plugin', 'wpscan', 'accessally', 'vuln'],
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
            'https://wpscan.com/vulnerability/8e3e89fd-e380-4108-be23-00e87fbaad16',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24226',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24226',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<div id="accessally-testing-data"',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="AccessAlly <3.5.7 - Sensitive Information Leakage detected",
                path='/',
            )
            return True
        return False

