#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jira before version 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jira - Incorrect Authorization Detection',
        'description': 'Jira before version 7.13.3, from version 8.0.0 before version 8.0.4, and from version 8.1.0 before version 8.1.1 is susceptible to an incorrect authorization check in the /rest/api/2/user/picker rest resource, enabling an attacker to enumerate usernames and gain improper access.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'atlassian', 'jira', 'enumeration', 'vuln'],
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
            'https://jira.atlassian.com/browse/JRASERVER-69242',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-3403',
            'https://github.com/nomi-sec/PoC-in-GitHub',
            'https://github.com/rezasarvani/JiraVulChecker',
            'https://github.com/und3sc0n0c1d0/UserEnumJira',
        ],
        'cve': 'CVE-2019-3403',
    }

    def run(self):
        r = self.http_request(method="GET", path='/rest/api/2/user/picker?query=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = (':', 'total":0')
        body_all = (':',)
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Jira - Incorrect Authorization detected",
                path='/rest/api/2/user/picker?query=',
            )
            return True
        return False

