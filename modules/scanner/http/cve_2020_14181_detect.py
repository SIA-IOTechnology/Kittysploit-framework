#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jira Server and Data Center is susceptible to information disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jira Server and Data Center - Information Disclosure Detection',
        'description': 'Jira Server and Data Center is susceptible to information disclosure. An attacker can enumerate users via the /ViewUserHover.jspa endpoint and thus potentially access sensitive information, modify data, and/or execute unauthorized operations. Affected versions are before version 7.13.6, from version 8.0.0 before 8.5.7, and from version 8.6.0 before 8.12.0.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'atlassian', 'jira', 'packetstorm', 'vuln'],
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
            'https://jira.atlassian.com/browse/JRASERVER-71560',
            'http://packetstormsecurity.com/files/161730/Atlassian-JIRA-8.11.1-User-Enumeration.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-14181',
            'https://github.com/H4ckTh3W0r1d/Goby_POC',
            'https://github.com/Rival420/CVE-2020-14181',
        ],
        'cve': 'CVE-2020-14181',
    }

    def run(self):
        r = self.http_request(method="GET", path='/secure/ViewUserHover.jspa', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('user-hover-details', 'content="JIRA"',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Jira Server and Data Center - Information Disclosure detected",
                path='/secure/ViewUserHover.jspa',
            )
            return True
        return False

