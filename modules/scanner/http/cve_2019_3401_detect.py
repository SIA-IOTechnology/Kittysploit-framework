#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Atlasssian Jira before version 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atlassian Jira <7.13.3/8.0.0-8.1.1 - Incorrect Authorization Detection',
        'description': 'Atlasssian Jira before version 7.13.3 and from version 8.0.0 before version 8.1.1 is susceptible to incorrect authorization. The ManageFilters.jspa resource allows a remote attacker to enumerate usernames via an incorrect authorization check, thus possibly obtaining sensitive information, modifying data, and/or executing unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'jira', 'atlassian', 'exposure', 'vuln'],
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
            'https://jira.atlassian.com/browse/JRASERVER-69244',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-3401',
        ],
        'cve': 'CVE-2019-3401',
    }

    def run(self):
        r = self.http_request(method="GET", path='/secure/ManageFilters.jspa?filter=popular&filterView=popular', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<span data-filter-field="owner-full-name">', '<title>Manage Filters - Jira</title>',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Atlassian Jira <7.13.3/8.0.0-8.1.1 - Incorrect Authorization detected",
                path='/secure/ManageFilters.jspa?filter=popular&filterView=popular',
            )
            return True
        return False

