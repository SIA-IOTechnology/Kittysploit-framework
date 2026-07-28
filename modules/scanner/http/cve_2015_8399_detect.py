#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Atlassian Confluence before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atlassian Confluence <5.8.17 - Information Disclosure Detection',
        'description': 'Atlassian Confluence before 5.8.17 contains an information disclsoure vulnerability. A remote authenticated user can read configuration files via the decoratorName parameter to (1) spaces/viewdefaultdecorator.action or (2) admin/viewdefaultdecorator.action.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'edb', 'atlassian', 'confluence', 'vuln'],
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
            'https://jira.atlassian.com/browse/CONFSERVER-39704?src=confmacro',
            'https://www.exploit-db.com/exploits/39170/',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-8399',
        ],
        'cve': 'CVE-2015-8399',
    }

    def run(self):
        r = self.http_request(method="GET", path='/spaces/viewdefaultdecorator.action?decoratorName', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('confluence-init.properties', 'View Default Decorator',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Atlassian Confluence <5.8.17 - Information Disclosure detected",
                path='/spaces/viewdefaultdecorator.action?decoratorName',
            )
            return True
        return False

