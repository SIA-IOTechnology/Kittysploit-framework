#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jenkins is susceptible to a remote code execution vulnerability due to accessible script functionality."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jenkins - Remote Code Execution Detection',
        'description': 'Jenkins is susceptible to a remote code execution vulnerability due to accessible script functionality.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'devops', 'hackerone', 'jenkins', 'rce', 'vuln'],
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
            'https://hackerone.com/reports/403402',
            'https://medium.com/@gokulsspace/the-30000-bounty-affair-3f025ee6b834',
        ],
    }

    def run(self):
        for path in ('/script/', '/jenkins/script'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('println(Jenkins.instance.pluginManager.plugins)', 'Script Console', 'Scriptconsole',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='critical',
                    reason="Jenkins - Remote Code Execution detected",
                    path=path,
                )
                return True
        return False

