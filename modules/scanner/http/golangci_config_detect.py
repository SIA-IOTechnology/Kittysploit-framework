#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GolangCI-Lint configuration file was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GolangCI-Lint Configuration File - Detect',
        'description': 'GolangCI-Lint configuration file was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'golang', 'devops', 'cicd', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://github.com/maurosoria/dirsearch/blob/master/db/dicc.txt',
            'https://golangci-lint.run/usage/configuration/',
        ],
    }

    def run(self):
        for path in ('/.golangci.yml', '/.golangci.yaml', '/.golangci.toml', '/.golangci.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('linters:', 'linters-settings:',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='info',
                    reason="GolangCI-Lint Configuration File detected",
                    path=path,
                )
                return True
        return False

