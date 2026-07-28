#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Woodwing Studio Server ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Woodwing Studio Server - Git Config Detection',
        'description': 'Woodwing Studio Server .git/config file exposed.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'woodwing', 'git', 'config', 'vuln'],
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
        'references': ['https://twitter.com/ynsmroztas/status/1680961398011047936'],
    }

    def run(self):
        for path in ('/Server/.git/config', '/StudioServer/.git/config'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            body_all = ('<html', '<body', '[credentials]', '[core]',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Woodwing Studio Server - Git Config detected",
                    path=path,
                )
                return True
        return False

