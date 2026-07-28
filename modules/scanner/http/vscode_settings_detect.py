#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed Visual Studio Code configuration files that were accessible over HTTP, which could have led t."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Visual Studio Code Settings - Credential Exposure Detection',
        'description': 'Detected exposed Visual Studio Code configuration files that were accessible over HTTP, which could have led to credential leakage or sensitive workspace disclosure.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'config', 'vscode', 'misconfig'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
    }

    def run(self):
        for path in ('/.vscode/settings.json', '/settings.json', '/.vscode/launch.json', '/.vscode/tasks.json', '/.vscode-server/data/Machine/settings.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('application/json', 'ignoreLimitWarning', 'yaml.schemas', 'search.exclude', 'sqltools.connections', 'python', 'livePreview', 'multipliers', 'matchCommandLine', 'errorSquiggles', 'editor',)
            body_all = ('launch', 'configurations', 'version', 'tasks',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="Visual Studio Code Settings - Credential Exposure detected",
                    path=path,
                )
                return True
        return False

