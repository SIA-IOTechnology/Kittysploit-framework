#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple Docker Compose configuration files were detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Docker Compose - Detect',
        'description': 'Multiple Docker Compose configuration files were detected. The configuration allows deploy, combine and configure operations on multiple containers at the same time. The default is to outsource each process to its own container, which is then publicly accessible.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'config', 'devops', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
        for path in ('/docker-compose.yml', '/docker-compose.prod.yml', '/docker-compose.production.yml', '/docker-compose.staging.yml', '/docker-compose.dev.yml', '/docker-compose-dev.yml', '/docker-compose.override.yml'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('services:',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="Docker Compose detected",
                    path=path,
                )
                return True
        return False

