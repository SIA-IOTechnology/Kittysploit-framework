#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""symfony."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Symfony Lock File - Exposure Detection',
        'description': "symfony.lock was found accessible, exposing a full list of installed Composer packages, library versions, and metadata for a Symfony-based PHP application. Disclosure of this file can provide insight into the application's attack surface, potentially revealing vulnerable or outdated dependencies and aiding an attacker in choosing their exploit strategy.",
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'symfony', 'composer', 'php', 'config'],
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
            'https://cheatsheetseries.owasp.org/cheatsheets/Information_Leakage.html',
            'https://symfony.com/doc/current/deployment.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/symfony.lock', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('symfony/', 'php\\',)
        body_all = ('version\\', ':')
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Symfony Lock File - Exposure detected",
                path='/symfony.lock',
            )
            return True
        return False

