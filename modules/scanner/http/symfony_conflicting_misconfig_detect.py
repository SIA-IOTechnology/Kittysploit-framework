#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A misconfiguration in Symfony’s trusted proxy and header settings could trigger a ConflictingHeadersException ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Symfony Conflicting Headers - Information Disclosure Detection',
        'description': 'A misconfiguration in Symfony’s trusted proxy and header settings could trigger a ConflictingHeadersException when both Forwarded and X-Forwarded-* headers were present. When debug mode was enabled in production, this issue could have exposed sensitive environment details such as SMTP credentials, application paths, or system configuration.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'symfony', 'exposure', 'vuln'],
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
            'https://symfony.com/doc/current/deployment/proxies.html',
            'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        body_any = ('Symfony\\Component\\HttpFoundation\\Exception\\ConflictingHeadersException',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Symfony Conflicting Headers - Information Disclosure detected",
                path='/',
            )
            return True
        return False

