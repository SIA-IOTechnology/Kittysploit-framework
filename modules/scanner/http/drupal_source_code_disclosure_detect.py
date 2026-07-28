#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed Drupal source code, backup files, and sensitive configurations, potentially disclosing databa."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Drupal - Source Code Disclosure Detection',
        'description': 'Detected exposed Drupal source code, backup files, and sensitive configurations, potentially disclosing database credentials and API keys. This exposure revealed internal system paths and critical site metadata, increasing the risk of full system compromise.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'drupal', 'exposure', 'disclosure', 'misconfig'],
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
        'references': [
            'https://www.drupal.org/docs/security-in-drupal',
            'https://www.drupal.org/project/drupal/issues/3457781',
        ],
    }

    def run(self):
        for path in ('/sites/default/settings.php', '/sites/default/settings.php~', '/sites/default/settings.php.bak', '/sites/default/settings.php.old', '/sites/default/settings.php.orig', '/sites/default/settings.php.save', '/sites/default/settings.php.swp', '/sites/default/settings.local.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Drupal database driver', 'drupal_initialize_variables()', 'allow_authorize_operations',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Drupal - Source Code Disclosure detected",
                    path=path,
                )
                return True
        return False

